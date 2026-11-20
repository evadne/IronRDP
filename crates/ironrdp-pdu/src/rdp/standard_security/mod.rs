//! Standard RDP Security ([MS-RDPBCGR] 5.3): the encryption and the MAC of every PDU after the Security Exchange.
//!
//! [`StandardSecurity`] is the one security layer of a connection. It turns the frames that the rest of IronRDP
//! makes and reads, as they are under Enhanced RDP Security, into the frames of Standard RDP Security and back: the
//! slow path's security header ([MS-RDPBCGR] 2.2.8.1.1.2, 2.2.9.1.1.2) and the fast path's encryption flags,
//! FIPS information and signature ([MS-RDPBCGR] 2.2.8.1.2, 2.2.9.1.2), around data encrypted under the session keys.
//!
//! Only the methods that a client of this crate advertises are implemented: 128-bit RC4 and FIPS
//! ([`StandardSecurityMethod`]).
//!
//! [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/

mod keys;
mod server_key;

use core::fmt;
use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use ironrdp_core::{DecodeError, EncodeError, decode, encode_vec};

use self::keys::{FIPS_BLOCK_SIZE, PacketCount, SIGNATURE_SIZE, SessionKeys};
pub use self::server_key::{MAX_MODULUS_BITS, MIN_MODULUS_BITS, ServerKeyError, ServerPublicKey};
use crate::gcc::EncryptionMethod;
use crate::mcs::{McsMessage, SendDataIndication, SendDataRequest};
use crate::rdp::client_info::ClientAutoReconnect;
use crate::rdp::headers::BasicSecurityHeaderFlags;
use crate::rdp::session_info::ServerAutoReconnect;
use crate::x224::X224;
use crate::{Action, find_size};

/// The size of the client random ([MS-RDPBCGR] 5.3.4).
///
/// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
pub const CLIENT_RANDOM_SIZE: usize = 32;

/// The size of the server random ([MS-RDPBCGR] 2.2.1.4.3).
///
/// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
pub const SERVER_RANDOM_SIZE: usize = 32;

/// The renewal interval of the RC4 keys, in packets of one direction ([MS-RDPBCGR] 5.3.7.1).
///
/// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
pub const RC4_KEY_RENEWAL_INTERVAL: u32 = keys::RC4_KEY_RENEWAL_INTERVAL;

/// The length of the FIPS security header and of the fast path's FIPS information, `length` ([MS-RDPBCGR]
/// 2.2.8.1.1.2.3, 2.2.8.1.2.1).
const FIPS_HEADER_LENGTH: u16 = 0x0010;

/// `TSFIPS_VERSION1`.
const FIPS_VERSION: u8 = 0x01;

/// The longest user data of an MCS Send Data PDU that this layer writes: what a PER length of two bytes holds.
const MAX_SEALED_USER_DATA: usize = 0x3FFF;

/// The longest fast-path PDU: its length has 15 bits ([MS-RDPBCGR] 2.2.8.1.2, 2.2.9.1.2).
const MAX_FAST_PATH_LENGTH: usize = 0x7FFF;

/// The fast path's `FASTPATH_INPUT_SECURE_CHECKSUM` and `FASTPATH_OUTPUT_SECURE_CHECKSUM`, in the header byte.
const FAST_PATH_SECURE_CHECKSUM: u8 = 0x1 << 6;

/// The fast path's `FASTPATH_INPUT_ENCRYPTED` and `FASTPATH_OUTPUT_ENCRYPTED`, in the header byte.
const FAST_PATH_ENCRYPTED: u8 = 0x2 << 6;

/// The flags of a security header that describe its encryption, and not the PDU it carries.
const ENCRYPTION_FLAGS: BasicSecurityHeaderFlags = BasicSecurityHeaderFlags::ENCRYPT
    .union(BasicSecurityHeaderFlags::SECURE_CHECKSUM)
    .union(BasicSecurityHeaderFlags::RESET_SEQNO)
    .union(BasicSecurityHeaderFlags::IGNORE_SEQNO)
    .union(BasicSecurityHeaderFlags::FLAGSHI_VALID);

/// An encryption method of Standard RDP Security that this crate implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StandardSecurityMethod {
    /// `ENCRYPTION_METHOD_128BIT`: RC4 with 128-bit keys, MACs of MD5 and SHA-1.
    Rc4128Bit,
    /// `ENCRYPTION_METHOD_FIPS`: Triple DES in CBC mode, MACs of HMAC-SHA-1.
    Fips,
}

impl StandardSecurityMethod {
    /// The methods a client advertises in its Client Security Data: every method this crate implements.
    pub const ADVERTISED: EncryptionMethod = EncryptionMethod::BIT_128.union(EncryptionMethod::FIPS);

    /// The method the server selected in its Server Security Data, if it is exactly one that this crate implements.
    pub fn from_selected(method: EncryptionMethod) -> Option<Self> {
        if method == EncryptionMethod::BIT_128 {
            Some(Self::Rc4128Bit)
        } else if method == EncryptionMethod::FIPS {
            Some(Self::Fips)
        } else {
            None
        }
    }

    pub fn encryption_method(self) -> EncryptionMethod {
        match self {
            Self::Rc4128Bit => EncryptionMethod::BIT_128,
            Self::Fips => EncryptionMethod::FIPS,
        }
    }
}

/// Which end of the connection a [`StandardSecurity`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// What a PDU on the I/O channel is, for [`StandardSecurity::seal`]: which decides whether its user data starts with
/// a Basic Security Header, and whether it is encrypted at all.
///
/// The user data of a PDU on the message channel always starts with a Basic Security Header, and that of a PDU on a
/// static virtual channel never does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoChannelPdu {
    /// A Share Control PDU, which carries no security header under Enhanced RDP Security.
    ShareControl,
    /// The Client Info PDU, which starts with its Basic Security Header (`SEC_INFO_PKT`) and is encrypted
    /// ([MS-RDPBCGR] 2.2.1.11).
    ///
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
    ClientInfo,
    /// A licensing PDU, which starts with its Basic Security Header (`SEC_LICENSE_PKT`) and whose encryption is
    /// optional ([MS-RDPBCGR] 5.3.6): it is sent as it is.
    ///
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
    Licensing,
}

/// Why a frame could not be sealed or opened.
///
/// Every one of them is the end of the connection: a MAC that does not verify, or data that cannot be decrypted,
/// "SHOULD be dropped" ([MS-RDPBCGR] 3.2.5.2, 3.2.5.9.3), and the keys of a direction cannot go on once a packet of it
/// was not processed.
///
/// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
#[derive(Debug)]
#[non_exhaustive]
pub enum StandardSecurityError {
    /// The MAC of a received packet does not verify.
    MacMismatch,
    /// A received packet is not encrypted, though encryption is in force and its encryption is not optional.
    Unencrypted,
    /// A received frame's lengths or fields do not hold together: what is named.
    Malformed(&'static str),
    /// A frame to be sent would be longer than its framing can say once sealed.
    TooLong { length: usize },
    /// A frame cannot be read as X.224 and MCS.
    Decode(DecodeError),
    /// A sealed frame cannot be written.
    Encode(EncodeError),
    /// A call on the layer panicked before, so that its keys are in no known state.
    Poisoned,
}

impl fmt::Display for StandardSecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MacMismatch => write!(f, "the MAC of a received packet does not verify"),
            Self::Unencrypted => write!(f, "a received packet is not encrypted though encryption is in force"),
            Self::Malformed(what) => write!(f, "a received frame is malformed: {what}"),
            Self::TooLong { length } => write!(f, "a frame of {length} bytes is too long to be sealed"),
            Self::Decode(error) => write!(f, "a frame cannot be read: {error}"),
            Self::Encode(error) => write!(f, "a sealed frame cannot be written: {error}"),
            Self::Poisoned => write!(f, "the security layer is poisoned"),
        }
    }
}

impl core::error::Error for StandardSecurityError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Encode(error) => Some(error),
            _ => None,
        }
    }
}

/// The security layer of one connection under Standard RDP Security, from the Security Exchange to its end.
///
/// Every PDU after the Security Exchange goes through it: [`Self::seal`] what is sent, [`Self::open`] what is
/// received, in the order of the wire, since each direction's keys and count move with every packet. Clones share
/// the one layer, so that the connector, the session and a reactivation sequence all use the same keys.
#[derive(Clone)]
pub struct StandardSecurity {
    layer: Arc<Mutex<Layer>>,
    role: Role,
    method: StandardSecurityMethod,
    io_channel_id: u16,
    message_channel_id: Option<u16>,
}

impl fmt::Debug for StandardSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NOTE: no key, random or count is shown.
        f.debug_struct("StandardSecurity")
            .field("role", &self.role)
            .field("method", &self.method)
            .field("io_channel_id", &self.io_channel_id)
            .field("message_channel_id", &self.message_channel_id)
            .finish_non_exhaustive()
    }
}

struct Layer {
    keys: SessionKeys,
    encrypt_count: PacketCount,
    decrypt_count: PacketCount,
    client_random: [u8; CLIENT_RANDOM_SIZE],
}

impl StandardSecurity {
    /// Derives the session keys from the two randoms ([MS-RDPBCGR] 5.3.5).
    ///
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
    pub fn new(
        role: Role,
        method: StandardSecurityMethod,
        client_random: &[u8; CLIENT_RANDOM_SIZE],
        server_random: &[u8; SERVER_RANDOM_SIZE],
        io_channel_id: u16,
        message_channel_id: Option<u16>,
    ) -> Self {
        Self {
            layer: Arc::new(Mutex::new(Layer {
                keys: SessionKeys::derive(method, role, client_random, server_random),
                encrypt_count: PacketCount::default(),
                decrypt_count: PacketCount::default(),
                client_random: *client_random,
            })),
            role,
            method,
            io_channel_id,
            message_channel_id,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn method(&self) -> StandardSecurityMethod {
        self.method
    }

    /// Seals every frame of `frames`, one after another: X.224 frames carrying an MCS Send Data PDU of this end's
    /// direction, and fast-path frames. Another MCS PDU is passed as it is.
    ///
    /// `io_channel_pdu` says what a PDU on the I/O channel is.
    pub fn seal(&self, frames: &[u8], io_channel_pdu: IoChannelPdu) -> Result<Vec<u8>, StandardSecurityError> {
        let mut sealed = Vec::with_capacity(frames.len() + 32);
        let mut rest = frames;
        while !rest.is_empty() {
            let frame = next_frame(rest)?;
            rest = &rest[frame.len()..];
            self.seal_frame(frame, io_channel_pdu, &mut sealed)?;
        }
        Ok(sealed)
    }

    /// Opens one received frame into the frame it would be under Enhanced RDP Security, checking its MAC.
    ///
    /// An MCS PDU other than a Send Data PDU of the other end's direction is passed as it is.
    pub fn open(&self, frame: &[u8]) -> Result<Vec<u8>, StandardSecurityError> {
        let whole = next_frame(frame)?;
        if whole.len() != frame.len() {
            return Err(StandardSecurityError::Malformed("bytes follow the frame"));
        }

        match action_of(frame)? {
            Action::X224 => {
                let message = decode::<X224<McsMessage<'_>>>(frame)
                    .map_err(StandardSecurityError::Decode)?
                    .0;
                let opened = match (self.role, message) {
                    (Role::Client, McsMessage::SendDataIndication(pdu)) => {
                        McsMessage::SendDataIndication(SendDataIndication {
                            user_data: Cow::Owned(self.open_user_data(&pdu.user_data)?),
                            ..pdu
                        })
                    }
                    (Role::Server, McsMessage::SendDataRequest(pdu)) => McsMessage::SendDataRequest(SendDataRequest {
                        user_data: Cow::Owned(self.open_user_data(&pdu.user_data)?),
                        ..pdu
                    }),
                    _ => return Ok(frame.to_vec()),
                };
                encode_vec(&X224(opened)).map_err(StandardSecurityError::Encode)
            }
            Action::FastPath => self.open_fast_path(frame),
        }
    }

    /// The Client Auto-Reconnect Packet answering `cookie`, whose verifier is keyed with this connection's client
    /// random ([MS-RDPBCGR] 5.5).
    ///
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
    pub fn client_auto_reconnect(
        &self,
        cookie: &ServerAutoReconnect,
    ) -> Result<ClientAutoReconnect, StandardSecurityError> {
        let layer = self.lock()?;
        Ok(ClientAutoReconnect::from_server_cookie_and_client_random(
            cookie,
            &layer.client_random,
        ))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Layer>, StandardSecurityError> {
        self.layer.lock().map_err(|_| StandardSecurityError::Poisoned)
    }

    fn seal_frame(
        &self,
        frame: &[u8],
        io_channel_pdu: IoChannelPdu,
        sealed: &mut Vec<u8>,
    ) -> Result<(), StandardSecurityError> {
        match action_of(frame)? {
            Action::X224 => {
                let message = decode::<X224<McsMessage<'_>>>(frame)
                    .map_err(StandardSecurityError::Decode)?
                    .0;
                let (initiator_id, channel_id, user_data) = match (self.role, message) {
                    (Role::Client, McsMessage::SendDataRequest(pdu)) => {
                        (pdu.initiator_id, pdu.channel_id, pdu.user_data)
                    }
                    (Role::Server, McsMessage::SendDataIndication(pdu)) => {
                        (pdu.initiator_id, pdu.channel_id, pdu.user_data)
                    }
                    _ => {
                        sealed.extend_from_slice(frame);
                        return Ok(());
                    }
                };

                let starts_with_header = if Some(channel_id) == self.message_channel_id {
                    true
                } else if channel_id == self.io_channel_id {
                    match io_channel_pdu {
                        IoChannelPdu::ShareControl => false,
                        IoChannelPdu::ClientInfo => true,
                        IoChannelPdu::Licensing => {
                            sealed.extend_from_slice(frame);
                            return Ok(());
                        }
                    }
                } else {
                    false
                };

                let user_data = self.seal_user_data(&user_data, starts_with_header)?;
                if user_data.len() > MAX_SEALED_USER_DATA {
                    return Err(StandardSecurityError::TooLong {
                        length: user_data.len(),
                    });
                }
                let user_data = Cow::Owned(user_data);
                let message = match self.role {
                    Role::Client => McsMessage::SendDataRequest(SendDataRequest {
                        initiator_id,
                        channel_id,
                        user_data,
                    }),
                    Role::Server => McsMessage::SendDataIndication(SendDataIndication {
                        initiator_id,
                        channel_id,
                        user_data,
                    }),
                };
                sealed.extend_from_slice(&encode_vec(&X224(message)).map_err(StandardSecurityError::Encode)?);
                Ok(())
            }
            Action::FastPath => self.seal_fast_path(frame, sealed),
        }
    }

    fn seal_user_data(&self, user_data: &[u8], starts_with_header: bool) -> Result<Vec<u8>, StandardSecurityError> {
        let (flags, data) = if starts_with_header {
            let (header, data) = user_data.split_at_checked(4).ok_or(StandardSecurityError::Malformed(
                "user data is shorter than its security header",
            ))?;
            (
                BasicSecurityHeaderFlags::from_bits_retain(u16::from_le_bytes([header[0], header[1]])),
                data,
            )
        } else {
            (BasicSecurityHeaderFlags::empty(), user_data)
        };

        let mut layer = self.lock()?;
        let layer = &mut *layer;
        let count = layer.encrypt_count.next_value();
        let sealed = layer.keys.encrypt(data, count);

        let mut out = Vec::with_capacity(16 + sealed.ciphertext.len());
        out.extend_from_slice(&(flags | BasicSecurityHeaderFlags::ENCRYPT).bits().to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flagsHi
        if self.method == StandardSecurityMethod::Fips {
            out.extend_from_slice(&FIPS_HEADER_LENGTH.to_le_bytes());
            out.push(FIPS_VERSION);
            out.push(sealed.padding);
        }
        out.extend_from_slice(&sealed.signature);
        out.extend_from_slice(&sealed.ciphertext);
        Ok(out)
    }

    fn open_user_data(&self, user_data: &[u8]) -> Result<Vec<u8>, StandardSecurityError> {
        let (header, rest) = user_data.split_at_checked(4).ok_or(StandardSecurityError::Malformed(
            "user data is shorter than a security header",
        ))?;
        let flags = BasicSecurityHeaderFlags::from_bits_retain(u16::from_le_bytes([header[0], header[1]]));

        if !flags.contains(BasicSecurityHeaderFlags::ENCRYPT) {
            // [MS-RDPBCGR] 5.3.6: licensing PDUs have optional encryption; every other PDU is encrypted.
            return if flags.contains(BasicSecurityHeaderFlags::LICENSE_PKT) {
                Ok(user_data.to_vec())
            } else {
                Err(StandardSecurityError::Unencrypted)
            };
        }

        let (padding, rest) = self.read_fips_information(rest)?;
        let (signature, ciphertext) = read_signature(rest)?;

        let data = {
            let mut layer = self.lock()?;
            let layer = &mut *layer;
            let count = layer.decrypt_count.next_value();
            layer.keys.decrypt(
                &signature,
                ciphertext,
                padding,
                flags.contains(BasicSecurityHeaderFlags::SECURE_CHECKSUM),
                count,
            )?
        };

        let carried = flags.difference(ENCRYPTION_FLAGS);
        if carried.is_empty() {
            Ok(data)
        } else {
            let mut out = Vec::with_capacity(4 + data.len());
            out.extend_from_slice(&carried.bits().to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&data);
            Ok(out)
        }
    }

    /// Reads the FIPS fields that follow the flags under FIPS, the same in the slow path's FIPS security header and
    /// in the fast path's FIPS information: `length`, `version` and `padlen`.
    fn read_fips_information<'a>(&self, rest: &'a [u8]) -> Result<(u8, &'a [u8]), StandardSecurityError> {
        if self.method != StandardSecurityMethod::Fips {
            return Ok((0, rest));
        }
        let (fields, rest) = rest
            .split_at_checked(4)
            .ok_or(StandardSecurityError::Malformed("the FIPS information is cut short"))?;
        if u16::from_le_bytes([fields[0], fields[1]]) != FIPS_HEADER_LENGTH {
            return Err(StandardSecurityError::Malformed("the FIPS header's length is not 16"));
        }
        // `version` SHOULD be TSFIPS_VERSION1, and is not held to it.
        let padding = fields[3];
        if usize::from(padding) >= FIPS_BLOCK_SIZE {
            return Err(StandardSecurityError::Malformed("FIPS padding is longer than allowed"));
        }
        Ok((padding, rest))
    }

    fn seal_fast_path(&self, frame: &[u8], sealed: &mut Vec<u8>) -> Result<(), StandardSecurityError> {
        let (header, payload) = split_fast_path(frame)?;

        let mut layer = self.lock()?;
        let layer = &mut *layer;
        let count = layer.encrypt_count.next_value();
        let encrypted = layer.keys.encrypt(payload, count);

        let fips_information = if self.method == StandardSecurityMethod::Fips {
            4
        } else {
            0
        };
        let body_length = fips_information + SIGNATURE_SIZE + encrypted.ciphertext.len();
        let length = fast_path_length(body_length)?;

        sealed.push((header & !(FAST_PATH_ENCRYPTED | FAST_PATH_SECURE_CHECKSUM)) | FAST_PATH_ENCRYPTED);
        push_fast_path_length(sealed, length);
        if fips_information != 0 {
            sealed.extend_from_slice(&FIPS_HEADER_LENGTH.to_le_bytes());
            sealed.push(FIPS_VERSION);
            sealed.push(encrypted.padding);
        }
        sealed.extend_from_slice(&encrypted.signature);
        sealed.extend_from_slice(&encrypted.ciphertext);
        Ok(())
    }

    fn open_fast_path(&self, frame: &[u8]) -> Result<Vec<u8>, StandardSecurityError> {
        let (header, body) = split_fast_path(frame)?;
        if header & FAST_PATH_ENCRYPTED == 0 {
            return Err(StandardSecurityError::Unencrypted);
        }

        let (padding, rest) = self.read_fips_information(body)?;
        let (signature, ciphertext) = read_signature(rest)?;

        let data = {
            let mut layer = self.lock()?;
            let layer = &mut *layer;
            let count = layer.decrypt_count.next_value();
            layer.keys.decrypt(
                &signature,
                ciphertext,
                padding,
                header & FAST_PATH_SECURE_CHECKSUM != 0,
                count,
            )?
        };

        let length = fast_path_length(data.len())?;
        let mut out = Vec::with_capacity(length);
        out.push(header & !(FAST_PATH_ENCRYPTED | FAST_PATH_SECURE_CHECKSUM));
        push_fast_path_length(&mut out, length);
        out.extend_from_slice(&data);
        Ok(out)
    }
}

fn action_of(frame: &[u8]) -> Result<Action, StandardSecurityError> {
    let first = *frame
        .first()
        .ok_or(StandardSecurityError::Malformed("the frame is empty"))?;
    Action::from_fp_output_header(first).map_err(|_| StandardSecurityError::Malformed("the frame's action is unknown"))
}

/// The first whole frame of `bytes`, by its own length.
fn next_frame(bytes: &[u8]) -> Result<&[u8], StandardSecurityError> {
    let info = find_size(bytes)
        .map_err(StandardSecurityError::Decode)?
        .ok_or(StandardSecurityError::Malformed("the frame is cut short"))?;
    bytes
        .get(..info.length)
        .ok_or(StandardSecurityError::Malformed("the frame is shorter than its length"))
}

/// A fast-path frame's header byte and what follows its length, the length having been checked against the frame.
fn split_fast_path(frame: &[u8]) -> Result<(u8, &[u8]), StandardSecurityError> {
    let (&header, rest) = frame
        .split_first()
        .ok_or(StandardSecurityError::Malformed("the frame is empty"))?;
    let (&first, rest) = rest
        .split_first()
        .ok_or(StandardSecurityError::Malformed("the fast-path length is cut short"))?;
    let (length, rest) = if first & 0x80 != 0 {
        let (&second, rest) = rest
            .split_first()
            .ok_or(StandardSecurityError::Malformed("the fast-path length is cut short"))?;
        (usize::from(u16::from_be_bytes([first & 0x7F, second])), rest)
    } else {
        (usize::from(first), rest)
    };
    if length != frame.len() {
        return Err(StandardSecurityError::Malformed(
            "the fast-path length is not the frame's",
        ));
    }
    Ok((header, rest))
}

/// The whole length of a fast-path frame whose body, after its length field, is `body_length` bytes.
fn fast_path_length(body_length: usize) -> Result<usize, StandardSecurityError> {
    let short = 1 + 1 + body_length;
    let length = if short <= 0x7F { short } else { short + 1 };
    if length > MAX_FAST_PATH_LENGTH {
        return Err(StandardSecurityError::TooLong { length });
    }
    Ok(length)
}

fn push_fast_path_length(out: &mut Vec<u8>, length: usize) {
    if length <= 0x7F {
        out.push(u8::try_from(length).expect("held to 0x7F"));
    } else {
        let length = u16::try_from(length).expect("held to MAX_FAST_PATH_LENGTH");
        out.extend_from_slice(&(length | 0x8000).to_be_bytes());
    }
}

fn read_signature(rest: &[u8]) -> Result<([u8; SIGNATURE_SIZE], &[u8]), StandardSecurityError> {
    let (signature, ciphertext) = rest
        .split_at_checked(SIGNATURE_SIZE)
        .ok_or(StandardSecurityError::Malformed("the data signature is cut short"))?;
    Ok((signature.try_into().expect("SIGNATURE_SIZE bytes"), ciphertext))
}

#[cfg(test)]
mod tests;
