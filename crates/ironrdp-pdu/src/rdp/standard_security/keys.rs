//! The session keys of Standard RDP Security and what is done with them: their derivation from the two randoms
//! ([MS-RDPBCGR] 5.3.5), the encryption and decryption of a packet's data with its MAC (5.3.6), and the renewal of the
//! RC4 keys (5.3.7).
//!
//! [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/

use cbc::cipher::{BlockModeDecrypt as _, BlockModeEncrypt as _, KeyIvInit as _};
use md5::Digest as _;
use rc4::{KeyInit as _, StreamCipher as _};

use super::{CLIENT_RANDOM_SIZE, Role, SERVER_RANDOM_SIZE, StandardSecurityError, StandardSecurityMethod};

/// The size of the MAC carried on the wire, `dataSignature`.
pub(super) const SIGNATURE_SIZE: usize = 8;

/// The block size of Triple DES, to which FIPS pads the data.
pub(super) const FIPS_BLOCK_SIZE: usize = 8;

/// RC4 keys are renewed after this many packets have been encrypted, or decrypted, with them ([MS-RDPBCGR] 5.3.7.1).
pub(super) const RC4_KEY_RENEWAL_INTERVAL: u32 = 4096;

/// `Pad1`: 0x36 repeated 40 times ([MS-RDPBCGR] 5.3.6.1, 5.3.7.1).
const PAD1: [u8; 40] = [0x36; 40];

/// `Pad2`: 0x5C repeated 48 times ([MS-RDPBCGR] 5.3.6.1, 5.3.7.1).
const PAD2: [u8; 48] = [0x5C; 48];

/// The Initialization Vector of Triple DES under FIPS ([MS-RDPBCGR] 5.3.6.2).
const FIPS_IV: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF];

type TripleDesEncryptor = cbc::Encryptor<des::TdesEde3>;
type TripleDesDecryptor = cbc::Decryptor<des::TdesEde3>;

/// What a packet's data became: its MAC, its ciphertext and, under FIPS, how many bytes of padding were appended.
pub(super) struct Sealed {
    pub(super) signature: [u8; SIGNATURE_SIZE],
    pub(super) ciphertext: Vec<u8>,
    pub(super) padding: u8,
}

/// The keys of one connection, in force from the Security Exchange to its end.
pub(super) enum SessionKeys {
    Rc4 {
        mac_key: SessionKey,
        encrypt: Box<Rc4Key>,
        decrypt: Box<Rc4Key>,
    },
    Fips {
        hmac_key: [u8; 20],
        encrypt: Box<TripleDesEncryptor>,
        decrypt: Box<TripleDesDecryptor>,
    },
}

/// The cumulative count of encryptions or decryptions of one direction, which salts the MAC ([MS-RDPBCGR] 5.3.6.1.1,
/// 5.3.6.2). It is a little-endian 32-bit integer on the wire, so it wraps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct PacketCount(pub(super) u32);

impl PacketCount {
    /// The count before this packet, which the packet's MAC is salted with; the count moves past it.
    pub(super) fn next_value(&mut self) -> u32 {
        let current = self.0;
        self.0 = self.0.wrapping_add(1);
        current
    }
}

impl SessionKeys {
    pub(super) fn derive(
        method: StandardSecurityMethod,
        role: Role,
        client_random: &[u8; CLIENT_RANDOM_SIZE],
        server_random: &[u8; SERVER_RANDOM_SIZE],
    ) -> Self {
        match method {
            StandardSecurityMethod::Rc440Bit | StandardSecurityMethod::Rc456Bit | StandardSecurityMethod::Rc4128Bit => {
                let strength = match method {
                    StandardSecurityMethod::Rc440Bit => KeyStrength::Bits40,
                    StandardSecurityMethod::Rc456Bit => KeyStrength::Bits56,
                    _ => KeyStrength::Bits128,
                };
                let keys = NonFipsKeys::derive(client_random, server_random);
                let (encrypt, decrypt) = match role {
                    Role::Client => (keys.client_encrypt_key, keys.client_decrypt_key),
                    // The server's encryption key is the client's decryption key, and the other way round.
                    Role::Server => (keys.client_decrypt_key, keys.client_encrypt_key),
                };
                Self::Rc4 {
                    mac_key: strength.reduce(&keys.mac_key),
                    encrypt: Box::new(Rc4Key::new(strength, strength.reduce(&encrypt))),
                    decrypt: Box::new(Rc4Key::new(strength, strength.reduce(&decrypt))),
                }
            }
            StandardSecurityMethod::Fips => {
                let keys = FipsKeys::derive(client_random, server_random);
                let (encrypt, decrypt) = match role {
                    Role::Client => (keys.client_encrypt_key, keys.client_decrypt_key),
                    Role::Server => (keys.client_decrypt_key, keys.client_encrypt_key),
                };
                Self::Fips {
                    hmac_key: keys.hmac_key,
                    encrypt: Box::new(TripleDesEncryptor::new(&encrypt.into(), &FIPS_IV.into())),
                    decrypt: Box::new(TripleDesDecryptor::new(&decrypt.into(), &FIPS_IV.into())),
                }
            }
        }
    }

    /// Encrypts one packet's data and makes its MAC ([MS-RDPBCGR] 5.3.6). `count` is the number of packets encrypted
    /// before this one.
    ///
    /// A salted MAC is never made for the RC4 methods: the client does not advertise `SALTED_MAC_GENERATION`, and the
    /// security header says which a packet carries ([MS-RDPBCGR] 5.3.6.1.1).
    pub(super) fn encrypt(&mut self, data: &[u8], count: u32) -> Sealed {
        match self {
            Self::Rc4 { mac_key, encrypt, .. } => {
                let signature = non_fips_mac(mac_key.as_slice(), data, None);
                let mut ciphertext = data.to_vec();
                encrypt.apply(&mut ciphertext);
                Sealed {
                    signature,
                    ciphertext,
                    padding: 0,
                }
            }
            Self::Fips { hmac_key, encrypt, .. } => {
                let signature = fips_mac(hmac_key, data, count);
                let padding = (FIPS_BLOCK_SIZE - data.len() % FIPS_BLOCK_SIZE) % FIPS_BLOCK_SIZE;
                let mut ciphertext = data.to_vec();
                ciphertext.resize(data.len() + padding, 0);
                for block in ciphertext.chunks_exact_mut(FIPS_BLOCK_SIZE) {
                    encrypt.encrypt_block(block.try_into().expect("a block of FIPS_BLOCK_SIZE bytes"));
                }
                Sealed {
                    signature,
                    ciphertext,
                    padding: u8::try_from(padding).expect("less than FIPS_BLOCK_SIZE"),
                }
            }
        }
    }

    /// Decrypts one packet's data and checks its MAC ([MS-RDPBCGR] 5.3.6). `count` is the number of packets decrypted
    /// before this one; `salted` is whether the packet says that its MAC is salted.
    pub(super) fn decrypt(
        &mut self,
        signature: &[u8; SIGNATURE_SIZE],
        ciphertext: &[u8],
        padding: u8,
        salted: bool,
        count: u32,
    ) -> Result<Vec<u8>, StandardSecurityError> {
        let (data, expected) = match self {
            Self::Rc4 { mac_key, decrypt, .. } => {
                let mut data = ciphertext.to_vec();
                decrypt.apply(&mut data);
                let expected = non_fips_mac(mac_key.as_slice(), &data, salted.then_some(count));
                (data, expected)
            }
            Self::Fips { hmac_key, decrypt, .. } => {
                let padding = usize::from(padding);
                if !ciphertext.len().is_multiple_of(FIPS_BLOCK_SIZE) {
                    return Err(StandardSecurityError::Malformed(
                        "FIPS data is not a whole number of Triple DES blocks",
                    ));
                }
                if padding >= FIPS_BLOCK_SIZE || padding > ciphertext.len() {
                    return Err(StandardSecurityError::Malformed("FIPS padding is longer than allowed"));
                }
                let mut data = ciphertext.to_vec();
                for block in data.chunks_exact_mut(FIPS_BLOCK_SIZE) {
                    decrypt.decrypt_block(block.try_into().expect("a block of FIPS_BLOCK_SIZE bytes"));
                }
                data.truncate(data.len() - padding);
                let expected = fips_mac(hmac_key, &data, count);
                (data, expected)
            }
        };

        if !constant_time_eq(&expected, signature) {
            return Err(StandardSecurityError::MacMismatch);
        }

        Ok(data)
    }

    #[cfg(test)]
    pub(super) fn rc4_keys(&self) -> Option<(&Rc4Key, &Rc4Key)> {
        match self {
            Self::Rc4 { encrypt, decrypt, .. } => Some((encrypt.as_ref(), decrypt.as_ref())),
            Self::Fips { .. } => None,
        }
    }
}

/// The strength of an RC4 method's keys ([MS-RDPBCGR] 5.3.5.1, Table 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KeyStrength {
    Bits40,
    Bits56,
    Bits128,
}

impl KeyStrength {
    /// The 128-bit key reduced to this strength ([MS-RDPBCGR] 5.3.5.1): a 40-bit key is `0xD1269E` and the last 40
    /// bits of the key's first 64, a 56-bit key `0xD1` and the last 56 of them, each an RC4 key of 8 bytes; a 128-bit
    /// key is itself.
    pub(super) fn reduce(self, key: &[u8; 16]) -> SessionKey {
        match self {
            Self::Bits128 => SessionKey::new(key),
            Self::Bits40 | Self::Bits56 => {
                let first_64: [u8; 8] = key[..8].try_into().expect("8 bytes");
                self.salt(first_64)
            }
        }
    }

    /// Salts the first bytes of a 64-bit key to this strength's ([MS-RDPBCGR] 5.3.5.1, 5.3.7.1).
    fn salt(self, mut key: [u8; 8]) -> SessionKey {
        match self {
            Self::Bits40 => key[..3].copy_from_slice(&[0xD1, 0x26, 0x9E]),
            Self::Bits56 => key[0] = 0xD1,
            Self::Bits128 => {}
        }
        SessionKey::new(&key)
    }
}

/// An RC4 key of 8 bytes (40-bit and 56-bit) or 16 bytes (128-bit).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct SessionKey {
    bytes: [u8; 16],
    len: usize,
}

impl SessionKey {
    fn new(key: &[u8]) -> Self {
        let mut bytes = [0u8; 16];
        bytes[..key.len()].copy_from_slice(key);
        Self { bytes, len: key.len() }
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl core::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // NOTE: the key is not shown.
        f.debug_struct("SessionKey")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// The RC4 key of one direction, renewed every [`RC4_KEY_RENEWAL_INTERVAL`] packets.
pub(super) struct Rc4Key {
    strength: KeyStrength,
    initial: SessionKey,
    current: SessionKey,
    cipher: rc4::Rc4,
    since_renewal: u32,
}

impl Rc4Key {
    fn new(strength: KeyStrength, key: SessionKey) -> Self {
        Self {
            strength,
            initial: key,
            current: key,
            cipher: rc4_with(key.as_slice()),
            since_renewal: 0,
        }
    }

    /// Applies the key stream to one packet's data, renewing the key first after [`RC4_KEY_RENEWAL_INTERVAL`]
    /// packets.
    fn apply(&mut self, data: &mut [u8]) {
        if self.since_renewal == RC4_KEY_RENEWAL_INTERVAL {
            self.renew();
        }
        self.cipher.apply_keystream(data);
        self.since_renewal += 1;
    }

    /// [MS-RDPBCGR] 5.3.7.1. The initial and current keys are taken whole: for the 40-bit and 56-bit methods each is
    /// already their first 64 bits.
    fn renew(&mut self) {
        let sha = sha1::Sha1::new()
            .chain_update(self.initial.as_slice())
            .chain_update(PAD1)
            .chain_update(self.current.as_slice())
            .finalize();
        let temp: [u8; 16] = md5::Md5::new()
            .chain_update(self.initial.as_slice())
            .chain_update(PAD2)
            .chain_update(sha)
            .finalize()
            .into();

        let key = match self.strength {
            KeyStrength::Bits128 => {
                let mut key = temp;
                rc4_with(&temp).apply_keystream(&mut key);
                SessionKey::new(&key)
            }
            KeyStrength::Bits40 | KeyStrength::Bits56 => {
                let temp_64: [u8; 8] = temp[..8].try_into().expect("8 bytes");
                let mut pre_salt = temp_64;
                rc4_with(&temp_64).apply_keystream(&mut pre_salt);
                self.strength.salt(pre_salt)
            }
        };

        self.current = key;
        self.cipher = rc4_with(key.as_slice());
        self.since_renewal = 0;
    }

    #[cfg(test)]
    pub(super) fn current(&self) -> SessionKey {
        self.current
    }
}

fn rc4_with(key: &[u8]) -> rc4::Rc4 {
    rc4::Rc4::new_from_slice(key).expect("RC4 takes a key of 8 or 16 bytes")
}

/// The keys of the RC4 methods at 128 bits ([MS-RDPBCGR] 5.3.5.1).
pub(super) struct NonFipsKeys {
    pub(super) mac_key: [u8; 16],
    pub(super) client_encrypt_key: [u8; 16],
    pub(super) client_decrypt_key: [u8; 16],
}

impl NonFipsKeys {
    pub(super) fn derive(client_random: &[u8; CLIENT_RANDOM_SIZE], server_random: &[u8; SERVER_RANDOM_SIZE]) -> Self {
        let salted_hash = |secret: &[u8], salt: &[u8]| -> [u8; 16] {
            let sha = sha1::Sha1::new()
                .chain_update(salt)
                .chain_update(secret)
                .chain_update(client_random)
                .chain_update(server_random)
                .finalize();
            md5::Md5::new().chain_update(secret).chain_update(sha).finalize().into()
        };
        let triple_hash = |secret: &[u8], salts: [&[u8]; 3]| -> [u8; 48] {
            let mut out = [0u8; 48];
            for (chunk, salt) in out.chunks_exact_mut(16).zip(salts) {
                chunk.copy_from_slice(&salted_hash(secret, salt));
            }
            out
        };

        let mut pre_master_secret = [0u8; 48];
        pre_master_secret[..24].copy_from_slice(&client_random[..24]);
        pre_master_secret[24..].copy_from_slice(&server_random[..24]);

        let master_secret = triple_hash(&pre_master_secret, [b"A", b"BB", b"CCC"]);
        let session_key_blob = triple_hash(&master_secret, [b"X", b"YY", b"ZZZ"]);

        let final_hash = |key: &[u8]| -> [u8; 16] {
            md5::Md5::new()
                .chain_update(key)
                .chain_update(client_random)
                .chain_update(server_random)
                .finalize()
                .into()
        };

        Self {
            mac_key: session_key_blob[..16].try_into().expect("16 bytes"),
            client_decrypt_key: final_hash(&session_key_blob[16..32]),
            client_encrypt_key: final_hash(&session_key_blob[32..48]),
        }
    }
}

/// The keys of the FIPS method ([MS-RDPBCGR] 5.3.5.2).
pub(super) struct FipsKeys {
    pub(super) hmac_key: [u8; 20],
    pub(super) client_encrypt_key: [u8; 24],
    pub(super) client_decrypt_key: [u8; 24],
}

impl FipsKeys {
    pub(super) fn derive(client_random: &[u8; CLIENT_RANDOM_SIZE], server_random: &[u8; SERVER_RANDOM_SIZE]) -> Self {
        let encrypt_t: [u8; 20] = sha1::Sha1::new()
            .chain_update(&client_random[16..])
            .chain_update(&server_random[16..])
            .finalize()
            .into();
        let decrypt_t: [u8; 20] = sha1::Sha1::new()
            .chain_update(&client_random[..16])
            .chain_update(&server_random[..16])
            .finalize()
            .into();
        let hmac_key = sha1::Sha1::new()
            .chain_update(decrypt_t)
            .chain_update(encrypt_t)
            .finalize()
            .into();

        Self {
            hmac_key,
            client_encrypt_key: expand_fips_key(&encrypt_t),
            client_decrypt_key: expand_fips_key(&decrypt_t),
        }
    }
}

/// Expands a 160-bit key to the 192 bits of a Triple DES key ([MS-RDPBCGR] 5.3.5.2).
///
/// The key is made 168 bits by copying its first byte to its end. Then the specification reverses the bits of every
/// byte, inserts a zero bit after every seven bits, and reverses every byte again: which is to take the key's bits
/// seven at a time, each byte's least significant bit first, into bits 0 to 6 of each byte of the result. Last, the
/// least significant bit of each byte is altered so that the byte has odd parity.
pub(super) fn expand_fips_key(key: &[u8; 20]) -> [u8; 24] {
    let mut key_168 = [0u8; 21];
    key_168[..20].copy_from_slice(key);
    key_168[20] = key[0];

    let bit = |index: usize| (key_168[index / 8] >> (index % 8)) & 1;

    let mut expanded = [0u8; 24];
    for (index, byte) in expanded.iter_mut().enumerate() {
        let mut value = 0u8;
        for position in 0..7 {
            value |= bit(index * 7 + position) << position;
        }
        if value.count_ones().is_multiple_of(2) {
            value ^= 1;
        }
        *byte = value;
    }
    expanded
}

/// [MS-RDPBCGR] 5.3.6.1 and, with `count`, 5.3.6.1.1.
pub(super) fn non_fips_mac(mac_key: &[u8], data: &[u8], count: Option<u32>) -> [u8; SIGNATURE_SIZE] {
    let data_length = u32::try_from(data.len()).expect("a packet's data is held to its frame's length");
    let mut sha = sha1::Sha1::new()
        .chain_update(mac_key)
        .chain_update(PAD1)
        .chain_update(data_length.to_le_bytes())
        .chain_update(data);
    if let Some(count) = count {
        sha.update(count.to_le_bytes());
    }
    let md5 = md5::Md5::new()
        .chain_update(mac_key)
        .chain_update(PAD2)
        .chain_update(sha.finalize())
        .finalize();
    md5[..SIGNATURE_SIZE]
        .try_into()
        .expect("an MD5 hash is longer than a signature")
}

/// [MS-RDPBCGR] 5.3.6.2.
fn fips_mac(hmac_key: &[u8; 20], data: &[u8], count: u32) -> [u8; SIGNATURE_SIZE] {
    use hmac::{KeyInit as _, Mac as _};

    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(hmac_key).expect("HMAC takes a key of any length");
    mac.update(data);
    mac.update(&count.to_le_bytes());
    let hmac = mac.finalize().into_bytes();
    hmac[..SIGNATURE_SIZE]
        .try_into()
        .expect("an HMAC-SHA-1 is longer than a signature")
}

fn constant_time_eq(a: &[u8; SIGNATURE_SIZE], b: &[u8; SIGNATURE_SIZE]) -> bool {
    a.iter().zip(b).fold(0u8, |difference, (x, y)| difference | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [MS-RDPBCGR] 5.3.5.2's example of a 168-bit key expanded to 192 bits with odd parity: its first five bytes.
    #[test]
    fn fips_key_expansion_matches_the_specification_example() {
        let mut key = [0u8; 20];
        key[..5].copy_from_slice(&[0xD1, 0x5E, 0xC4, 0x7E, 0xDA]);
        let expanded = expand_fips_key(&key);
        assert_eq!(expanded[..5], [0x51, 0x3D, 0x10, 0x76, 0x26]);
    }

    #[test]
    fn fips_key_expansion_gives_every_byte_odd_parity() {
        let key: [u8; 20] = core::array::from_fn(|index| u8::try_from(index * 37 % 256).unwrap());
        for byte in expand_fips_key(&key) {
            assert_eq!(byte.count_ones() % 2, 1);
        }
    }

    /// The renewal of [MS-RDPBCGR] 5.3.7.1 for a 40-bit and a 56-bit key, written out step by step here, with the
    /// crate's own RC4, and compared with the key's.
    #[test]
    fn rc4_key_renewal_of_reduced_keys_follows_the_specification() {
        for strength in [KeyStrength::Bits40, KeyStrength::Bits56] {
            let initial = strength.reduce(&core::array::from_fn(|index| u8::try_from(index * 3).unwrap()));
            let mut key = Rc4Key::new(strength, initial);
            key.renew();

            let mut sha_input = Vec::new();
            sha_input.extend_from_slice(initial.as_slice());
            sha_input.extend_from_slice(&[0x36; 40]);
            sha_input.extend_from_slice(initial.as_slice());
            let sha = sha1::Sha1::digest(&sha_input);
            let mut md5_input = Vec::new();
            md5_input.extend_from_slice(initial.as_slice());
            md5_input.extend_from_slice(&[0x5C; 48]);
            md5_input.extend_from_slice(&sha);
            let temp_128 = md5::Md5::digest(&md5_input);
            let temp_64 = &temp_128[..8];
            let mut expected = crate::crypto::rc4::Rc4::new(temp_64).process(temp_64);
            match strength {
                KeyStrength::Bits40 => expected[..3].copy_from_slice(&[0xD1, 0x26, 0x9E]),
                _ => expected[0] = 0xD1,
            }

            assert_eq!(key.current().as_slice(), &*expected, "{strength:?}");
        }
    }

    /// The renewal of [MS-RDPBCGR] 5.3.7.1, written out step by step here and compared with the key's.
    #[test]
    fn rc4_key_renewal_follows_the_specification() {
        let initial: [u8; 16] = core::array::from_fn(|index| u8::try_from(index).unwrap());
        let mut key = Rc4Key::new(KeyStrength::Bits128, SessionKey::new(&initial));
        key.renew();

        let mut sha_input = Vec::new();
        sha_input.extend_from_slice(&initial);
        sha_input.extend_from_slice(&[0x36; 40]);
        sha_input.extend_from_slice(&initial);
        let sha = sha1::Sha1::digest(&sha_input);
        let mut md5_input = Vec::new();
        md5_input.extend_from_slice(&initial);
        md5_input.extend_from_slice(&[0x5C; 48]);
        md5_input.extend_from_slice(&sha);
        let temp: [u8; 16] = md5::Md5::digest(&md5_input).into();
        let new_key = crate::crypto::rc4::Rc4::new(&temp).process(&temp);

        assert_eq!(key.current().as_slice(), &*new_key);
    }
}
