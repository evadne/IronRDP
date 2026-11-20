use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err,
};

use crate::rdp::headers::{BasicSecurityHeader, BasicSecurityHeaderFlags};
use crate::rdp::standard_security::MAX_MODULUS_BITS;

/// The largest encrypted client random accepted when decoding: the buffer for the largest modulus taken, which is
/// `(bitlen / 8) + 8` bytes long ([MS-RDPBCGR] 5.3.4.1).
///
/// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
const MAX_ENCRYPTED_CLIENT_RANDOM_LEN: usize = MAX_MODULUS_BITS / 8 + 8;

/// Security Exchange PDU Data (TS_SECURITY_PACKET), [MS-RDPBCGR] 2.2.1.10.1
///
/// The client random, encrypted with the server's public key, which the client sends in the RDP Security
/// Commencement phase of the connection sequence under Standard RDP Security.
///
/// The Basic Security Header carries `SEC_EXCHANGE_PKT`, and `SEC_LICENSE_ENCRYPT_SC` to tell the server that the
/// client can process encrypted licensing PDUs, as in the annotated Security Exchange PDU of [MS-RDPBCGR] 4.1.9.
///
/// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityExchangePdu {
    /// `encryptedClientRandom`: the encrypted client random with its eight bytes of rear padding.
    pub encrypted_client_random: Vec<u8>,
}

impl SecurityExchangePdu {
    const NAME: &'static str = "SecurityExchangePdu";

    const FIXED_PART_SIZE: usize = BasicSecurityHeader::FIXED_PART_SIZE + 4 /* length */;

    const FLAGS: BasicSecurityHeaderFlags =
        BasicSecurityHeaderFlags::EXCHANGE_PKT.union(BasicSecurityHeaderFlags::LICENSE_ENCRYPT_SC);
}

impl Encode for SecurityExchangePdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        BasicSecurityHeader { flags: Self::FLAGS }.encode(dst)?;
        dst.write_u32(cast_length!("length", self.encrypted_client_random.len(), in: dst)?);
        dst.write_slice(&self.encrypted_client_random);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE + self.encrypted_client_random.len()
    }
}

impl<'de> Decode<'de> for SecurityExchangePdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let security_header = BasicSecurityHeader::decode(src)?;
        if !security_header.flags.contains(BasicSecurityHeaderFlags::EXCHANGE_PKT) {
            return Err(invalid_field_err!("flags", "SEC_EXCHANGE_PKT is not set", in: src));
        }

        let length: usize = cast_length!("length", src.read_u32(), in: src)?;
        if length > MAX_ENCRYPTED_CLIENT_RANDOM_LEN {
            return Err(invalid_field_err!("length", "encrypted client random is too long", in: src));
        }

        ensure_size!(in: src, size: length);
        let encrypted_client_random = src.read_slice(length).to_vec();

        Ok(Self {
            encrypted_client_random,
        })
    }
}
