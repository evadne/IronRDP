use core::fmt;

use ironrdp_core::{DecodeError, decode};
use num_bigint::BigUint;

use super::CLIENT_RANDOM_SIZE;
use crate::rdp::server_license::ServerCertificate;
use crate::rdp::server_license::cert::CertificateType;

/// The smallest modulus of a server's key taken under Standard RDP Security, in bits.
///
/// The size of the key in the annotated connection sequence of [MS-RDPBCGR] 4.1.4 and of the sample of 4.8.
///
/// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
pub const MIN_MODULUS_BITS: usize = 512;

/// The largest modulus of a server's key taken under Standard RDP Security, in bits.
///
/// It bounds the work of encrypting the client random, `r^e mod n`.
pub const MAX_MODULUS_BITS: usize = 16_384;

/// The OID of `rsaEncryption` (1.2.840.113549.1.1.1), the algorithm of an RSA key in an X.509 certificate.
const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";

/// The zero bytes that follow the modulus of an `RSA_PUBLIC_KEY` ([MS-RDPBCGR] 2.2.1.4.3.1.1.1).
///
/// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
const MODULUS_PADDING: usize = 8;

/// Why the key of the Server Security Data's certificate cannot be used to encrypt the client random.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServerKeyError {
    /// The certificate cannot be read ([MS-RDPBCGR] 2.2.1.4.3.1).
    ///
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
    Certificate(DecodeError),
    /// The certificate holds no RSA public key: what is named.
    NotRsa(&'static str),
    /// The modulus is shorter than [`MIN_MODULUS_BITS`].
    ModulusTooShort { bits: usize },
    /// The modulus is longer than [`MAX_MODULUS_BITS`].
    ModulusTooLong { bits: usize },
    /// The public exponent is less than 3 or even, so that it does not encrypt.
    UnusableExponent,
}

impl fmt::Display for ServerKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate(error) => write!(f, "the server certificate cannot be read: {error}"),
            Self::NotRsa(what) => write!(f, "the server certificate holds no RSA public key: {what}"),
            Self::ModulusTooShort { bits } => {
                write!(
                    f,
                    "the server's key has a {bits}-bit modulus, under {MIN_MODULUS_BITS} bits"
                )
            }
            Self::ModulusTooLong { bits } => {
                write!(
                    f,
                    "the server's key has a {bits}-bit modulus, over {MAX_MODULUS_BITS} bits"
                )
            }
            Self::UnusableExponent => write!(f, "the server's key has a public exponent that does not encrypt"),
        }
    }
}

impl core::error::Error for ServerKeyError {}

/// The RSA public key of the server under Standard RDP Security, from the certificate of the Server Security Data
/// ([MS-RDPBCGR] 2.2.1.4.3.1, 5.3.3).
///
/// A Proprietary Certificate holds the key itself; of an X.509 certificate chain, the key is the one of the chain's
/// last certificate, the server's own ([MS-RDPBCGR] 5.3.3.2). The certificate's signature is not checked: the
/// Proprietary Certificate's is made with the Terminal Services signing key, whose private exponent the
/// specification publishes ([MS-RDPBCGR] 5.3.3.1.1), so it establishes nothing; whether the key is the server's is
/// for the caller to judge.
///
/// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
#[derive(Clone, PartialEq, Eq)]
pub struct ServerPublicKey {
    modulus: BigUint,
    public_exponent: BigUint,
    /// The size in bytes of the key's modulus field without its padding: `bitlen / 8` ([MS-RDPBCGR] 5.3.4.1).
    modulus_len: usize,
}

impl fmt::Debug for ServerPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerPublicKey")
            .field("modulus_bits", &self.modulus_bits())
            .finish_non_exhaustive()
    }
}

impl ServerPublicKey {
    /// Reads the key of the Server Security Data's `serverCertificate`, and holds it to its bounds.
    pub fn from_server_certificate(certificate: &[u8]) -> Result<Self, ServerKeyError> {
        let certificate = decode::<ServerCertificate>(certificate).map_err(ServerKeyError::Certificate)?;

        let key = match certificate.certificate {
            CertificateType::Proprietary(certificate) => {
                // [MS-RDPBCGR] 2.2.1.4.3.1.1.1: the modulus is little-endian, `bitlen / 8` bytes followed by eight
                // bytes of zero padding; the decoder has held `keylen` to `(bitlen / 8) + 8`.
                let key = certificate.public_key;
                let modulus_len = key
                    .modulus
                    .len()
                    .checked_sub(MODULUS_PADDING)
                    .ok_or(ServerKeyError::NotRsa("the modulus is shorter than its padding"))?;
                let (modulus, padding) = key.modulus.split_at(modulus_len);
                if padding.iter().any(|byte| *byte != 0) {
                    return Err(ServerKeyError::NotRsa("the modulus's padding is not zero"));
                }

                Self {
                    modulus: BigUint::from_bytes_le(modulus),
                    public_exponent: BigUint::from(key.public_exponent),
                    modulus_len,
                }
            }
            CertificateType::X509(chain) => {
                use pkcs1::der::Decode as _;
                use x509_cert::der::Decode as _;

                let last = chain
                    .certificate_array
                    .last()
                    .ok_or(ServerKeyError::NotRsa("the certificate chain is empty"))?;
                let certificate = x509_cert::Certificate::from_der(last)
                    .map_err(|_| ServerKeyError::NotRsa("the server's X.509 certificate cannot be read"))?;
                let key_info = certificate.tbs_certificate().subject_public_key_info();
                if key_info.algorithm.oid.to_string() != RSA_ENCRYPTION_OID {
                    return Err(ServerKeyError::NotRsa(
                        "the server's X.509 certificate is not for rsaEncryption",
                    ));
                }
                let key = pkcs1::RsaPublicKey::from_der(key_info.subject_public_key.raw_bytes())
                    .map_err(|_| ServerKeyError::NotRsa("the server's X.509 key is not an RSAPublicKey"))?;
                let modulus = BigUint::from_bytes_be(key.modulus.as_bytes());

                Self {
                    modulus_len: modulus.to_bytes_be().len(),
                    modulus,
                    public_exponent: BigUint::from_bytes_be(key.public_exponent.as_bytes()),
                }
            }
        };

        key.check_bounds()?;

        Ok(key)
    }

    fn check_bounds(&self) -> Result<(), ServerKeyError> {
        let bits = self.modulus_bits();
        if bits < MIN_MODULUS_BITS {
            return Err(ServerKeyError::ModulusTooShort { bits });
        }
        if bits > MAX_MODULUS_BITS {
            return Err(ServerKeyError::ModulusTooLong { bits });
        }
        if self.public_exponent < BigUint::from(3u8) || !self.public_exponent.bit(0) {
            return Err(ServerKeyError::UnusableExponent);
        }
        Ok(())
    }

    /// The number of significant bits of the modulus.
    ///
    /// # Panics
    ///
    /// Never: the modulus is held to [`MAX_MODULUS_BITS`] when the key is read.
    pub fn modulus_bits(&self) -> usize {
        usize::try_from(self.modulus.bits()).expect("held to MAX_MODULUS_BITS")
    }

    /// The key as a PKCS #1 `RSAPublicKey` in DER: the modulus and the public exponent as big-endian integers.
    ///
    /// # Panics
    ///
    /// Never: both integers are positive, and the modulus is held to [`MAX_MODULUS_BITS`], whose DER encodes.
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        use pkcs1::der::Encode as _;

        let modulus = self.modulus.to_bytes_be();
        let public_exponent = self.public_exponent.to_bytes_be();
        pkcs1::RsaPublicKey {
            modulus: pkcs1::UintRef::new(&modulus).expect("a non-empty big-endian integer"),
            public_exponent: pkcs1::UintRef::new(&public_exponent).expect("a non-empty big-endian integer"),
        }
        .to_der()
        .expect("an RSAPublicKey within MAX_MODULUS_BITS encodes")
    }

    /// Encrypts the client random for the Security Exchange PDU ([MS-RDPBCGR] 5.3.4.1).
    ///
    /// `c = r^e mod n`, the random and the result read and written as little-endian, the result copied into a zeroed
    /// buffer of `(bitlen / 8) + 8` bytes.
    ///
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
    pub fn encrypt_client_random(&self, client_random: &[u8; CLIENT_RANDOM_SIZE]) -> Vec<u8> {
        let random = BigUint::from_bytes_le(client_random);
        let encrypted = random.modpow(&self.public_exponent, &self.modulus).to_bytes_le();

        let mut buffer = vec![0u8; self.modulus_len + MODULUS_PADDING];
        // `encrypted < modulus`, whose length in bytes is at most `modulus_len`.
        buffer[..encrypted.len()].copy_from_slice(&encrypted);
        buffer
    }
}
