//! Tests of the security layer, against [MS-RDPBCGR] section 4 where it gives bytes, and against a peer of the other
//! role built from the same randoms everywhere else.

use super::keys::{self, KeyStrength, NonFipsKeys};
use super::*;
use crate::mcs::ConnectResponse;
use crate::rdp::security_exchange::SecurityExchangePdu;
use crate::rdp::server_license::ServerCertificate;
use crate::rdp::server_license::cert::{CertificateType, ProprietaryCertificate, RsaPublicKey};
use crate::x224::X224Data;

/// [MS-RDPBCGR] 4.1.4: the Server MCS Connect Response PDU with GCC Conference Create Response, whose Server Security
/// Data selects 128-bit RC4 at level Client Compatible with a Proprietary Certificate of a 512-bit key.
const SECTION_4_1_4: [u8; 337] = [
    0x03, 0x00, 0x01, 0x51, 0x02, 0xf0, 0x80, 0x7f, 0x66, 0x82, 0x01, 0x45, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
    0x1a, 0x02, 0x01, 0x22, 0x02, 0x01, 0x03, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01,
    0x02, 0x03, 0x00, 0xff, 0xf8, 0x02, 0x01, 0x02, 0x04, 0x82, 0x01, 0x1f, 0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01,
    0x2a, 0x14, 0x76, 0x0a, 0x01, 0x01, 0x00, 0x01, 0xc0, 0x00, 0x4d, 0x63, 0x44, 0x6e, 0x81, 0x08, 0x01, 0x0c, 0x0c,
    0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x0c, 0x10, 0x00, 0xeb, 0x03, 0x03, 0x00, 0xec, 0x03,
    0xed, 0x03, 0xee, 0x03, 0x00, 0x00, 0x02, 0x0c, 0xec, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x20,
    0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x10, 0x11, 0x77, 0x20, 0x30, 0x61, 0x0a, 0x12, 0xe4, 0x34, 0xa1, 0x1e,
    0xf2, 0xc3, 0x9f, 0x31, 0x7d, 0xa4, 0x5f, 0x01, 0x89, 0x34, 0x96, 0xe0, 0xff, 0x11, 0x08, 0x69, 0x7f, 0x1a, 0xc3,
    0xd2, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x5c, 0x00, 0x52, 0x53,
    0x41, 0x31, 0x48, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xcb,
    0x81, 0xfe, 0xba, 0x6d, 0x61, 0xc3, 0x55, 0x05, 0xd5, 0x5f, 0x2e, 0x87, 0xf8, 0x71, 0x94, 0xd6, 0xf1, 0xa5, 0xcb,
    0xf1, 0x5f, 0x0c, 0x3d, 0xf8, 0x70, 0x02, 0x96, 0xc4, 0xfb, 0x9b, 0xc8, 0x3c, 0x2d, 0x55, 0xae, 0xe8, 0xff, 0x32,
    0x75, 0xea, 0x68, 0x79, 0xe5, 0xa2, 0x01, 0xfd, 0x31, 0xa0, 0xb1, 0x1f, 0x55, 0xa6, 0x1f, 0xc1, 0xf6, 0xd1, 0x83,
    0x88, 0x63, 0x26, 0x56, 0x12, 0xbc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x48, 0x00, 0xe9,
    0xe1, 0xd6, 0x28, 0x46, 0x8b, 0x4e, 0xf5, 0x0a, 0xdf, 0xfd, 0xee, 0x21, 0x99, 0xac, 0xb4, 0xe1, 0x8f, 0x5f, 0x81,
    0x57, 0x82, 0xef, 0x9d, 0x96, 0x52, 0x63, 0x27, 0x18, 0x29, 0xdb, 0xb3, 0x4a, 0xfd, 0x9a, 0xda, 0x42, 0xad, 0xb5,
    0x69, 0x21, 0x89, 0x0e, 0x1d, 0xc0, 0x4c, 0x1a, 0xa8, 0xaa, 0x71, 0x3e, 0x0f, 0x54, 0xb9, 0x9a, 0xe4, 0x99, 0x68,
    0x3f, 0x6c, 0xd6, 0x76, 0x84, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// [MS-RDPBCGR] 4.1.9: the Client Security Exchange PDU, initiator 1007 on the I/O channel 1003.
const SECTION_4_1_9: [u8; 94] = [
    0x03, 0x00, 0x00, 0x5e, 0x02, 0xf0, 0x80, 0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x50, 0x01, 0x02, 0x00, 0x00, 0x48,
    0x00, 0x00, 0x00, 0x91, 0xac, 0x0c, 0x8f, 0x64, 0x8c, 0x39, 0xf4, 0xe7, 0xff, 0x0a, 0x3b, 0x79, 0x11, 0x5c, 0x13,
    0x51, 0x2a, 0xcb, 0x72, 0x8f, 0x9d, 0xb7, 0x42, 0x2e, 0xf7, 0x08, 0x4c, 0x8e, 0xae, 0x55, 0x99, 0x62, 0xd2, 0x81,
    0x81, 0xe4, 0x66, 0xc8, 0x05, 0xea, 0xd4, 0x73, 0x06, 0x3f, 0xc8, 0x5f, 0xaf, 0x2a, 0xfd, 0xfc, 0xf1, 0x64, 0xb3,
    0x3f, 0x0a, 0x15, 0x1d, 0xdb, 0x2c, 0x10, 0x9d, 0x30, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// [MS-RDPBCGR] 4.1.10: the Client Info PDU, encrypted under the keys of the same connection.
const SECTION_4_1_10: [u8; 427] = [
    0x03, 0x00, 0x01, 0xab, 0x02, 0xf0, 0x80, 0x64, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x81, 0x9c, 0x48, 0x00, 0x00, 0x00,
    0x45, 0xca, 0x46, 0xfa, 0x5e, 0xa7, 0xbe, 0xbc, 0x74, 0x21, 0xd3, 0x65, 0xe9, 0xba, 0x76, 0x12, 0x7c, 0x55, 0x4b,
    0x9d, 0x84, 0x3b, 0x3e, 0x07, 0x29, 0x20, 0x73, 0x25, 0x7b, 0xe6, 0x9a, 0xbb, 0xe8, 0x41, 0x8a, 0xa0, 0x69, 0x3f,
    0x26, 0x9a, 0xcd, 0xbc, 0xa6, 0x03, 0x27, 0xf5, 0xce, 0xbb, 0xa8, 0xc2, 0xff, 0x0f, 0x38, 0xa3, 0xbf, 0x74, 0x81,
    0xac, 0xcb, 0xc9, 0x08, 0x49, 0x0a, 0x43, 0xcf, 0x91, 0x31, 0x36, 0xcd, 0xba, 0x3d, 0x16, 0x4f, 0x11, 0xd7, 0x69,
    0x12, 0xc8, 0xe9, 0x57, 0xc0, 0xb8, 0x0f, 0xc4, 0x72, 0x66, 0x79, 0xbd, 0x86, 0xba, 0x30, 0x60, 0x76, 0xb4, 0xcd,
    0x52, 0x5e, 0x79, 0x8e, 0x88, 0x95, 0xf0, 0x9a, 0x43, 0x20, 0xd9, 0x96, 0x74, 0x1d, 0x5c, 0x8a, 0x9a, 0xe3, 0x8a,
    0x5d, 0xd2, 0x55, 0x17, 0x8c, 0xf2, 0x66, 0x6b, 0x3f, 0x3d, 0x3a, 0xe3, 0x2a, 0xd4, 0xff, 0xd5, 0x11, 0x30, 0x30,
    0xe2, 0xff, 0xe2, 0xe4, 0x11, 0x0c, 0x7f, 0x6a, 0x1e, 0xa3, 0xf4, 0x2f, 0xdd, 0x4f, 0x89, 0x8c, 0xc0, 0xca, 0xd3,
    0x8a, 0x49, 0xd7, 0x00, 0xd9, 0x09, 0x40, 0xab, 0x79, 0x1a, 0x72, 0xf9, 0x89, 0x42, 0xaf, 0x20, 0xaa, 0x50, 0xc7,
    0xcd, 0xd0, 0xb8, 0x1e, 0xab, 0xd3, 0xeb, 0x10, 0x01, 0x82, 0x68, 0x9f, 0xf5, 0xc9, 0x05, 0xfe, 0x20, 0xbb, 0x7c,
    0x68, 0xb4, 0x72, 0xcd, 0x37, 0x53, 0xdf, 0x43, 0x0a, 0x6d, 0xde, 0xcb, 0xbe, 0x5f, 0x80, 0x05, 0x1e, 0xb8, 0xf3,
    0x5d, 0x04, 0x0c, 0xc6, 0x66, 0x3b, 0x39, 0x5f, 0x5d, 0xa2, 0xda, 0xb9, 0xea, 0xc9, 0xda, 0xba, 0x7c, 0x9d, 0x4e,
    0x4a, 0x4f, 0x4a, 0x16, 0x04, 0xea, 0x4e, 0x23, 0xd3, 0x6d, 0x2c, 0x2b, 0x42, 0x58, 0x19, 0x69, 0x10, 0x23, 0xd4,
    0xe1, 0xaf, 0x46, 0x34, 0xfc, 0x23, 0x81, 0x59, 0x54, 0x65, 0x5f, 0x6c, 0x67, 0x57, 0x14, 0x62, 0x57, 0x94, 0xf1,
    0x81, 0x86, 0x00, 0xfe, 0x1c, 0x27, 0xf6, 0x76, 0xe2, 0x00, 0xea, 0xc5, 0xf7, 0xb5, 0xe9, 0xb2, 0xad, 0xef, 0x7f,
    0x87, 0x8b, 0x8a, 0xb0, 0xd3, 0x1e, 0x43, 0x54, 0x4b, 0xab, 0xf6, 0xba, 0x7f, 0x5a, 0xb9, 0xe5, 0x2d, 0x5f, 0x81,
    0xab, 0x2a, 0x15, 0xc4, 0x97, 0xbc, 0xd3, 0x92, 0x9a, 0xda, 0xbe, 0x8a, 0xb0, 0xfb, 0xa4, 0x1a, 0xa0, 0x96, 0x26,
    0x86, 0x23, 0x10, 0x1b, 0x21, 0x0a, 0x91, 0x05, 0x22, 0x4d, 0x6c, 0x4d, 0x01, 0x4c, 0x84, 0xf3, 0x50, 0x56, 0x4f,
    0x3a, 0xe4, 0xc0, 0x24, 0xbf, 0x35, 0xf6, 0xf5, 0x8b, 0x3f, 0x20, 0x55, 0x98, 0x91, 0x05, 0x4d, 0xee, 0x46, 0x95,
    0x44, 0x6d, 0x06, 0x33, 0x42, 0x1f, 0x9f, 0x84, 0x91, 0xe7, 0xc5, 0x9f, 0x04, 0x11, 0xde, 0xcf, 0xa5, 0x07, 0x5f,
    0x27, 0xdd, 0xc0, 0xac, 0xb1, 0xa7, 0x98, 0x9d, 0x6d, 0x79, 0x00, 0x70, 0x33, 0xbf, 0x4e, 0x16, 0x23, 0x57, 0xf5,
    0xc7, 0x88, 0x82, 0xd1, 0xc6, 0xa3, 0xb4, 0x0b, 0x29,
];

/// [MS-RDPBCGR] 4.1.10: the decrypted TS_INFO_PACKET of the same PDU.
const SECTION_4_1_10_DECRYPTED: [u8; 400] = [
    0x09, 0x04, 0x09, 0x04, 0xb3, 0x43, 0x00, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e,
    0x00, 0x54, 0x00, 0x44, 0x00, 0x45, 0x00, 0x56, 0x00, 0x00, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x74, 0x00, 0x6f, 0x00,
    0x6e, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x1e, 0x00, 0x31, 0x00, 0x35,
    0x00, 0x37, 0x00, 0x2e, 0x00, 0x35, 0x00, 0x39, 0x00, 0x2e, 0x00, 0x32, 0x00, 0x34, 0x00, 0x32, 0x00, 0x2e, 0x00,
    0x31, 0x00, 0x35, 0x00, 0x36, 0x00, 0x00, 0x00, 0x84, 0x00, 0x43, 0x00, 0x3a, 0x00, 0x5c, 0x00, 0x64, 0x00, 0x65,
    0x00, 0x70, 0x00, 0x6f, 0x00, 0x74, 0x00, 0x73, 0x00, 0x5c, 0x00, 0x77, 0x00, 0x32, 0x00, 0x6b, 0x00, 0x33, 0x00,
    0x5f, 0x00, 0x31, 0x00, 0x5c, 0x00, 0x74, 0x00, 0x65, 0x00, 0x72, 0x00, 0x6d, 0x00, 0x73, 0x00, 0x72, 0x00, 0x76,
    0x00, 0x5c, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x77, 0x00, 0x63, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x65, 0x00, 0x6e, 0x00,
    0x74, 0x00, 0x5c, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x62, 0x00, 0x5c, 0x00, 0x77, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x33,
    0x00, 0x32, 0x00, 0x5c, 0x00, 0x6f, 0x00, 0x62, 0x00, 0x6a, 0x00, 0x5c, 0x00, 0x69, 0x00, 0x33, 0x00, 0x38, 0x00,
    0x36, 0x00, 0x5c, 0x00, 0x6d, 0x00, 0x73, 0x00, 0x74, 0x00, 0x73, 0x00, 0x63, 0x00, 0x61, 0x00, 0x78, 0x00, 0x2e,
    0x00, 0x64, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x00, 0x00, 0xe0, 0x01, 0x00, 0x00, 0x50, 0x00, 0x61, 0x00, 0x63, 0x00,
    0x69, 0x00, 0x66, 0x00, 0x69, 0x00, 0x63, 0x00, 0x20, 0x00, 0x53, 0x00, 0x74, 0x00, 0x61, 0x00, 0x6e, 0x00, 0x64,
    0x00, 0x61, 0x00, 0x72, 0x00, 0x64, 0x00, 0x20, 0x00, 0x54, 0x00, 0x69, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x50, 0x00, 0x61, 0x00, 0x63, 0x00, 0x69, 0x00, 0x66, 0x00, 0x69, 0x00, 0x63, 0x00, 0x20, 0x00, 0x44,
    0x00, 0x61, 0x00, 0x79, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x67, 0x00, 0x68, 0x00, 0x74, 0x00, 0x20, 0x00, 0x54, 0x00,
    0x69, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc4, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00,
];

/// [MS-RDPBCGR] 4.8: the modulus of the sample's 512-bit key, little-endian as on the wire.
const SECTION_4_8_MODULUS: [u8; 64] = [
    0x37, 0xa8, 0x70, 0xfe, 0x9a, 0xb9, 0xa8, 0x54, 0xcb, 0x98, 0x79, 0x44, 0x7a, 0xb9, 0xeb, 0x38, 0x06, 0xea, 0x26,
    0xa1, 0x47, 0xea, 0x19, 0x70, 0x5d, 0xf3, 0x52, 0x88, 0x70, 0x21, 0xb5, 0x9e, 0x50, 0xb4, 0xe1, 0xf5, 0x1a, 0xd8,
    0x2d, 0x51, 0x4d, 0x1a, 0xad, 0x79, 0x7c, 0x89, 0x46, 0xb0, 0xcc, 0x66, 0x74, 0x02, 0xd8, 0x28, 0x5d, 0x9d, 0xd7,
    0xca, 0xfc, 0x60, 0x0f, 0x38, 0xf9, 0xb3,
];

/// [MS-RDPBCGR] 4.8: the private exponent of the sample's key, little-endian.
const SECTION_4_8_PRIVATE_EXPONENT: [u8; 64] = [
    0xc1, 0x07, 0xe7, 0xd4, 0xd3, 0x38, 0x8d, 0x36, 0xf5, 0x9e, 0x8b, 0x96, 0x0d, 0x55, 0x65, 0x08, 0x28, 0x25, 0xa3,
    0x2e, 0xc7, 0x68, 0xd6, 0x44, 0x85, 0x2d, 0x32, 0xf6, 0x72, 0xa8, 0x9b, 0xba, 0x5e, 0x82, 0x82, 0xf0, 0x5c, 0x0c,
    0xeb, 0x6b, 0x12, 0x6a, 0xa7, 0x45, 0x15, 0xce, 0x41, 0xe0, 0x03, 0xe5, 0xe6, 0x6d, 0xdf, 0xfd, 0x58, 0x61, 0x0b,
    0x07, 0xa4, 0x7b, 0xb3, 0xf3, 0x71, 0x94,
];

/// [MS-RDPBCGR] 4.8: the sample client random.
const SECTION_4_8_CLIENT_RANDOM: [u8; 32] = [
    0xff, 0xee, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
];

const CLIENT_RANDOM: [u8; 32] = [0x11; 32];
const SERVER_RANDOM: [u8; 32] = [0x22; 32];
const IO_CHANNEL: u16 = 1003;
const MESSAGE_CHANNEL: u16 = 1008;
const STATIC_CHANNEL: u16 = 1004;
const USER_CHANNEL: u16 = 1007;

/// A client and a server at level High, or FIPS for the FIPS method.
fn pair(method: StandardSecurityMethod) -> (StandardSecurity, StandardSecurity) {
    let level = if method == StandardSecurityMethod::Fips {
        StandardSecurityLevel::Fips
    } else {
        StandardSecurityLevel::High
    };
    pair_at(level, method)
}

fn pair_at(level: StandardSecurityLevel, method: StandardSecurityMethod) -> (StandardSecurity, StandardSecurity) {
    let make = |role| {
        StandardSecurity::new(
            role,
            level,
            method,
            &CLIENT_RANDOM,
            &SERVER_RANDOM,
            IO_CHANNEL,
            Some(MESSAGE_CHANNEL),
        )
    };
    (make(Role::Client), make(Role::Server))
}

fn request(channel_id: u16, user_data: &[u8]) -> Vec<u8> {
    encode_vec(&X224(McsMessage::SendDataRequest(SendDataRequest {
        initiator_id: USER_CHANNEL,
        channel_id,
        user_data: Cow::Borrowed(user_data),
    })))
    .unwrap()
}

fn indication(channel_id: u16, user_data: &[u8]) -> Vec<u8> {
    encode_vec(&X224(McsMessage::SendDataIndication(SendDataIndication {
        initiator_id: USER_CHANNEL,
        channel_id,
        user_data: Cow::Borrowed(user_data),
    })))
    .unwrap()
}

fn user_data_of(frame: &[u8]) -> Vec<u8> {
    match decode::<X224<McsMessage<'_>>>(frame).unwrap().0 {
        McsMessage::SendDataRequest(pdu) => pdu.user_data.into_owned(),
        McsMessage::SendDataIndication(pdu) => pdu.user_data.into_owned(),
        other => panic!("not a Send Data PDU: {other:?}"),
    }
}

fn fast_path(header: u8, payload: &[u8]) -> Vec<u8> {
    let length = fast_path_length(payload.len()).unwrap();
    let mut frame = vec![header];
    push_fast_path_length(&mut frame, length);
    frame.extend_from_slice(payload);
    frame
}

fn proprietary_certificate(modulus_le: &[u8], public_exponent: u32) -> Vec<u8> {
    let mut modulus = modulus_le.to_vec();
    modulus.extend_from_slice(&[0; 8]);
    encode_vec(&ServerCertificate {
        issued_permanently: false,
        certificate: CertificateType::Proprietary(ProprietaryCertificate {
            public_key: RsaPublicKey {
                public_exponent,
                modulus,
            },
            signature: vec![0; 72],
        }),
    })
    .unwrap()
}

/// A modulus of exactly `bits` significant bits, little-endian, odd.
fn modulus_of_bits(bits: usize) -> Vec<u8> {
    let mut modulus = vec![0xA5u8; bits.div_ceil(8)];
    modulus[0] |= 1;
    let top = (bits - 1) % 8;
    let last = modulus.len() - 1;
    modulus[last] &= u8::MAX >> (7 - top);
    modulus[last] |= 1 << top;
    modulus
}

fn server_security_data_of_section_4_1_4() -> crate::gcc::ServerSecurityData {
    let x224 = decode::<X224<X224Data<'_>>>(&SECTION_4_1_4).unwrap().0;
    let response = decode::<ConnectResponse>(x224.data.as_ref()).unwrap();
    response.conference_create_response.into_gcc_blocks().security
}

// == [MS-RDPBCGR] section 4 == //

/// 4.1.4: the Server Security Data and its Proprietary Certificate, read to the byte: the method, the level, the
/// server random and the server's key, written back as a PKCS #1 `RSAPublicKey`.
#[test]
fn section_4_1_4_server_security_data_gives_the_key_to_the_byte() {
    let security = server_security_data_of_section_4_1_4();
    assert_eq!(security.encryption_method, EncryptionMethod::BIT_128);
    assert_eq!(security.encryption_level, EncryptionLevel::ClientCompatible);
    assert_eq!(
        StandardSecurityMethod::from_selected(security.encryption_method),
        Some(StandardSecurityMethod::Rc4128Bit)
    );
    assert_eq!(
        security.server_random.unwrap()[..],
        SECTION_4_1_4[0x79..0x99],
        "the server random is the 32 bytes after serverCertLen"
    );

    let key = ServerPublicKey::from_server_certificate(&security.server_cert).unwrap();
    assert_eq!(key.modulus_bits(), 512);

    // The modulus as the dump has it, little-endian, at 0xbd; RSAPublicKey wants it big-endian.
    let mut modulus_be = SECTION_4_1_4[0xbd..0xbd + 64].to_vec();
    modulus_be.reverse();
    let mut expected = vec![0x30, 0x48, 0x02, 0x41, 0x00];
    expected.extend_from_slice(&modulus_be);
    expected.extend_from_slice(&[0x02, 0x03, 0x01, 0x00, 0x01]);
    assert_eq!(key.to_pkcs1_der(), expected);
}

/// 4.8: the sample client random encrypted with the sample key, as 5.3.4.1 lays it out, decrypts with the sample's
/// private exponent to the same random. The section gives no ciphertext to compare with: its Java prints one.
#[test]
fn section_4_8_sample_client_random_encrypts_and_decrypts_to_itself() {
    use num_bigint::BigUint;

    let key =
        ServerPublicKey::from_server_certificate(&proprietary_certificate(&SECTION_4_8_MODULUS, 0x0001_0001)).unwrap();
    let encrypted = key.encrypt_client_random(&SECTION_4_8_CLIENT_RANDOM);

    assert_eq!(encrypted.len(), 72, "(bitlen / 8) + 8 for a 512-bit key");
    assert_eq!(encrypted[64..], [0; 8], "eight bytes of rear padding");

    let modulus = BigUint::from_bytes_le(&SECTION_4_8_MODULUS);
    let private_exponent = BigUint::from_bytes_le(&SECTION_4_8_PRIVATE_EXPONENT);
    let decrypted = BigUint::from_bytes_le(&encrypted).modpow(&private_exponent, &modulus);
    assert_eq!(decrypted, BigUint::from_bytes_le(&SECTION_4_8_CLIENT_RANDOM));
}

/// 4.1.9: the Security Exchange PDU, written to the byte from its encrypted client random, and read back.
#[test]
fn section_4_1_9_security_exchange_is_written_to_the_byte() {
    let encrypted_client_random = SECTION_4_1_9[22..].to_vec();
    assert_eq!(encrypted_client_random.len(), 72);

    let pdu = SecurityExchangePdu {
        encrypted_client_random,
    };
    let frame = request(IO_CHANNEL, &encode_vec(&pdu).unwrap());
    assert_eq!(frame, SECTION_4_1_9);

    assert_eq!(
        decode::<SecurityExchangePdu>(&user_data_of(&SECTION_4_1_9)).unwrap(),
        pdu
    );
}

/// 4.1.10: the encrypted Client Info PDU's layout, to the byte of its framing: the client's own seal of the
/// section's decrypted TS_INFO_PACKET, under keys of its own, gives a frame of the same length whose framing and
/// security flags are the section's, the signature and the ciphertext being where the section has them. The bytes of
/// the signature and the ciphertext cannot be compared: section 4 gives neither the client random nor the server's
/// private key, so the session keys of its connection cannot be derived.
#[test]
fn section_4_1_10_client_info_is_sealed_with_the_section_layout() {
    let (client, server) = pair(StandardSecurityMethod::Rc4128Bit);

    let mut plain = vec![0x40, 0x00, 0x00, 0x00]; // SEC_INFO_PKT
    plain.extend_from_slice(&SECTION_4_1_10_DECRYPTED);
    let sealed = client
        .seal(&request(IO_CHANNEL, &plain), IoChannelPdu::ClientInfo)
        .unwrap();

    assert_eq!(sealed.len(), SECTION_4_1_10.len());
    assert_eq!(
        sealed[..19],
        SECTION_4_1_10[..19],
        "TPKT, X.224, MCS and the flags SEC_INFO_PKT | SEC_ENCRYPT"
    );

    let opened = server.open(&sealed).unwrap();
    assert_eq!(user_data_of(&opened), plain);

    // The section's own PDU parses to its MAC, which keys of another connection cannot verify.
    let other = pair(StandardSecurityMethod::Rc4128Bit).1;
    assert!(matches!(
        other.open(&SECTION_4_1_10),
        Err(StandardSecurityError::MacMismatch)
    ));
}

// == Sealing and opening == //

#[test]
fn every_kind_of_slow_path_pdu_round_trips_under_both_methods() {
    for method in [
        StandardSecurityMethod::Rc440Bit,
        StandardSecurityMethod::Rc456Bit,
        StandardSecurityMethod::Rc4128Bit,
        StandardSecurityMethod::Fips,
    ] {
        let (client, server) = pair_at(StandardSecurityLevel::ClientCompatible, method);
        let (client, server) = if method == StandardSecurityMethod::Fips {
            pair(method)
        } else {
            (client, server)
        };

        // Share Control on the I/O channel, a static channel, the message channel, and the Client Info.
        let cases: [(u16, Vec<u8>, IoChannelPdu); 4] = [
            (IO_CHANNEL, b"share control data".to_vec(), IoChannelPdu::ShareControl),
            (
                STATIC_CHANNEL,
                b"static channel data".to_vec(),
                IoChannelPdu::ShareControl,
            ),
            (
                MESSAGE_CHANNEL,
                [&[0x00, 0x20, 0x00, 0x00][..], b"autodetect response"].concat(),
                IoChannelPdu::ShareControl,
            ),
            (
                IO_CHANNEL,
                [&[0x40, 0x00, 0x00, 0x00][..], b"client info"].concat(),
                IoChannelPdu::ClientInfo,
            ),
        ];

        for (channel_id, user_data, io_channel_pdu) in cases {
            let sealed = client.seal(&request(channel_id, &user_data), io_channel_pdu).unwrap();
            let sealed_user_data = user_data_of(&sealed);
            let flags = u16::from_le_bytes([sealed_user_data[0], sealed_user_data[1]]);
            assert_ne!(flags & BasicSecurityHeaderFlags::ENCRYPT.bits(), 0);
            assert_eq!(
                user_data_of(&server.open(&sealed).unwrap()),
                user_data,
                "{method:?} {channel_id}"
            );

            let sealed = server
                .seal(&indication(channel_id, &user_data), io_channel_pdu)
                .unwrap();
            assert_eq!(
                user_data_of(&client.open(&sealed).unwrap()),
                user_data,
                "{method:?} {channel_id}"
            );
        }
    }
}

#[test]
fn fast_path_round_trips_with_the_header_bits_kept() {
    for method in [StandardSecurityMethod::Rc4128Bit, StandardSecurityMethod::Fips] {
        let (client, server) = pair(method);

        // A fast-path input PDU of three events (numEvents in bits 2 to 5), and one of twenty, whose count follows
        // the signature and so is encrypted.
        for (header, payload) in [(3u8 << 2, vec![0xAAu8; 9]), (0, [&[20u8][..], &[0xBB; 200]].concat())] {
            let frame = fast_path(header, &payload);
            let sealed = client.seal(&frame, IoChannelPdu::ShareControl).unwrap();
            assert_eq!(sealed[0], header | FAST_PATH_ENCRYPTED);
            assert_eq!(server.open(&sealed).unwrap(), frame, "{method:?}");

            let sealed = server.seal(&frame, IoChannelPdu::ShareControl).unwrap();
            assert_eq!(client.open(&sealed).unwrap(), frame, "{method:?}");
        }
    }
}

#[test]
fn concatenated_frames_are_each_sealed() {
    let (client, server) = pair(StandardSecurityMethod::Rc4128Bit);
    let first = request(IO_CHANNEL, b"first");
    let second = fast_path(1 << 2, b"second");
    let sealed = client
        .seal(&[first.clone(), second.clone()].concat(), IoChannelPdu::ShareControl)
        .unwrap();

    let first_sealed = next_frame(&sealed).unwrap();
    let second_sealed = &sealed[first_sealed.len()..];
    assert_eq!(server.open(first_sealed).unwrap(), first);
    assert_eq!(server.open(second_sealed).unwrap(), second);
}

#[test]
fn licensing_is_sent_as_it_is_and_an_unencrypted_licensing_pdu_is_taken() {
    let (client, server) = pair(StandardSecurityMethod::Rc4128Bit);
    let licensing = request(IO_CHANNEL, &[0x80, 0x00, 0x00, 0x00, 0xFF, 0x03, 0x10, 0x00]);
    assert_eq!(client.seal(&licensing, IoChannelPdu::Licensing).unwrap(), licensing);

    let from_server = indication(IO_CHANNEL, &[0x80, 0x00, 0x00, 0x00, 0xFF, 0x03, 0x10, 0x00]);
    assert_eq!(client.open(&from_server).unwrap(), from_server);

    // Nothing was encrypted, so the keys of both directions are where they began.
    let sealed = server
        .seal(&indication(IO_CHANNEL, b"after"), IoChannelPdu::ShareControl)
        .unwrap();
    assert_eq!(user_data_of(&client.open(&sealed).unwrap()), b"after");
}

#[test]
fn an_unencrypted_pdu_is_refused() {
    let (client, _) = pair(StandardSecurityMethod::Rc4128Bit);
    let frame = indication(IO_CHANNEL, &[0x00, 0x00, 0x00, 0x00, 0x01, 0x02]);
    assert!(matches!(client.open(&frame), Err(StandardSecurityError::Unencrypted)));

    let frame = fast_path(0, &[0x01, 0x02, 0x03]);
    assert!(matches!(client.open(&frame), Err(StandardSecurityError::Unencrypted)));
}

#[test]
fn an_mcs_pdu_that_carries_no_data_is_passed_as_it_is() {
    let (client, _) = pair(StandardSecurityMethod::Rc4128Bit);
    let ultimatum = encode_vec(&X224(McsMessage::DisconnectProviderUltimatum(
        crate::mcs::DisconnectProviderUltimatum::from_reason(crate::mcs::DisconnectReason::UserRequested),
    )))
    .unwrap();
    assert_eq!(client.open(&ultimatum).unwrap(), ultimatum);
    assert_eq!(client.seal(&ultimatum, IoChannelPdu::ShareControl).unwrap(), ultimatum);
}

// == A MAC that fails == //

#[test]
fn a_mac_that_fails_is_a_value_in_every_place() {
    for method in [StandardSecurityMethod::Rc4128Bit, StandardSecurityMethod::Fips] {
        let signature_at = if method == StandardSecurityMethod::Fips { 8 } else { 4 };

        // The signature changed, then the ciphertext changed: slow path.
        for flip in [signature_at, signature_at + SIGNATURE_SIZE] {
            let (client, server) = pair(method);
            let mut user_data = user_data_of(
                &server
                    .seal(&indication(IO_CHANNEL, b"0123456789abcdef"), IoChannelPdu::ShareControl)
                    .unwrap(),
            );
            user_data[flip] ^= 0x01;
            let result = client.open(&indication(IO_CHANNEL, &user_data));
            assert!(
                matches!(result, Err(StandardSecurityError::MacMismatch)),
                "{method:?} at {flip}"
            );
        }

        // Fast path.
        let (client, server) = pair(method);
        let mut sealed = server
            .seal(&fast_path(0, b"0123456789abcdef"), IoChannelPdu::ShareControl)
            .unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x80;
        assert!(
            matches!(client.open(&sealed), Err(StandardSecurityError::MacMismatch)),
            "{method:?}"
        );
    }
}

/// A salted MAC ([MS-RDPBCGR] 5.3.6.1.1), which a server may send whatever the client advertised, is checked as one:
/// with the count of packets decrypted before it.
#[test]
fn a_salted_mac_is_checked_with_the_count() {
    let (client, server) = pair(StandardSecurityMethod::Rc4128Bit);
    let session_keys = NonFipsKeys::derive(&CLIENT_RANDOM, &SERVER_RANDOM);

    // Two packets, so that the second's count is 1.
    for count in 0..2u32 {
        let data = b"salted";
        let sealed = server
            .seal(&indication(IO_CHANNEL, data), IoChannelPdu::ShareControl)
            .unwrap();
        let mut user_data = user_data_of(&sealed);
        user_data[1] |= 0x08; // SEC_SECURE_CHECKSUM, 0x0800
        user_data[4..12].copy_from_slice(&keys::non_fips_mac(&session_keys.mac_key, data, Some(count)));
        assert_eq!(
            user_data_of(&client.open(&indication(IO_CHANNEL, &user_data)).unwrap()),
            data
        );
    }
}

// == The renewal of keys == //

/// [MS-RDPBCGR] 5.3.7.1: the keys of each direction are renewed after 4,096 packets, so that the 4,096th packet is
/// the last under the initial key and the 4,097th the first under the new one; the peer, renewing its own keys, keeps
/// decrypting. At 40, 56 and 128 bits.
#[test]
fn rc4_keys_are_renewed_after_the_4096th_packet_each_way() {
    for (method, strength) in [
        (StandardSecurityMethod::Rc440Bit, KeyStrength::Bits40),
        (StandardSecurityMethod::Rc456Bit, KeyStrength::Bits56),
        (StandardSecurityMethod::Rc4128Bit, KeyStrength::Bits128),
    ] {
        rc4_keys_are_renewed_after_the_4096th_packet(method, strength);
    }
}

fn rc4_keys_are_renewed_after_the_4096th_packet(method: StandardSecurityMethod, strength: KeyStrength) {
    let (client, server) = pair_at(StandardSecurityLevel::ClientCompatible, method);
    let keys = NonFipsKeys::derive(&CLIENT_RANDOM, &SERVER_RANDOM);
    let initial_encrypt = strength.reduce(&keys.client_encrypt_key);
    let initial_decrypt = strength.reduce(&keys.client_decrypt_key);

    let current = |security: &StandardSecurity| {
        let layer = security.lock().unwrap();
        let (encrypt, decrypt) = layer.keys.rc4_keys().unwrap();
        (encrypt.current(), decrypt.current())
    };

    for packet in 1..=RC4_KEY_RENEWAL_INTERVAL + 1 {
        let up = client
            .seal(&request(IO_CHANNEL, b"up"), IoChannelPdu::ShareControl)
            .unwrap();
        assert_eq!(
            user_data_of(&server.open(&up).unwrap()),
            b"up",
            "client to server, packet {packet}"
        );
        let down = server
            .seal(&indication(IO_CHANNEL, b"down"), IoChannelPdu::ShareControl)
            .unwrap();
        assert_eq!(
            user_data_of(&client.open(&down).unwrap()),
            b"down",
            "server to client, packet {packet}"
        );

        let (client_encrypt, client_decrypt) = current(&client);
        if packet <= RC4_KEY_RENEWAL_INTERVAL {
            assert_eq!(client_encrypt, initial_encrypt, "{method:?} packet {packet}");
            assert_eq!(client_decrypt, initial_decrypt, "{method:?} packet {packet}");
        } else {
            assert_ne!(client_encrypt, initial_encrypt, "{method:?} packet {packet}");
            assert_ne!(client_decrypt, initial_decrypt, "{method:?} packet {packet}");
            // The server's keys are the client's, the other way round.
            assert_eq!(current(&server), (client_decrypt, client_encrypt));
        }
    }
}

/// [MS-RDPBCGR] 5.3.7.2: no keys are renewed under FIPS; the 4,097th packet is under the same keys, which the CBC
/// chain of every packet before it carries on.
#[test]
fn fips_keys_are_never_renewed() {
    let (client, server) = pair(StandardSecurityMethod::Fips);
    for packet in 1..=RC4_KEY_RENEWAL_INTERVAL + 1 {
        let up = client
            .seal(&request(IO_CHANNEL, b"up"), IoChannelPdu::ShareControl)
            .unwrap();
        assert_eq!(user_data_of(&server.open(&up).unwrap()), b"up", "packet {packet}");
    }
    assert!(client.lock().unwrap().keys.rc4_keys().is_none());
}

// == FIPS == //

/// [MS-RDPBCGR] 5.3.6.2: the data is padded to a whole number of Triple DES blocks, `padlen` saying how much.
#[test]
fn fips_padding_makes_whole_blocks_and_is_removed() {
    let (client, server) = pair(StandardSecurityMethod::Fips);
    for length in 0..=17usize {
        let data = vec![0x5Au8; length];
        let sealed = client
            .seal(&request(STATIC_CHANNEL, &data), IoChannelPdu::ShareControl)
            .unwrap();
        let user_data = user_data_of(&sealed);

        assert_eq!(user_data[4..6], [0x10, 0x00], "length");
        assert_eq!(user_data[6], 0x01, "version");
        let padding = usize::from(user_data[7]);
        assert_eq!(padding, (8 - length % 8) % 8, "padlen of {length} bytes");
        assert_eq!(user_data.len(), 16 + length + padding);

        assert_eq!(user_data_of(&server.open(&sealed).unwrap()), data);
    }
}

#[test]
fn fips_padding_and_header_out_of_bounds_are_refused() {
    let seal = |data: &[u8]| {
        let (client, server) = pair(StandardSecurityMethod::Fips);
        let user_data = user_data_of(
            &server
                .seal(&indication(IO_CHANNEL, data), IoChannelPdu::ShareControl)
                .unwrap(),
        );
        (client, user_data)
    };

    // padlen at 7 is taken; at 8, one past it, refused.
    let (client, mut user_data) = seal(b"0");
    assert_eq!(user_data[7], 7);
    assert!(client.open(&indication(IO_CHANNEL, &user_data)).is_ok());
    let (client, _) = seal(b"0");
    user_data[7] = 8;
    assert!(matches!(
        client.open(&indication(IO_CHANNEL, &user_data)),
        Err(StandardSecurityError::Malformed(_))
    ));

    // The FIPS header's length is 16 and nothing else.
    let (client, mut user_data) = seal(b"0");
    user_data[4] = 0x0F;
    assert!(matches!(
        client.open(&indication(IO_CHANNEL, &user_data)),
        Err(StandardSecurityError::Malformed(_))
    ));

    // Data that is not a whole number of blocks.
    let (client, mut user_data) = seal(b"01234567");
    user_data.pop();
    assert!(matches!(
        client.open(&indication(IO_CHANNEL, &user_data)),
        Err(StandardSecurityError::Malformed(_))
    ));
}

// == The bounds == //

/// B-STDKEY: a modulus of 512 to 16,384 bits, each at its bound and one past it.
#[test]
fn server_key_modulus_is_held_to_its_bounds() {
    let key = |bits| ServerPublicKey::from_server_certificate(&proprietary_certificate(&modulus_of_bits(bits), 65537));

    assert_eq!(key(MIN_MODULUS_BITS).unwrap().modulus_bits(), MIN_MODULUS_BITS);
    assert!(matches!(
        key(MIN_MODULUS_BITS - 1),
        Err(ServerKeyError::ModulusTooShort { bits: 511 })
    ));
    assert_eq!(key(MAX_MODULUS_BITS).unwrap().modulus_bits(), MAX_MODULUS_BITS);
    assert!(matches!(
        key(MAX_MODULUS_BITS + 1),
        Err(ServerKeyError::ModulusTooLong { bits: 16_385 })
    ));
}

#[test]
fn server_key_exponent_that_does_not_encrypt_is_refused() {
    for exponent in [0, 1, 2, 65536] {
        let certificate = proprietary_certificate(&modulus_of_bits(512), exponent);
        assert!(
            matches!(
                ServerPublicKey::from_server_certificate(&certificate),
                Err(ServerKeyError::UnusableExponent)
            ),
            "{exponent}"
        );
    }
    assert!(ServerPublicKey::from_server_certificate(&proprietary_certificate(&modulus_of_bits(512), 3)).is_ok());
}

#[test]
fn server_key_with_padding_that_is_not_zero_is_refused() {
    let mut certificate = proprietary_certificate(&modulus_of_bits(512), 65537);
    // The modulus's eight bytes of padding are the last eight before the signature blob's header and its 72 bytes.
    let padding_end = certificate.len() - 72 - 4;
    certificate[padding_end - 1] = 1;
    assert!(matches!(
        ServerPublicKey::from_server_certificate(&certificate),
        Err(ServerKeyError::NotRsa(_))
    ));
}

/// The Server Security Data's certificate is read at any length that the PDU holds, 1,025 bytes among them: its
/// bound is the connector's, a value of its own (`ironrdp_connector::MAX_SERVER_CERTIFICATE_LEN`), and not a failure
/// to decode. A certificate longer than the PDU holds is refused before anything is read by its length.
#[test]
fn server_certificate_is_read_at_any_length_that_the_pdu_holds() {
    let security_data = |certificate_length: usize| {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&EncryptionMethod::BIT_128.bits().to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes()); // High
        bytes.extend_from_slice(&32u32.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(certificate_length).unwrap().to_le_bytes());
        bytes.extend_from_slice(&SERVER_RANDOM);
        bytes.extend_from_slice(&vec![0; certificate_length]);
        decode::<crate::gcc::ServerSecurityData>(&bytes)
    };
    assert_eq!(security_data(1024).unwrap().server_cert.len(), 1024);
    assert_eq!(security_data(1025).unwrap().server_cert.len(), 1025);
    assert_eq!(security_data(16_384).unwrap().server_cert.len(), 16_384);

    let mut short = Vec::new();
    short.extend_from_slice(&EncryptionMethod::BIT_128.bits().to_le_bytes());
    short.extend_from_slice(&3u32.to_le_bytes()); // High
    short.extend_from_slice(&32u32.to_le_bytes());
    short.extend_from_slice(&1025u32.to_le_bytes());
    short.extend_from_slice(&SERVER_RANDOM);
    short.extend_from_slice(&[0; 1024]);
    assert!(decode::<crate::gcc::ServerSecurityData>(&short).is_err());
}

/// The Security Exchange PDU's encrypted client random is held to the buffer of the largest key taken.
#[test]
fn security_exchange_length_is_held_to_the_largest_key() {
    let largest = MAX_MODULUS_BITS / 8 + 8;
    let pdu = |length: usize| {
        let mut bytes = vec![0x01, 0x02, 0x00, 0x00];
        bytes.extend_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
        bytes.extend_from_slice(&vec![0; length]);
        decode::<SecurityExchangePdu>(&bytes)
    };
    assert_eq!(pdu(largest).unwrap().encrypted_client_random.len(), largest);
    assert!(pdu(largest + 1).is_err());
}

/// A received frame's declared lengths are checked before anything is read by them.
#[test]
fn received_frames_with_lengths_that_do_not_hold_together_are_refused() {
    let (client, _) = pair(StandardSecurityMethod::Rc4128Bit);

    // A security header with ENCRYPT and no room for the signature: three bytes of it, then none.
    for length in [4usize, 4 + SIGNATURE_SIZE - 1] {
        let mut user_data = vec![0x08, 0x00, 0x00, 0x00];
        user_data.resize(length, 0);
        assert!(matches!(
            client.open(&indication(IO_CHANNEL, &user_data)),
            Err(StandardSecurityError::Malformed(_))
        ));
    }

    // User data shorter than a security header.
    assert!(matches!(
        client.open(&indication(IO_CHANNEL, &[0x08, 0x00])),
        Err(StandardSecurityError::Malformed(_))
    ));

    // A fast-path frame whose length says one byte more than it holds, and one with a byte after it.
    let mut frame = fast_path(FAST_PATH_ENCRYPTED, &[0; SIGNATURE_SIZE + 4]);
    frame[1] += 1;
    assert!(matches!(client.open(&frame), Err(StandardSecurityError::Malformed(_))));
    let mut frame = fast_path(FAST_PATH_ENCRYPTED, &[0; SIGNATURE_SIZE + 4]);
    frame.push(0);
    assert!(matches!(client.open(&frame), Err(StandardSecurityError::Malformed(_))));

    // An encrypted fast-path frame with no room for its signature.
    let frame = fast_path(FAST_PATH_ENCRYPTED, &[0; SIGNATURE_SIZE - 1]);
    assert!(matches!(client.open(&frame), Err(StandardSecurityError::Malformed(_))));
}

/// What is sealed is held to what its framing can say: a fast-path frame at the longest whose sealed form fits is
/// sealed, one byte longer refused; user data likewise.
#[test]
fn sealed_frames_are_held_to_their_framing() {
    let (client, _) = pair(StandardSecurityMethod::Rc4128Bit);

    // Sealed fast path: 1 + 2 + 8 + payload, the payload being everything after the length.
    let longest_payload = MAX_FAST_PATH_LENGTH - 3 - SIGNATURE_SIZE;
    assert!(
        client
            .seal(
                &fast_path(1 << 2, &vec![0; longest_payload]),
                IoChannelPdu::ShareControl
            )
            .is_ok()
    );
    assert!(matches!(
        client.seal(
            &fast_path(1 << 2, &vec![0; longest_payload + 1]),
            IoChannelPdu::ShareControl
        ),
        Err(StandardSecurityError::TooLong { .. })
    ));

    // Sealed user data: 4 + 8 + data.
    let longest_data = MAX_SEALED_USER_DATA - 4 - SIGNATURE_SIZE;
    assert!(
        client
            .seal(&request(IO_CHANNEL, &vec![0; longest_data]), IoChannelPdu::ShareControl)
            .is_ok()
    );
    assert!(matches!(
        client.seal(
            &request(IO_CHANNEL, &vec![0; longest_data + 1]),
            IoChannelPdu::ShareControl
        ),
        Err(StandardSecurityError::TooLong { .. })
    ));
}

/// [MS-RDPBCGR] 5.5: under Standard RDP Security the auto-reconnect verifier is keyed with the client random.
#[test]
fn auto_reconnect_verifier_is_keyed_with_the_client_random() {
    let (client, _) = pair(StandardSecurityMethod::Rc4128Bit);
    let cookie = ServerAutoReconnect {
        logon_id: 7,
        random_bits: [0x33; 16],
    };
    let packet = client.client_auto_reconnect(&cookie).unwrap();
    assert_eq!(
        packet,
        ClientAutoReconnect::from_server_cookie_and_client_random(&cookie, &CLIENT_RANDOM)
    );
    assert_ne!(packet, ClientAutoReconnect::from_server_cookie(&cookie));
}

#[test]
fn debug_shows_no_key() {
    let (client, _) = pair(StandardSecurityMethod::Rc4128Bit);
    let shown = format!("{client:?}");
    assert!(!shown.contains("11, 17"), "{shown}");
    assert!(shown.contains("Rc4128Bit"));
}

// == The 40-bit and 56-bit methods == //

/// [MS-RDPBCGR] 5.3.5.1, Table 1 and the formulas after it: a 40-bit key is 0xD1269E and the last 40 bits of the
/// 128-bit key's first 64, a 56-bit key 0xD1 and the last 56 of them. The section gives the salts and the formulas and
/// no example key, so this holds the formula, not a published vector.
#[test]
fn keys_are_reduced_to_40_and_56_bits_with_the_salt_of_table_1() {
    let key: [u8; 16] = core::array::from_fn(|index| u8::try_from(0x10 + index).unwrap());
    assert_eq!(
        KeyStrength::Bits40.reduce(&key).as_slice(),
        [0xD1, 0x26, 0x9E, 0x13, 0x14, 0x15, 0x16, 0x17]
    );
    assert_eq!(
        KeyStrength::Bits56.reduce(&key).as_slice(),
        [0xD1, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]
    );
    assert_eq!(KeyStrength::Bits128.reduce(&key).as_slice(), key);
}

/// [MS-RDPBCGR] 5.3.6.1: the MAC key is reduced as the encryption keys are, and the MAC is made with the reduced key.
#[test]
fn the_mac_of_a_40_bit_packet_is_made_with_the_reduced_mac_key() {
    let (_, server) = pair_at(
        StandardSecurityLevel::ClientCompatible,
        StandardSecurityMethod::Rc440Bit,
    );
    let keys = NonFipsKeys::derive(&CLIENT_RANDOM, &SERVER_RANDOM);
    let mac_key = KeyStrength::Bits40.reduce(&keys.mac_key);

    let sealed = server
        .seal(&indication(IO_CHANNEL, b"forty"), IoChannelPdu::ShareControl)
        .unwrap();
    let user_data = user_data_of(&sealed);
    assert_eq!(user_data[4..12], keys::non_fips_mac(mac_key.as_slice(), b"forty", None));

    let mut ciphertext = user_data[12..].to_vec();
    rc4::StreamCipher::apply_keystream(
        &mut <rc4::Rc4 as rc4::KeyInit>::new_from_slice(
            KeyStrength::Bits40.reduce(&keys.client_decrypt_key).as_slice(),
        )
        .unwrap(),
        &mut ciphertext,
    );
    assert_eq!(
        ciphertext, b"forty",
        "the server encrypts with the client's decryption key, reduced"
    );
}

#[test]
fn only_exactly_one_advertised_method_is_taken() {
    assert_eq!(
        StandardSecurityMethod::ADVERTISED,
        EncryptionMethod::BIT_40 | EncryptionMethod::BIT_56 | EncryptionMethod::BIT_128 | EncryptionMethod::FIPS
    );
    for method in [
        StandardSecurityMethod::Rc440Bit,
        StandardSecurityMethod::Rc456Bit,
        StandardSecurityMethod::Rc4128Bit,
        StandardSecurityMethod::Fips,
    ] {
        assert_eq!(
            StandardSecurityMethod::from_selected(method.encryption_method()),
            Some(method)
        );
    }
    assert_eq!(
        StandardSecurityMethod::from_selected(EncryptionMethod::BIT_40 | EncryptionMethod::BIT_128),
        None
    );
    assert_eq!(StandardSecurityMethod::from_selected(EncryptionMethod::empty()), None);
}

// == Level Low == //

/// [MS-RDPBCGR] 5.3.1, 5.3.6 and the securityHeader of every server PDU of 2.2: at level Low what the client sends is
/// encrypted, and what the server sends carries a Basic Security Header without `SEC_ENCRYPT`, and no MAC, on the slow
/// path, and no encryption flag or signature on the fast path (2.2.9.1.2).
#[test]
fn at_level_low_the_client_encrypts_and_the_server_does_not() {
    for method in [
        StandardSecurityMethod::Rc440Bit,
        StandardSecurityMethod::Rc456Bit,
        StandardSecurityMethod::Rc4128Bit,
    ] {
        let (client, server) = pair_at(StandardSecurityLevel::Low, method);

        // Client to server: encrypted, the Client Info among it.
        let client_info = [&[0x40, 0x00, 0x00, 0x00][..], b"client info"].concat();
        let sealed = client
            .seal(&request(IO_CHANNEL, &client_info), IoChannelPdu::ClientInfo)
            .unwrap();
        assert_eq!(user_data_of(&sealed)[..2], [0x48, 0x00], "{method:?}");
        assert_eq!(user_data_of(&server.open(&sealed).unwrap()), client_info);

        // Server to client, slow path: a Basic Security Header, the data in the clear.
        let sealed = server
            .seal(&indication(IO_CHANNEL, b"share control"), IoChannelPdu::ShareControl)
            .unwrap();
        assert_eq!(
            user_data_of(&sealed),
            [&[0x00, 0x00, 0x00, 0x00][..], b"share control"].concat()
        );
        assert_eq!(user_data_of(&client.open(&sealed).unwrap()), b"share control");

        // On the message channel, the header keeps its flags.
        let autodetect = [&[0x00, 0x10, 0x00, 0x00][..], b"autodetect"].concat();
        let sealed = server
            .seal(&indication(MESSAGE_CHANNEL, &autodetect), IoChannelPdu::ShareControl)
            .unwrap();
        assert_eq!(user_data_of(&sealed), autodetect);
        assert_eq!(user_data_of(&client.open(&sealed).unwrap()), autodetect);

        // Fast path: as it is.
        let frame = fast_path(0, &[0x05, 0x00, 0x00]);
        assert_eq!(server.seal(&frame, IoChannelPdu::ShareControl).unwrap(), frame);
        assert_eq!(client.open(&frame).unwrap(), frame);
    }
}

/// An unencrypted PDU from the server is refused above level Low and taken at it.
#[test]
fn an_unencrypted_pdu_is_refused_at_high_and_taken_at_low() {
    let frame = indication(IO_CHANNEL, &[0x00, 0x00, 0x00, 0x00, 0x01, 0x02]);
    for (level, taken) in [
        (StandardSecurityLevel::Low, true),
        (StandardSecurityLevel::ClientCompatible, false),
        (StandardSecurityLevel::High, false),
    ] {
        let (client, _) = pair_at(level, StandardSecurityMethod::Rc4128Bit);
        let result = client.open(&frame);
        if taken {
            assert_eq!(user_data_of(&result.unwrap()), [0x01, 0x02]);
        } else {
            assert!(matches!(result, Err(StandardSecurityError::Unencrypted)), "{level:?}");
        }
    }
}

/// At level Low the server may encrypt only the PDUs whose security header is a Basic Security Header at Low only
/// without `SEC_ENCRYPT`: licensing (2.2.1.12), auto-detection (2.2.14.3), multitransport (2.2.15.1) and the
/// heartbeat (2.2.16.1). Those are opened with their MAC verified; any other encrypted PDU, slow path or fast path,
/// is refused.
#[test]
fn at_level_low_an_encrypted_pdu_is_taken_only_where_the_specification_allows_it() {
    let (low_client, _) = pair_at(StandardSecurityLevel::Low, StandardSecurityMethod::Rc4128Bit);
    // A server of the same keys that encrypts, as a server encrypting what it may at Low does.
    let (_, encrypting_server) = pair_at(StandardSecurityLevel::High, StandardSecurityMethod::Rc4128Bit);

    let autodetect = [&[0x00, 0x10, 0x00, 0x00][..], b"autodetect"].concat();
    let sealed = encrypting_server
        .seal(&indication(MESSAGE_CHANNEL, &autodetect), IoChannelPdu::ShareControl)
        .unwrap();
    assert_eq!(user_data_of(&sealed)[..2], [0x08, 0x10]);
    assert_eq!(user_data_of(&low_client.open(&sealed).unwrap()), autodetect);

    let sealed = encrypting_server
        .seal(&indication(IO_CHANNEL, b"share control"), IoChannelPdu::ShareControl)
        .unwrap();
    assert!(matches!(
        low_client.open(&sealed),
        Err(StandardSecurityError::EncryptedAtLevelLow)
    ));

    let sealed = encrypting_server
        .seal(&fast_path(0, &[0x05, 0x00, 0x00]), IoChannelPdu::ShareControl)
        .unwrap();
    assert!(matches!(
        low_client.open(&sealed),
        Err(StandardSecurityError::EncryptedAtLevelLow)
    ));
}
