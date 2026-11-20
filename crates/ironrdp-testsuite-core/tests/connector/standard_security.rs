//! Standard RDP Security with its encryption ([MS-RDPBCGR] 5.3), through the connector: the methods advertised, the
//! refusal of each selection that is not taken, the server's key held for the caller before anything of the Security
//! Exchange exists, the Security Exchange made from the caller's client random, and every PDU after it encrypted.
//!
//! The server's key is the 512-bit key of [MS-RDPBCGR] 4.8, whose private exponent the section gives, so that the
//! Security Exchange can be decrypted here.

use std::borrow::Cow;

use ironrdp_connector::{
    ClientConnector, ClientConnectorState, ConnectorErrorKind, Credentials, CredentialsRefusal, Sequence as _,
    StandardSecurityRefusal,
};
use ironrdp_core::{WriteBuf, decode, encode_vec};
use ironrdp_pdu::gcc::{
    ConferenceCreateResponse, EncryptionLevel, EncryptionMethod, ServerEarlyCapabilityFlags, ServerSecurityData,
};
use ironrdp_pdu::mcs::{AttachUserConfirm, ConnectInitial, ConnectResponse, McsMessage, SendDataIndication};
use ironrdp_pdu::nego::{ConnectionConfirm, ResponseFlags, SecurityProtocol};
use ironrdp_pdu::rdp::ClientInfoPdu;
use ironrdp_pdu::rdp::client_info::ClientInfoFlags;
use ironrdp_pdu::rdp::headers::{ShareControlHeader, ShareControlPdu};
use ironrdp_pdu::rdp::security_exchange::SecurityExchangePdu;
use ironrdp_pdu::rdp::server_license::ServerCertificate;
use ironrdp_pdu::rdp::server_license::cert::{CertificateType, ProprietaryCertificate, RsaPublicKey};
use ironrdp_pdu::rdp::standard_security::{IoChannelPdu, Role, StandardSecurity, StandardSecurityMethod};
use ironrdp_pdu::x224::{X224, X224Data};
use ironrdp_testsuite_core::capsets::SERVER_DEMAND_ACTIVE;
use num_bigint::BigUint;

const IO_CHANNEL: u16 = 1003;
const USER_CHANNEL: u16 = 1007;
const SHARE_ID: u32 = 0x0001_03EA;
const CLIENT_RANDOM: [u8; 32] = [0x5C; 32];
const SERVER_RANDOM: [u8; 32] = [0xA3; 32];

/// [MS-RDPBCGR] 4.8: the sample key's modulus, little-endian.
const MODULUS: [u8; 64] = [
    0x37, 0xa8, 0x70, 0xfe, 0x9a, 0xb9, 0xa8, 0x54, 0xcb, 0x98, 0x79, 0x44, 0x7a, 0xb9, 0xeb, 0x38, 0x06, 0xea, 0x26,
    0xa1, 0x47, 0xea, 0x19, 0x70, 0x5d, 0xf3, 0x52, 0x88, 0x70, 0x21, 0xb5, 0x9e, 0x50, 0xb4, 0xe1, 0xf5, 0x1a, 0xd8,
    0x2d, 0x51, 0x4d, 0x1a, 0xad, 0x79, 0x7c, 0x89, 0x46, 0xb0, 0xcc, 0x66, 0x74, 0x02, 0xd8, 0x28, 0x5d, 0x9d, 0xd7,
    0xca, 0xfc, 0x60, 0x0f, 0x38, 0xf9, 0xb3,
];

/// [MS-RDPBCGR] 4.8: the sample key's private exponent, little-endian.
const PRIVATE_EXPONENT: [u8; 64] = [
    0xc1, 0x07, 0xe7, 0xd4, 0xd3, 0x38, 0x8d, 0x36, 0xf5, 0x9e, 0x8b, 0x96, 0x0d, 0x55, 0x65, 0x08, 0x28, 0x25, 0xa3,
    0x2e, 0xc7, 0x68, 0xd6, 0x44, 0x85, 0x2d, 0x32, 0xf6, 0x72, 0xa8, 0x9b, 0xba, 0x5e, 0x82, 0x82, 0xf0, 0x5c, 0x0c,
    0xeb, 0x6b, 0x12, 0x6a, 0xa7, 0x45, 0x15, 0xce, 0x41, 0xe0, 0x03, 0xe5, 0xe6, 0x6d, 0xdf, 0xfd, 0x58, 0x61, 0x0b,
    0x07, 0xa4, 0x7b, 0xb3, 0xf3, 0x71, 0x94,
];

fn password() -> Credentials {
    Credentials::UsernamePassword {
        username: "standard-user".to_owned(),
        password: "not-a-real-password".to_owned(),
    }
}

fn connector(encryption: bool) -> ClientConnector {
    let mut config = super::test_config();
    config.enable_tls = false;
    config.enable_credssp = false;
    config.enable_standard_rdp_security = true;
    config.credentials = None;
    config.autologon = true;
    let connector = ClientConnector::new(config, "127.0.0.1:3389".parse().unwrap());
    if encryption {
        connector.with_standard_rdp_security_encryption()
    } else {
        connector
    }
}

fn certificate() -> Vec<u8> {
    let mut modulus = MODULUS.to_vec();
    modulus.extend_from_slice(&[0; 8]);
    encode_vec(&ServerCertificate {
        issued_permanently: true,
        certificate: CertificateType::Proprietary(ProprietaryCertificate {
            public_key: RsaPublicKey {
                public_exponent: 0x0001_0001,
                modulus,
            },
            signature: vec![0; 72],
        }),
    })
    .unwrap()
}

fn security_data(method: EncryptionMethod, level: EncryptionLevel) -> ServerSecurityData {
    if method.is_empty() && level == EncryptionLevel::None {
        ServerSecurityData::no_security()
    } else {
        ServerSecurityData {
            encryption_method: method,
            encryption_level: level,
            server_random: Some(SERVER_RANDOM),
            server_cert: certificate(),
        }
    }
}

fn connect_response(security: ServerSecurityData) -> Vec<u8> {
    let mut gcc_blocks = ironrdp_testsuite_core::conference_create::CONFERENCE_CREATE_RESPONSE
        .clone()
        .into_gcc_blocks();
    gcc_blocks.security = security;
    gcc_blocks.message_channel = None;
    gcc_blocks.core.optional_data.early_capability_flags = Some(ServerEarlyCapabilityFlags::SKIP_CHANNELJOIN_SUPPORTED);
    let connect_response = ConnectResponse {
        conference_create_response: ConferenceCreateResponse::new(USER_CHANNEL, gcc_blocks).unwrap(),
        ..ironrdp_testsuite_core::mcs::CONNECT_RESPONSE.clone()
    };
    let mcs = encode_vec(&connect_response).unwrap();
    encode_vec(&X224(X224Data {
        data: Cow::Borrowed(&mcs),
    }))
    .unwrap()
}

/// Steps a connector through the negotiation of Standard RDP Security and the MCS Connect Initial. Returns the Connect
/// Initial's bytes.
fn to_basic_settings(connector: &mut ClientConnector) -> Vec<u8> {
    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();
    output.clear();
    let confirm = encode_vec(&X224(ConnectionConfirm::Response {
        flags: ResponseFlags::empty(),
        protocol: SecurityProtocol::empty(),
    }))
    .unwrap();
    connector.step(&confirm, None, &mut output).unwrap();
    connector.mark_security_upgrade_as_done();
    connector.step_no_input(&mut output).unwrap();
    output.filled().to_vec()
}

fn advertised(connect_initial: &[u8]) -> EncryptionMethod {
    let x224 = decode::<X224<X224Data<'_>>>(connect_initial).unwrap().0;
    let initial = decode::<ConnectInitial>(x224.data.as_ref()).unwrap();
    initial
        .conference_create_request
        .gcc_blocks()
        .security
        .encryption_methods
}

/// A connector holding the server's key: negotiation, the Connect Initial and the Connect Response done.
fn holding_the_key(method: EncryptionMethod, level: EncryptionLevel) -> ClientConnector {
    let mut connector = connector(true);
    to_basic_settings(&mut connector);
    let mut output = WriteBuf::new();
    connector
        .step(&connect_response(security_data(method, level)), None, &mut output)
        .unwrap();
    assert_eq!(output.filled_len(), 0);
    connector
}

fn refusal(method: EncryptionMethod, level: EncryptionLevel) -> StandardSecurityRefusal {
    let mut connector = connector(true);
    to_basic_settings(&mut connector);
    let mut output = WriteBuf::new();
    let error = connector
        .step(&connect_response(security_data(method, level)), None, &mut output)
        .unwrap_err();
    assert_eq!(output.filled_len(), 0, "nothing is sent on a refusal");
    assert!(
        connector.standard_security_key().is_none(),
        "no key is held on a refusal"
    );
    match error.kind() {
        ConnectorErrorKind::StandardSecurityRefused(refusal) => *refusal,
        other => panic!("expected a refusal of the selection, got {other:?}"),
    }
}

fn indication(user_data: &[u8]) -> Vec<u8> {
    encode_vec(&X224(McsMessage::SendDataIndication(SendDataIndication {
        initiator_id: USER_CHANNEL,
        channel_id: IO_CHANNEL,
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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

// == R3: the methods advertised == //

// oracle: spec MS-RDPBCGR §2.2.1.3.3
#[test]
fn client_security_data_advertises_128_bit_and_fips_alone() {
    let mut connector = connector(true);
    assert_eq!(
        advertised(&to_basic_settings(&mut connector)),
        EncryptionMethod::BIT_128 | EncryptionMethod::FIPS
    );
}

/// Upstream's behaviour where the caller does not ask for the encryption: nothing advertised, level None taken, any
/// other selection refused as before.
// oracle: spec MS-RDPBCGR §5.3.2
#[test]
fn without_the_encryption_nothing_is_advertised_and_level_none_alone_is_taken() {
    let mut connector = connector(false);
    assert_eq!(
        advertised(&to_basic_settings(&mut connector)),
        EncryptionMethod::empty()
    );
    let mut output = WriteBuf::new();
    connector
        .step(&connect_response(ServerSecurityData::no_security()), None, &mut output)
        .unwrap();
    assert!(matches!(
        connector.state,
        ClientConnectorState::ChannelConnection { .. }
    ));

    let mut connector = connector_without_encryption_at_basic_settings();
    let error = connector
        .step(
            &connect_response(security_data(EncryptionMethod::BIT_128, EncryptionLevel::High)),
            None,
            &mut output,
        )
        .unwrap_err();
    assert!(matches!(error.kind(), ConnectorErrorKind::General));
}

fn connector_without_encryption_at_basic_settings() -> ClientConnector {
    let mut connector = connector(false);
    to_basic_settings(&mut connector);
    connector
}

// == R5, R3: what is refused == //

// oracle: spec MS-RDPBCGR §5.3.1; spec MS-RDPBCGR §5.3.2
#[test]
fn level_none_is_refused_as_its_own_kind() {
    assert_eq!(
        refusal(EncryptionMethod::empty(), EncryptionLevel::None),
        StandardSecurityRefusal::LevelNone
    );
}

/// Level Low is refused whatever method comes with it: xrdp at `crypt_level=low` selects 40-bit, which was not
/// advertised, and the refusal says level Low.
// oracle: spec MS-RDPBCGR §5.3.1; spec MS-RDPBCGR §5.3.2.1
#[test]
fn level_low_is_refused_as_its_own_kind() {
    for method in [
        EncryptionMethod::BIT_128,
        EncryptionMethod::BIT_40,
        EncryptionMethod::BIT_56,
    ] {
        assert_eq!(
            refusal(method, EncryptionLevel::Low),
            StandardSecurityRefusal::LevelLow,
            "{method:?}"
        );
    }
}

// oracle: spec MS-RDPBCGR §2.2.1.3.3
#[test]
fn a_method_not_advertised_is_refused() {
    for method in [
        EncryptionMethod::BIT_40,
        EncryptionMethod::BIT_56,
        EncryptionMethod::BIT_128 | EncryptionMethod::FIPS,
    ] {
        assert_eq!(
            refusal(method, EncryptionLevel::High),
            StandardSecurityRefusal::MethodNotAdvertised { method },
        );
    }
}

// oracle: spec MS-RDPBCGR §5.3.2; spec MS-RDPBCGR §5.3.6
#[test]
fn a_level_and_a_method_that_do_not_go_together_are_refused() {
    for (method, level) in [
        (EncryptionMethod::BIT_128, EncryptionLevel::None),
        (EncryptionMethod::empty(), EncryptionLevel::High),
        (EncryptionMethod::empty(), EncryptionLevel::Low),
        (EncryptionMethod::BIT_128, EncryptionLevel::Fips),
        (EncryptionMethod::FIPS, EncryptionLevel::High),
        (EncryptionMethod::FIPS, EncryptionLevel::ClientCompatible),
    ] {
        assert_eq!(
            refusal(method, level),
            StandardSecurityRefusal::LevelMethodMismatch { level, method },
        );
    }
}

/// B-STDKEY through the connector: a key past its bounds ends the attempt with a value before the key is held.
#[test]
fn a_server_key_past_its_bounds_is_refused_before_it_is_held() {
    let mut connector = connector(true);
    to_basic_settings(&mut connector);
    let mut security = security_data(EncryptionMethod::BIT_128, EncryptionLevel::High);
    let mut short_modulus = MODULUS[..63].to_vec();
    short_modulus.extend_from_slice(&[0; 8]);
    security.server_cert = encode_vec(&ServerCertificate {
        issued_permanently: true,
        certificate: CertificateType::Proprietary(ProprietaryCertificate {
            public_key: RsaPublicKey {
                public_exponent: 0x0001_0001,
                modulus: short_modulus,
            },
            signature: vec![0; 72],
        }),
    })
    .unwrap();
    let mut output = WriteBuf::new();
    let error = connector
        .step(&connect_response(security), None, &mut output)
        .unwrap_err();
    assert!(matches!(error.kind(), ConnectorErrorKind::ServerKey(_)), "{error:?}");
    assert!(connector.standard_security_key().is_none());
}

// == R4: the server's key, before anything of the Security Exchange == //

// oracle: spec MS-RDPBCGR §2.2.1.4.3.1; spec MS-RDPBCGR §5.3.3.1
#[test]
fn the_server_key_is_held_for_the_caller_and_nothing_is_sent_until_it_is_answered() {
    let mut connector = holding_the_key(EncryptionMethod::BIT_128, EncryptionLevel::High);
    assert!(connector.should_answer_standard_security_key());
    let key = connector.standard_security_key().unwrap();
    assert_eq!(key.modulus_bits(), 512);
    let mut modulus_be = MODULUS.to_vec();
    modulus_be.reverse();
    assert!(contains(&key.to_pkcs1_der(), &modulus_be));

    // A step in this state is refused and changes nothing; nothing is written.
    let mut output = WriteBuf::new();
    assert!(connector.step_no_input(&mut output).is_err());
    assert!(connector.should_answer_standard_security_key());
    assert_eq!(output.filled_len(), 0);

    // No credential before the answer.
    let refused = connector.provide_credentials(password(), None).unwrap_err();
    assert!(matches!(
        refused.kind(),
        ConnectorErrorKind::CredentialsRefused(CredentialsRefusal::IdentityNotEstablished)
    ));

    // The answer moves to the channels; it is refused in any other state.
    connector.accept_standard_security_key(CLIENT_RANDOM).unwrap();
    assert!(matches!(
        connector.state,
        ClientConnectorState::ChannelConnection { .. }
    ));
    assert!(connector.accept_standard_security_key(CLIENT_RANDOM).is_err());
    assert!(matches!(
        connector.state,
        ClientConnectorState::ChannelConnection { .. }
    ));
    connector.provide_credentials(password(), None).unwrap();
}

// == R6, R7: the Security Exchange and every PDU after it == //

/// The whole connection under 128-bit RC4 and FIPS: the Security Exchange carries the caller's client random,
/// encrypted with the server's key; the Client Info is encrypted, with the name and the password given after the
/// answer and in no byte before it; the licensing PDU is taken unencrypted; and the Demand Active, encrypted by the
/// server, is answered with a Confirm Active encrypted by the client.
// oracle: spec MS-RDPBCGR §2.2.1.10; spec MS-RDPBCGR §2.2.1.11; spec MS-RDPBCGR §5.3.4.1; spec MS-RDPBCGR §5.3.8
#[test]
fn every_pdu_after_the_security_exchange_is_encrypted() {
    for (method, level) in [
        (EncryptionMethod::BIT_128, EncryptionLevel::High),
        (EncryptionMethod::BIT_128, EncryptionLevel::ClientCompatible),
        (EncryptionMethod::FIPS, EncryptionLevel::Fips),
    ] {
        let mut connector = holding_the_key(method, level);
        connector.accept_standard_security_key(CLIENT_RANDOM).unwrap();
        connector.provide_credentials(password(), None).unwrap();
        let server = StandardSecurity::new(
            Role::Server,
            StandardSecurityMethod::from_selected(method).unwrap(),
            &CLIENT_RANDOM,
            &SERVER_RANDOM,
            IO_CHANNEL,
            None,
        );

        let mut sent = Vec::new();
        let mut output = WriteBuf::new();
        // Erect Domain, Attach User.
        connector.step_no_input(&mut output).unwrap();
        connector.step_no_input(&mut output).unwrap();
        sent.extend_from_slice(output.filled());
        output.clear();
        let attach_user_confirm = encode_vec(&X224(AttachUserConfirm {
            result: 0,
            initiator_id: USER_CHANNEL,
        }))
        .unwrap();
        connector.step(&attach_user_confirm, None, &mut output).unwrap();
        assert!(matches!(
            connector.state,
            ClientConnectorState::SecurityCommencement { .. }
        ));

        // The Security Exchange: the client random, decrypted with the sample's private exponent.
        connector.step_no_input(&mut output).unwrap();
        let exchange = decode::<SecurityExchangePdu>(&user_data_of(output.filled())).unwrap();
        assert_eq!(exchange.encrypted_client_random.len(), 72);
        let decrypted = BigUint::from_bytes_le(&exchange.encrypted_client_random).modpow(
            &BigUint::from_bytes_le(&PRIVATE_EXPONENT),
            &BigUint::from_bytes_le(&MODULUS),
        );
        assert_eq!(decrypted, BigUint::from_bytes_le(&CLIENT_RANDOM));
        sent.extend_from_slice(output.filled());
        output.clear();

        // The Client Info, encrypted: SEC_INFO_PKT | SEC_ENCRYPT, opened by the server's keys.
        connector.step_no_input(&mut output).unwrap();
        let client_info = output.filled().to_vec();
        output.clear();
        assert_eq!(user_data_of(&client_info)[..2], [0x48, 0x00]);
        sent.extend_from_slice(&client_info);
        let utf16 = |text: &str| -> Vec<u8> { text.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        for secret in [utf16("standard-user"), utf16("not-a-real-password")] {
            assert!(
                !contains(&sent, &secret),
                "{method:?}: a credential crossed in the clear"
            );
        }
        let opened = server.open(&client_info).unwrap();
        let info = decode::<ClientInfoPdu>(&user_data_of(&opened)).unwrap().client_info;
        assert_eq!(info.credentials.username, "standard-user");
        assert_eq!(info.credentials.password, "not-a-real-password");
        assert!(info.flags.contains(ClientInfoFlags::AUTOLOGON));

        // A licensing PDU sent unencrypted, as xrdp sends STATUS_VALID_CLIENT: SEC_LICENSE_PKT, then the Licensing
        // Error Message.
        let valid_client = indication(&[
            0x80, 0x02, 0x00, 0x00, 0xff, 0x03, 0x10, 0x00, 0x07, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00,
        ]);
        // Without a message channel the connect-time auto-detection reads nothing.
        connector.step_no_input(&mut output).unwrap();
        assert!(matches!(
            connector.state,
            ClientConnectorState::LicensingExchange { .. }
        ));
        connector.step(&valid_client, None, &mut output).unwrap();
        assert_eq!(output.filled_len(), 0);
        assert!(matches!(
            connector.state,
            ClientConnectorState::MultitransportBootstrapping { .. }
        ));

        // The Demand Active, encrypted by the server; the Confirm Active, encrypted by the client.
        let demand_active = encode_vec(&ShareControlHeader {
            share_control_pdu: ShareControlPdu::ServerDemandActive(SERVER_DEMAND_ACTIVE.clone()),
            pdu_source: USER_CHANNEL,
            share_id: SHARE_ID,
        })
        .unwrap();
        let sealed = server
            .seal(&indication(&demand_active), IoChannelPdu::ShareControl)
            .unwrap();
        connector.step(&sealed, None, &mut output).unwrap();
        assert!(matches!(
            connector.state,
            ClientConnectorState::ConnectionFinalization { .. }
        ));
        assert_ne!(output.filled_len(), 0);
        let mut rest = output.filled();
        let mut confirm_active = None;
        while !rest.is_empty() {
            let length = ironrdp_pdu::find_size(rest).unwrap().unwrap().length;
            let opened = server.open(&rest[..length]).expect("every PDU the client sends opens");
            confirm_active.get_or_insert(opened);
            rest = &rest[length..];
        }
        let header = decode::<ShareControlHeader>(&user_data_of(&confirm_active.unwrap())).unwrap();
        assert!(matches!(
            header.share_control_pdu,
            ShareControlPdu::ClientConfirmActive(_)
        ));
    }
}

/// A PDU that the server sends unencrypted after the Security Exchange, a licensing PDU apart, ends the attempt with a
/// value; so does one whose MAC does not verify.
// oracle: spec MS-RDPBCGR §5.3.6; spec MS-RDPBCGR §3.2.5.2
#[test]
fn an_unencrypted_pdu_or_a_mac_that_fails_ends_the_connection_with_a_value() {
    for tamper in [false, true] {
        let mut connector = holding_the_key(EncryptionMethod::BIT_128, EncryptionLevel::High);
        connector.accept_standard_security_key(CLIENT_RANDOM).unwrap();
        connector.provide_credentials(password(), None).unwrap();
        let server = StandardSecurity::new(
            Role::Server,
            StandardSecurityMethod::Rc4128Bit,
            &CLIENT_RANDOM,
            &SERVER_RANDOM,
            IO_CHANNEL,
            None,
        );
        let mut output = WriteBuf::new();
        connector.step_no_input(&mut output).unwrap();
        connector.step_no_input(&mut output).unwrap();
        let attach_user_confirm = encode_vec(&X224(AttachUserConfirm {
            result: 0,
            initiator_id: USER_CHANNEL,
        }))
        .unwrap();
        connector.step(&attach_user_confirm, None, &mut output).unwrap();
        connector.step_no_input(&mut output).unwrap();
        connector.step_no_input(&mut output).unwrap();
        assert!(matches!(
            connector.state,
            ClientConnectorState::ConnectTimeAutoDetection { .. } | ClientConnectorState::LicensingExchange { .. }
        ));

        let licensing = [0x80u8, 0x00, 0x00, 0x00, 0xff, 0x03, 0x10, 0x00];
        let frame = if tamper {
            let mut user_data = user_data_of(
                &server
                    .seal(&indication(&licensing), IoChannelPdu::ShareControl)
                    .unwrap(),
            );
            // Make it look like an encrypted licensing PDU, then change its signature.
            user_data[0] |= 0x80;
            user_data[4] ^= 0x01;
            indication(&user_data)
        } else {
            // Neither encrypted nor licensing.
            indication(&[0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04])
        };
        let error = connector.step(&frame, None, &mut output).unwrap_err();
        assert!(
            matches!(error.kind(), ConnectorErrorKind::StandardSecurity(_)),
            "{error:?}"
        );
    }
}

/// [MS-RDPBCGR] section 4 gives the annotated PDUs of one connection, but neither its client random nor the server's
/// private key, so its session keys cannot be derived; these are the first frames that xrdp 0.10.1 sent after the
/// Security Exchange at `crypt_level=high` (128-bit RC4) and `crypt_level=fips`, with the two randoms of each
/// connection, recorded on 20 November 2026 by a client of the patched crates on the project's test host: an
/// unencrypted licensing PDU, the Demand Active, the finalization PDUs and a fast-path update. Every one opens with
/// its MAC verified, so the keys derived here are the ones xrdp derived. They hold no key and no credential: the
/// server's certificate is in the Connect Response, which is not kept.
// oracle: run xrdp 0.10.1 Standard RDP Security 2026-11-20
#[test]
fn xrdp_frames_open_under_keys_derived_from_the_two_randoms() {
    for (method, client_random, server_random, frames) in [
        (
            StandardSecurityMethod::Rc4128Bit,
            HIGH_CLIENT_RANDOM,
            HIGH_SERVER_RANDOM,
            HIGH_FRAMES,
        ),
        (
            StandardSecurityMethod::Fips,
            FIPS_CLIENT_RANDOM,
            FIPS_SERVER_RANDOM,
            FIPS_FRAMES,
        ),
    ] {
        let random = |hex: &str| -> [u8; 32] { hex::decode(hex).unwrap().try_into().unwrap() };
        let client = StandardSecurity::new(
            Role::Client,
            method,
            &random(client_random),
            &random(server_random),
            IO_CHANNEL,
            None,
        );
        for (index, frame) in frames.iter().enumerate() {
            let frame = hex::decode(frame.concat()).unwrap();
            let opened = client
                .open(&frame)
                .unwrap_or_else(|error| panic!("{method:?} frame {index}: {error}"));
            if index == 1 {
                let header = decode::<ShareControlHeader>(&user_data_of(&opened)).unwrap();
                assert!(
                    matches!(header.share_control_pdu, ShareControlPdu::ServerDemandActive(_)),
                    "{method:?}"
                );
            }
        }
    }
}

const HIGH_CLIENT_RANDOM: &str = "46dc3281b06f3b12a2ffd27488c7cdfd0fac6e575a00eb21a70d8f708e40ceaf";
const HIGH_SERVER_RANDOM: &str = "333562eb14a13e0a39f428d523c705af76fb7e79c51a43222300a18c02a6a05c";
const HIGH_FRAMES: [&[&str]; 7] = [
    &["0300002202f08068000103eb701480020000ff031000070000000200000004000000"],
    &[
        "030001bb02f08068000103eb7081ac08000000c89606e56be506f7376a190daec12d1af7105fae9195921f614fcfb874121c",
        "5214bd86ea62733548f80a7f981f496d00504341b26339d0a009dbb4e9d4339f9c9a5079ccd434a34186fd6ad16f3f1a8e9e",
        "d4ff9faa8291431af2ddb963bd7fcc48729a202fe54af106621339d82a65fc48649ef6c938a88f09557528454429c3d19fca",
        "c595d35c1035d06cb130bb211e19c0ae5fc0aec41cde27c245ce9768bb506b1139fdba1b481dd8f25899f2d85a860a6ecd01",
        "4d0ffc94298e7418c1f4ee6ec6f405b6b7c651c2df026f3986dc4e6d2b0f05b71e923cc8de651ce6a98a7fd52d31f84ff6a4",
        "4175ea28e0d44f9ac5672288603582e872dbceaf29b387c3f27685baf3967b68c07165d929d307d66ca45dfd1d7891b9256a",
        "874cbfe6624cb08de41f3285399ac953b7e7791235dea900eb8d9bc00b4a1c9e854196c0e8236c418bf58bf866920da860bc",
        "eedbbb6ba6a838532e5d20af6ff6831d6a7bdd5fc9a99a90698202bc16708b067fbf4c5b2a0a4d5efbd6f627bac04387e210",
        "338ac73279b6d97b369316d7def11613ca69eac68a72bcd63989a2a4398bae5bb167bace96f358af5da018",
    ],
    &["0300003002f08068000103eb702208000000f78fb167a9bb5f968e90827f306f434bf6b21161997aa38bf3b4cf4eb777"],
    &[
        "0300003402f08068000103eb702608000000faed9878a6e3abca823add54396f6ef3f3020c7d6e66d2ce2c2e8f7ad1dea8db",
        "8821",
    ],
    &[
        "0300003402f08068000103eb7026080000005fced5bcaf5fa9a532aa65ee2c32a3518dd5ec7e9a48696625688ad91e7143ab",
        "fe3c",
    ],
    &[
        "0300003402f08068000103eb70260800000091770f58ae21155b851e4a8dba3c1ec057b486f17f66f3dae000616cb62ac5b7",
        "3d70",
    ],
    &["80800ea307e90e67822ad8e208a2"],
];
const FIPS_CLIENT_RANDOM: &str = "07c192ab7fb41a962281996860b8e19c48385585aacbf119a60a60e1faee4b44";
const FIPS_SERVER_RANDOM: &str = "1efe887348198e44098e763a6dbefa7f7706e82ecae7c03dc1860264e9305fc9";
const FIPS_FRAMES: [&[&str]; 7] = [
    &["0300002202f08068000103eb701480020000ff031000070000000200000004000000"],
    &[
        "030001bf02f08068000103eb7081b00800000010000100e1cb434269851359befd0c0c18b360a0298abc0626a96eb1abc87d",
        "c71a7a203a863de29bacd2cf92f3cee6690543115d81dc0460c85da54b99d342752247484f6b79a016e2fa5b861cb80ffe91",
        "f8dbd87de7e302baecb8778a29b7e4e2702cd496cdbfcddc79855d10ab4e2cebc249fee916214c386ebd3e47efeb3737e92f",
        "94173ff9adecc8fddebdd9716cd69bbac48d0f37179ab9710849a44c8d1cb21679b5b99945c77a3d76be63b7ed39e1bec772",
        "cd154dbe5f7d2274b59042672facb1e58988d670eb616becaa580fde3fd2ef135f8922586e7fdbd2f5e6e5d3ad65d0647cc8",
        "7fa766d4e4c0f79361969851038a6e6e7e59f3df5e58c1eff28694730c8d1136f64867454d9e18a3a78029f6bca893d19b09",
        "b028b0f76e05dfaa428ebfda7bedbd6bbc4c0327cd08965de91f71f50b989fd38421464a1597a8d6f613a7fc1b7021c0c05f",
        "ed81dcf5da74a83a97ff010d89ff77a503a03d6d72eaf1543ee063ef686c18965e89feb1167615d89776367078988625ab53",
        "5bcdf4e1008233839ac0b56736697fe97dce004d841f8fd9d27d54c264d37e3844e8756a5d1aa626d629dbe7e5a84a",
    ],
    &[
        "0300003602f08068000103eb70280800000010000102154d39314e3ccab28cd3493c81f5e6d45a161a4c15f6e226038d24eb",
        "8ab95bf2",
    ],
    &[
        "0300003e02f08068000103eb70300800000010000106662fee2367ed258db4108dd82e5a5a2380032f2a33588271d7007d4b",
        "88fff1d292dae9b2461feece",
    ],
    &[
        "0300003e02f08068000103eb7030080000001000010676664eb9bffe285017cfe86b47ed0cb681fdba64cc8feff4ee9334f6",
        "f30c902d09bd729ee88ce186",
    ],
    &[
        "0300003e02f08068000103eb7030080000001000010670c4412dc1c7985a1a8ef7717810e9dbadbe837b89054efab0120f5f",
        "4476d8de7f927885ae5eb9c0",
    ],
    &["80801710000105b77b4abdfe75f70cad761683a4d054db"],
];
