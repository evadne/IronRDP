//! Credentials given after the server's identity is established, and the connection request's cookie.

use ironrdp_connector::credssp::CredsspSequence;
use ironrdp_connector::{
    ClientConnector, ClientConnectorState, ConnectorErrorKind, Credentials, CredentialsRefusal, Sequence as _,
};
use ironrdp_core::{WriteBuf, decode, encode_vec};
use ironrdp_pdu::gcc::{ConferenceCreateResponse, ServerEarlyCapabilityFlags, ServerSecurityData};
use ironrdp_pdu::mcs::{AttachUserConfirm, ConnectResponse, SendDataRequest};
use ironrdp_pdu::nego::{ConnectionConfirm, ConnectionRequest, NegoRequestData, ResponseFlags, SecurityProtocol};
use ironrdp_pdu::rdp::ClientInfoPdu;
use ironrdp_pdu::rdp::client_info::ClientInfo;
use ironrdp_pdu::x224::{X224, X224Data};

/// The X.224 Connection Request of a client asking for TLS alone, with no cookie: a TPKT header, the X.224 header and
/// an `RDP_NEG_REQ` for `PROTOCOL_SSL`, and nothing else.
const SSL_REQUEST_WITHOUT_COOKIE: [u8; 19] = [
    0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
];

const NTLM_SIGNATURE: &[u8] = b"NTLMSSP\0";

fn password(username: &str) -> Credentials {
    Credentials::UsernamePassword {
        username: username.to_owned(),
        password: "not-a-real-password".to_owned(),
    }
}

fn connector(credentials: Option<Credentials>) -> ClientConnector {
    let mut config = super::test_config();
    config.credentials = credentials;
    ClientConnector::new(config, "127.0.0.1:3389".parse().unwrap())
}

fn confirmation(protocol: SecurityProtocol) -> Vec<u8> {
    encode_vec(&X224(ConnectionConfirm::Response {
        flags: ResponseFlags::empty(),
        protocol,
    }))
    .unwrap()
}

/// Steps the connector through the connection request and the server's confirmation of `protocol`, leaving it in
/// [`ClientConnectorState::EnhancedSecurityUpgrade`].
fn confirmed(mut connector: ClientConnector, protocol: SecurityProtocol) -> ClientConnector {
    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();
    connector.step(&confirmation(protocol), None, &mut output).unwrap();
    assert!(connector.should_perform_security_upgrade());
    connector
}

/// A connector without credentials that has completed the TLS upgrade, as a caller does after judging the server's
/// certificate.
fn after_tls_upgrade() -> ClientConnector {
    let mut connector = confirmed(connector(None), SecurityProtocol::SSL);
    connector.mark_security_upgrade_as_done();
    assert!(matches!(
        connector.state,
        ClientConnectorState::BasicSettingsExchangeSendInitial {
            selected_protocol: SecurityProtocol::SSL
        }
    ));
    connector
}

fn connect_response() -> Vec<u8> {
    let mut gcc_blocks = ironrdp_testsuite_core::conference_create::CONFERENCE_CREATE_RESPONSE
        .clone()
        .into_gcc_blocks();
    gcc_blocks.security = ServerSecurityData::no_security();
    gcc_blocks.core.optional_data.early_capability_flags = Some(ServerEarlyCapabilityFlags::SKIP_CHANNELJOIN_SUPPORTED);
    let connect_response = ConnectResponse {
        conference_create_response: ConferenceCreateResponse::new(1007, gcc_blocks).unwrap(),
        ..ironrdp_testsuite_core::mcs::CONNECT_RESPONSE.clone()
    };
    let mcs = encode_vec(&connect_response).unwrap();
    encode_vec(&X224(X224Data {
        data: std::borrow::Cow::Borrowed(&mcs),
    }))
    .unwrap()
}

/// Steps a connector that is past the TLS upgrade through the basic settings exchange and the channel connection,
/// with a server that skips the channel joins, up to the Client Info PDU. Returns everything the client wrote.
fn to_secure_settings_exchange(connector: &mut ClientConnector) -> Vec<u8> {
    let mut sent = Vec::new();
    let mut output = WriteBuf::new();

    // MCS Connect Initial.
    connector.step_no_input(&mut output).unwrap();
    sent.extend_from_slice(output.filled());
    output.clear();

    connector.step(&connect_response(), None, &mut output).unwrap();
    assert!(matches!(
        connector.state,
        ClientConnectorState::ChannelConnection { .. }
    ));

    // MCS Erect Domain Request, then Attach User Request.
    connector.step_no_input(&mut output).unwrap();
    connector.step_no_input(&mut output).unwrap();
    sent.extend_from_slice(output.filled());
    output.clear();

    let attach_user_confirm = encode_vec(&X224(AttachUserConfirm {
        result: 0,
        initiator_id: 1007,
    }))
    .unwrap();
    connector.step(&attach_user_confirm, None, &mut output).unwrap();
    assert!(matches!(
        connector.state,
        ClientConnectorState::SecureSettingsExchange { .. }
    ));
    assert_eq!(output.filled_len(), 0);

    sent
}

fn decode_client_info(bytes: &[u8]) -> ClientInfo {
    let data = decode::<X224<SendDataRequest<'_>>>(bytes).unwrap().0;
    decode::<ClientInfoPdu>(data.user_data.as_ref()).unwrap().client_info
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn refusal(result: ironrdp_connector::ConnectorResult<()>) -> CredentialsRefusal {
    match result.unwrap_err().kind() {
        ConnectorErrorKind::CredentialsRefused(refusal) => *refusal,
        other => panic!("expected a refusal of the credentials, got {other:?}"),
    }
}

// oracle: spec MS-RDPBCGR §2.2.1.1; spec MS-RDPBCGR §2.2.1.1.1
#[test]
fn connection_request_carries_no_cookie_for_a_user_name() {
    let mut connector = connector(Some(password("cookie-user")));
    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();

    assert_eq!(output.filled(), SSL_REQUEST_WITHOUT_COOKIE);
    assert!(!contains(output.filled(), b"Cookie"));
    assert!(!contains(output.filled(), b"cookie-user"));
    let request = decode::<X224<ConnectionRequest>>(output.filled()).unwrap().0;
    assert!(request.nego_data.is_none());
}

// oracle: spec MS-RDPBCGR §2.2.1.1; spec MS-RDPBCGR §2.2.1.1.1
#[test]
fn connection_request_carries_no_cookie_without_credentials() {
    let mut connector = connector(None);
    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();

    assert_eq!(output.filled(), SSL_REQUEST_WITHOUT_COOKIE);
    let request = decode::<X224<ConnectionRequest>>(output.filled()).unwrap().0;
    assert!(request.nego_data.is_none());
}

// oracle: spec MS-RDPBCGR §2.2.1.1
#[test]
fn connection_request_cookie_is_the_callers_request_data_alone() {
    let mut connector = connector(Some(password("cookie-user")));
    connector.config.request_data = Some(NegoRequestData::cookie("broker-cookie".to_owned()));
    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();

    let request = decode::<X224<ConnectionRequest>>(output.filled()).unwrap().0;
    assert_eq!(
        request.nego_data,
        Some(NegoRequestData::cookie("broker-cookie".to_owned()))
    );
    assert!(!contains(output.filled(), b"cookie-user"));
}

// oracle: spec MS-RDPBCGR §2.2.1.11.1.1; spec MS-RDPBCGR §5.4.2
#[test]
fn client_info_carries_the_name_given_after_the_tls_upgrade() {
    let mut connector = after_tls_upgrade();
    connector
        .provide_credentials(password("late-user"), Some("LATE-DOMAIN".to_owned()))
        .unwrap();

    let sent = to_secure_settings_exchange(&mut connector);
    assert!(!contains(&sent, b"late-user"));
    assert!(!contains(&sent, &utf16("late-user")));

    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();
    let client_info = decode_client_info(output.filled());
    assert_eq!(client_info.credentials.username, "late-user");
    assert_eq!(client_info.credentials.password, "not-a-real-password");
    assert_eq!(client_info.credentials.domain.as_deref(), Some("LATE-DOMAIN"));
}

// oracle: spec MS-RDPBCGR §2.2.1.11.1.1
#[test]
fn client_info_is_not_made_until_credentials_are_provided() {
    let mut connector = after_tls_upgrade();
    to_secure_settings_exchange(&mut connector);

    let mut output = WriteBuf::new();
    let error = connector.step_no_input(&mut output).unwrap_err();
    assert!(matches!(error.kind(), ConnectorErrorKind::CredentialsNotProvided));
    assert_eq!(output.filled_len(), 0);
    assert!(matches!(
        connector.state,
        ClientConnectorState::SecureSettingsExchange { .. }
    ));

    connector
        .provide_credentials(password("last-moment-user"), None)
        .unwrap();
    connector.step_no_input(&mut output).unwrap();
    let client_info = decode_client_info(output.filled());
    assert_eq!(client_info.credentials.username, "last-moment-user");
    assert_eq!(client_info.credentials.domain, None);
    assert!(matches!(
        connector.state,
        ClientConnectorState::ConnectTimeAutoDetection { .. }
    ));
}

// oracle: spec MS-CSSP §3.1.5; spec MS-RDPBCGR §5.4.5.1
#[test]
fn credssp_first_ts_request_is_made_only_after_credentials_are_provided() {
    let mut config = super::test_config();
    config.enable_tls = false;
    config.enable_credssp = true;
    config.credentials = None;
    let connector = ClientConnector::new(config, "127.0.0.1:3389".parse().unwrap());
    let mut connector = confirmed(connector, SecurityProtocol::HYBRID);
    connector.mark_security_upgrade_as_done();
    assert!(connector.should_perform_credssp());

    let init = |connector: &ClientConnector| {
        CredsspSequence::init_for_connector(connector, "server.example".into(), vec![0; 32], None)
    };

    let error = init(&connector).unwrap_err();
    assert!(matches!(error.kind(), ConnectorErrorKind::CredentialsNotProvided));

    connector
        .provide_credentials(password("credssp-user"), Some("CREDSSP-DOMAIN".to_owned()))
        .unwrap();
    let (mut sequence, initial_request) = init(&connector).unwrap();
    let state = sequence
        .process_ts_request(initial_request)
        .resolve_to_result()
        .unwrap();
    let mut output = WriteBuf::new();
    sequence.handle_process_result(state, &mut output).unwrap();
    assert!(contains(output.filled(), NTLM_SIGNATURE));
}

// oracle: spec MS-RDPBCGR §1.3.1.1; spec MS-RDPBCGR §5.4.2
#[test]
fn credentials_are_refused_before_the_tls_upgrade() {
    let mut connector = connector(None);
    assert_eq!(
        refusal(connector.provide_credentials(password("early-user"), None)),
        CredentialsRefusal::IdentityNotEstablished
    );
    assert!(matches!(
        connector.state,
        ClientConnectorState::ConnectionInitiationSendRequest
    ));

    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();
    assert!(matches!(
        connector.state,
        ClientConnectorState::ConnectionInitiationWaitConfirm { .. }
    ));
    assert_eq!(
        refusal(connector.provide_credentials(password("early-user"), None)),
        CredentialsRefusal::IdentityNotEstablished
    );

    connector
        .step(&confirmation(SecurityProtocol::SSL), None, &mut output)
        .unwrap();
    assert!(matches!(
        connector.state,
        ClientConnectorState::EnhancedSecurityUpgrade { .. }
    ));
    assert_eq!(
        refusal(connector.provide_credentials(password("early-user"), None)),
        CredentialsRefusal::IdentityNotEstablished
    );

    assert!(connector.config.credentials.is_none());
    assert!(connector.config.domain.is_none());
}

// oracle: spec MS-RDPBCGR §5.3
#[test]
fn credentials_are_refused_under_standard_rdp_security_without_tls() {
    let mut config = super::test_config();
    config.enable_tls = false;
    config.enable_credssp = false;
    config.enable_standard_rdp_security = true;
    config.credentials = None;
    let connector = ClientConnector::new(config, "127.0.0.1:3389".parse().unwrap());
    let mut connector = confirmed(connector, SecurityProtocol::empty());
    connector.mark_security_upgrade_as_done();
    assert!(matches!(
        connector.state,
        ClientConnectorState::BasicSettingsExchangeSendInitial { .. }
    ));

    assert_eq!(
        refusal(connector.provide_credentials(password("plain-user"), None)),
        CredentialsRefusal::IdentityNotEstablished
    );
    assert!(connector.config.credentials.is_none());
}

#[test]
fn credentials_are_refused_once_provided() {
    let mut provided = after_tls_upgrade();
    provided
        .provide_credentials(password("first-user"), Some("FIRST".to_owned()))
        .unwrap();
    assert_eq!(
        refusal(provided.provide_credentials(password("second-user"), Some("SECOND".to_owned()))),
        CredentialsRefusal::AlreadyProvided
    );
    assert_eq!(provided.config.domain.as_deref(), Some("FIRST"));

    let mut configured = confirmed(connector(Some(password("configured-user"))), SecurityProtocol::SSL);
    configured.mark_security_upgrade_as_done();
    assert_eq!(
        refusal(configured.provide_credentials(password("second-user"), None)),
        CredentialsRefusal::AlreadyProvided
    );
}

#[test]
fn credentials_are_refused_once_the_client_info_is_made_or_the_connector_has_failed() {
    let mut connector = after_tls_upgrade();
    connector.state = ClientConnectorState::ConnectTimeAutoDetection {
        io_channel_id: 1003,
        user_channel_id: 1007,
    };
    assert_eq!(
        refusal(connector.provide_credentials(password("too-late-user"), None)),
        CredentialsRefusal::NoLongerAccepted
    );

    // A step that fails leaves the connector consumed.
    let mut connector = after_tls_upgrade();
    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();
    assert!(connector.step(&[0x03, 0x00, 0x00, 0x04], None, &mut output).is_err());
    assert!(matches!(connector.state, ClientConnectorState::Consumed));
    assert_eq!(
        refusal(connector.provide_credentials(password("too-late-user"), None)),
        CredentialsRefusal::NoLongerAccepted
    );
    assert!(connector.config.credentials.is_none());
}
