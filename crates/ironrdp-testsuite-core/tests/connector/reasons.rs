//! Reasons of failure during the connection sequence, as values.

use std::borrow::Cow;

use ironrdp_connector::connection_activation::ConnectionActivationSequence;
use ironrdp_connector::credssp::CredsspSequence;
use ironrdp_connector::sspi::credssp::{NStatusCode, TsRequest};
use ironrdp_connector::{
    ClientConnector, ClientConnectorState, ConnectionFinalizationSequence, ConnectorErrorKind, Credentials,
    Sequence as _,
};
use ironrdp_core::{WriteBuf, encode_vec};
use ironrdp_pdu::mcs::SendDataIndication;
use ironrdp_pdu::nego::{ConnectionConfirm, ResponseFlags, SecurityProtocol};
use ironrdp_pdu::rdp::client_info::CompressionType;
use ironrdp_pdu::rdp::headers::{
    CompressionFlags, ShareControlHeader, ShareControlPdu, ShareDataHeader, ShareDataPdu, StreamPriority,
};
use ironrdp_pdu::rdp::server_error_info::{
    ErrorInfo, ProtocolIndependentCode, ProtocolIndependentLicensingCode, RdpSpecificCode, ServerSetErrorInfoPdu,
};
use ironrdp_pdu::x224::X224;

fn confirmation(protocol: SecurityProtocol) -> Vec<u8> {
    encode_vec(&X224(ConnectionConfirm::Response {
        flags: ResponseFlags::empty(),
        protocol,
    }))
    .unwrap()
}

/// Sends the connection request of a connector configured by `configure`, then gives it a confirmation that selects
/// `selected`, and returns what the error says was requested and selected.
fn select(
    configure: impl FnOnce(&mut ironrdp_connector::Config),
    selected: SecurityProtocol,
) -> (SecurityProtocol, SecurityProtocol) {
    let mut config = super::test_config();
    configure(&mut config);
    let mut connector = ClientConnector::new(config, "127.0.0.1:3389".parse().unwrap());
    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();
    output.clear();

    let error = connector.step(&confirmation(selected), None, &mut output).unwrap_err();
    assert_eq!(output.filled_len(), 0);
    assert!(matches!(connector.state, ClientConnectorState::Consumed));

    match error.kind() {
        ConnectorErrorKind::SelectedNotRequested { requested, selected } => (*requested, *selected),
        other => panic!("expected a selection that was not requested, got {other:?}"),
    }
}

// oracle: spec MS-RDPBCGR §2.2.1.1.1; spec MS-RDPBCGR §2.2.1.2.1
#[test]
fn a_selection_not_requested_carries_what_was_requested_and_what_was_selected() {
    // CredSSP alone requested, Standard RDP Security selected: what xrdp does under `security_layer=rdp`.
    let (requested, selected) = select(
        |config| {
            config.enable_tls = false;
            config.enable_credssp = true;
        },
        SecurityProtocol::empty(),
    );
    assert_eq!(requested, SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX);
    assert_eq!(selected, SecurityProtocol::empty());
    assert!(selected.is_standard_rdp_security());

    // TLS alone requested, CredSSP selected.
    let (requested, selected) = select(|_| {}, SecurityProtocol::HYBRID);
    assert_eq!(requested, SecurityProtocol::SSL);
    assert_eq!(selected, SecurityProtocol::HYBRID);
}

// oracle: spec MS-CSSP §2.2.1; spec MS-CSSP §3.1.5
#[test]
fn a_credssp_refusal_keeps_the_servers_ntstatus() {
    for status in [
        NStatusCode::LOGON_FAILURE,
        NStatusCode::WRONG_PASSWORD,
        NStatusCode(0xC000_0022),
    ] {
        let (mut sequence, initial_request) = CredsspSequence::init(
            Credentials::UsernamePassword {
                username: "refused-user".to_owned(),
                password: "not-a-real-password".to_owned(),
            },
            None,
            SecurityProtocol::HYBRID_EX,
            "server.example".into(),
            vec![0; 32],
            None,
        )
        .unwrap();
        let state = sequence
            .process_ts_request(initial_request)
            .resolve_to_result()
            .unwrap();
        sequence.handle_process_result(state, &mut WriteBuf::new()).unwrap();

        let refusal = TsRequest {
            error_code: Some(status),
            ..TsRequest::default()
        };
        let mut bytes = vec![0; usize::from(refusal.buffer_len().unwrap())];
        refusal.encode_ts_request(bytes.as_mut_slice()).unwrap();

        let error = sequence.decode_server_message(&bytes).unwrap_err();
        let ConnectorErrorKind::Credssp(error) = error.kind() else {
            panic!("expected a CredSSP error, got {:?}", error.kind());
        };
        assert_eq!(error.nstatus, Some(status));
        assert!(
            sequence.next_pdu_hint().is_none(),
            "nothing more is read after a refusal"
        );
    }
}

// oracle: spec MS-CSSP §2.2.1
#[test]
fn a_ts_request_with_a_success_status_is_not_a_refusal() {
    let (mut sequence, initial_request) = CredsspSequence::init(
        Credentials::UsernamePassword {
            username: "accepted-user".to_owned(),
            password: "not-a-real-password".to_owned(),
        },
        None,
        SecurityProtocol::HYBRID,
        "server.example".into(),
        vec![0; 32],
        None,
    )
    .unwrap();
    let state = sequence
        .process_ts_request(initial_request)
        .resolve_to_result()
        .unwrap();
    sequence.handle_process_result(state, &mut WriteBuf::new()).unwrap();

    let message = TsRequest {
        error_code: Some(NStatusCode::SUCCESS),
        ..TsRequest::default()
    };
    let mut bytes = vec![0; usize::from(message.buffer_len().unwrap())];
    message.encode_ts_request(bytes.as_mut_slice()).unwrap();

    let decoded = sequence.decode_server_message(&bytes).unwrap().unwrap();
    assert_eq!(decoded.error_code, Some(NStatusCode::SUCCESS));
}

const USER_CHANNEL_ID: u16 = 1002;
const IO_CHANNEL_ID: u16 = 1003;
const SHARE_ID: u32 = 0x0001_0000;

/// A Set Error Info PDU as a server sends it on the I/O channel.
fn set_error_info(error_info: ErrorInfo) -> Vec<u8> {
    let control = ShareControlHeader {
        share_control_pdu: ShareControlPdu::Data(ShareDataHeader {
            share_data_pdu: ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(error_info)),
            stream_priority: StreamPriority::Medium,
            compression_flags: CompressionFlags::empty(),
            compression_type: CompressionType::K8,
        }),
        pdu_source: USER_CHANNEL_ID,
        share_id: SHARE_ID,
    };

    encode_vec(&X224(SendDataIndication {
        initiator_id: USER_CHANNEL_ID,
        channel_id: IO_CHANNEL_ID,
        user_data: Cow::Owned(encode_vec(&control).unwrap()),
    }))
    .unwrap()
}

const ERROR_INFOS: [ErrorInfo; 3] = [
    ErrorInfo::ProtocolIndependentCode(ProtocolIndependentCode::ServerDeniedConnection),
    ErrorInfo::ProtocolIndependentLicensingCode(ProtocolIndependentLicensingCode::NoLicenseServer),
    ErrorInfo::RdpSpecificCode(RdpSpecificCode::UnknownPduType2),
];

// oracle: spec MS-RDPBCGR §1.3.1.3; spec MS-RDPBCGR §2.2.5.1.1
#[test]
fn set_error_info_during_capabilities_exchange_is_carried_as_its_code() {
    for error_info in ERROR_INFOS {
        let mut sequence = ConnectionActivationSequence::new(super::test_config(), IO_CHANNEL_ID, USER_CHANNEL_ID);
        let error = sequence
            .step(&set_error_info(error_info), None, &mut WriteBuf::new())
            .unwrap_err();
        match error.kind() {
            ConnectorErrorKind::ServerErrorInfo(carried) => assert_eq!(*carried, error_info),
            other => panic!("expected the Error Info as a value, got {other:?}"),
        }
    }
}

// oracle: spec MS-RDPBCGR §2.2.5.1.1
#[test]
fn set_error_info_during_finalization_is_carried_as_its_code() {
    for error_info in ERROR_INFOS {
        let mut sequence = ConnectionFinalizationSequence::new(IO_CHANNEL_ID, USER_CHANNEL_ID, SHARE_ID);
        let mut output = WriteBuf::new();
        while sequence.next_pdu_hint().is_none() {
            sequence.step_no_input(&mut output).unwrap();
        }
        let error = sequence
            .step(&set_error_info(error_info), None, &mut output)
            .unwrap_err();
        match error.kind() {
            ConnectorErrorKind::ServerErrorInfo(carried) => assert_eq!(*carried, error_info),
            other => panic!("expected the Error Info as a value, got {other:?}"),
        }
    }
}
