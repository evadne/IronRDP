//! The server's reasons for ending a session reach the caller as values.

use ironrdp_core::encode_vec;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::Action;
use ironrdp_pdu::mcs::{DisconnectProviderUltimatum, DisconnectReason, McsMessage, SendDataIndication};
use ironrdp_pdu::rdp::client_info::CompressionType;
use ironrdp_pdu::rdp::headers::{
    CompressionFlags, ShareControlHeader, ShareControlPdu, ShareDataHeader, ShareDataPdu, StreamPriority,
};
use ironrdp_pdu::rdp::server_error_info::{
    ErrorInfo, ProtocolIndependentCode, ProtocolIndependentConnectionBrokerCode, ProtocolIndependentLicensingCode,
    RdpSpecificCode, ServerSetErrorInfoPdu,
};
use ironrdp_pdu::x224::X224;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput, GracefulDisconnectReason};
use ironrdp_svc::StaticChannelSet;

const USER_CHANNEL_ID: u16 = 1002;
const IO_CHANNEL_ID: u16 = 1003;

fn active_stage() -> ActiveStage {
    ActiveStageBuilder {
        static_channels: StaticChannelSet::new(),
        user_channel_id: USER_CHANNEL_ID,
        io_channel_id: IO_CHANNEL_ID,
        message_channel_id: None,
        share_id: 0,
        compression_type: None,
        enable_server_pointer: false,
        pointer_software_rendering: false,
        standard_security: None,
    }
    .build()
}

/// A Set Error Info PDU as a server sends it: Share Data inside a Share Control header, in an MCS Send Data
/// Indication on the I/O channel.
fn set_error_info(error_info: ErrorInfo) -> Vec<u8> {
    let control = ShareControlHeader {
        share_id: 0,
        pdu_source: USER_CHANNEL_ID,
        share_control_pdu: ShareControlPdu::Data(ShareDataHeader {
            share_data_pdu: ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(error_info)),
            stream_priority: StreamPriority::Medium,
            compression_flags: CompressionFlags::empty(),
            compression_type: CompressionType::K8,
        }),
    };

    encode_vec(&X224(SendDataIndication {
        initiator_id: USER_CHANNEL_ID,
        channel_id: IO_CHANNEL_ID,
        user_data: encode_vec(&control).unwrap().into(),
    }))
    .unwrap()
}

fn terminate(frame: &[u8]) -> GracefulDisconnectReason {
    let mut image = DecodedImage::new(PixelFormat::BgrX32, 64, 64);
    let outputs = active_stage().process(&mut image, Action::X224, frame, None).unwrap();

    match outputs.as_slice() {
        [ActiveStageOutput::Terminate(reason)] => reason.clone(),
        other => panic!("expected the session to terminate, got {other:?}"),
    }
}

// oracle: spec MS-RDPBCGR §2.2.5.1.1
#[test]
fn set_error_info_of_each_class_is_carried_as_its_code() {
    for (error_info, code) in [
        (
            ErrorInfo::ProtocolIndependentCode(ProtocolIndependentCode::LogoffByUser),
            0x0000_000C,
        ),
        (
            ErrorInfo::ProtocolIndependentLicensingCode(ProtocolIndependentLicensingCode::NoLicense),
            0x0000_0102,
        ),
        (
            ErrorInfo::ProtocolIndependentConnectionBrokerCode(
                ProtocolIndependentConnectionBrokerCode::DestinationNotFound,
            ),
            0x0000_0400,
        ),
        (
            ErrorInfo::RdpSpecificCode(RdpSpecificCode::UnknownPduType2),
            0x0000_10C9,
        ),
        (ErrorInfo::RdpSpecificCode(RdpSpecificCode::DecryptFailed2), 0x0000_1195),
    ] {
        let frame = set_error_info(error_info);
        // The code is on the wire as the PDU's last four bytes, little-endian.
        assert_eq!(frame[frame.len() - 4..], u32::to_le_bytes(code));

        let reason = terminate(&frame);
        let GracefulDisconnectReason::ErrorInfo(carried) = reason else {
            panic!("expected the Error Info as a value, got {reason:?}");
        };
        assert_eq!(carried, error_info);
        assert_eq!(carried.as_u32(), code);
        assert_eq!(reason.description(), error_info.description());
    }
}

// oracle: spec MS-RDPBCGR §2.2.2.3; spec MS-RDPBCGR §3.1.5.1.1
#[test]
fn mcs_disconnect_provider_ultimatum_is_carried_as_its_reason() {
    for (reason, expected) in [
        (
            DisconnectReason::ProviderInitiated,
            GracefulDisconnectReason::ServerInitiated,
        ),
        (DisconnectReason::UserRequested, GracefulDisconnectReason::UserInitiated),
        (
            DisconnectReason::DomainDisconnected,
            GracefulDisconnectReason::McsDisconnect(DisconnectReason::DomainDisconnected),
        ),
        (
            DisconnectReason::TokenPurged,
            GracefulDisconnectReason::McsDisconnect(DisconnectReason::TokenPurged),
        ),
        (
            DisconnectReason::ChannelPurged,
            GracefulDisconnectReason::McsDisconnect(DisconnectReason::ChannelPurged),
        ),
    ] {
        let frame = encode_vec(&X224(McsMessage::DisconnectProviderUltimatum(
            DisconnectProviderUltimatum::from_reason(reason),
        )))
        .unwrap();

        let carried = terminate(&frame);
        match (&carried, &expected) {
            (GracefulDisconnectReason::ServerInitiated, GracefulDisconnectReason::ServerInitiated)
            | (GracefulDisconnectReason::UserInitiated, GracefulDisconnectReason::UserInitiated) => {}
            (GracefulDisconnectReason::McsDisconnect(carried), GracefulDisconnectReason::McsDisconnect(expected)) => {
                assert_eq!(carried, expected);
                assert_eq!(carried.description(), reason.description());
            }
            _ => panic!("expected {expected:?} for {reason:?}, got {carried:?}"),
        }
    }
}
