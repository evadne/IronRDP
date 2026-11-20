//! Standard RDP Security in the session: every frame received is opened by the connection's security layer and every
//! frame sent is sealed by it, slow path and fast path; a MAC that fails and a frame that is not encrypted are values.

use ironrdp_core::{WriteBuf, decode, encode_vec};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::Action;
use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent, KeyboardFlags};
use ironrdp_pdu::mcs::{McsMessage, SendDataIndication};
use ironrdp_pdu::rdp::client_info::CompressionType;
use ironrdp_pdu::rdp::headers::{
    CompressionFlags, ShareControlHeader, ShareControlPdu, ShareDataHeader, ShareDataPdu, StreamPriority,
};
use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode, ServerSetErrorInfoPdu};
use ironrdp_pdu::rdp::standard_security::{
    IoChannelPdu, Role, StandardSecurity, StandardSecurityError, StandardSecurityLevel, StandardSecurityMethod,
};
use ironrdp_pdu::rdp::suppress_output::SuppressOutputPdu;
use ironrdp_pdu::x224::X224;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput, SessionErrorKind};
use ironrdp_svc::StaticChannelSet;

const USER_CHANNEL_ID: u16 = 1002;
const IO_CHANNEL_ID: u16 = 1003;
const CLIENT_RANDOM: [u8; 32] = [0x01; 32];
const SERVER_RANDOM: [u8; 32] = [0x02; 32];

fn layer(role: Role, method: StandardSecurityMethod) -> StandardSecurity {
    let level = if method == StandardSecurityMethod::Fips {
        StandardSecurityLevel::Fips
    } else {
        StandardSecurityLevel::High
    };
    layer_at(role, level, method)
}

fn layer_at(role: Role, level: StandardSecurityLevel, method: StandardSecurityMethod) -> StandardSecurity {
    StandardSecurity::new(role, level, method, &CLIENT_RANDOM, &SERVER_RANDOM, IO_CHANNEL_ID, None)
}

fn active_stage(standard_security: StandardSecurity) -> ActiveStage {
    ActiveStageBuilder {
        static_channels: StaticChannelSet::new(),
        user_channel_id: USER_CHANNEL_ID,
        io_channel_id: IO_CHANNEL_ID,
        message_channel_id: None,
        share_id: 0,
        compression_type: None,
        enable_server_pointer: true,
        pointer_software_rendering: false,
        standard_security: Some(standard_security),
    }
    .build()
}

fn set_error_info() -> Vec<u8> {
    let control = ShareControlHeader {
        share_id: 0,
        pdu_source: USER_CHANNEL_ID,
        share_control_pdu: ShareControlPdu::Data(ShareDataHeader {
            share_data_pdu: ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(
                ErrorInfo::ProtocolIndependentCode(ProtocolIndependentCode::LogoffByUser),
            )),
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

/// A fast-path update PDU of one update, a hidden pointer (`FASTPATH_UPDATETYPE_PTR_NULL`, no data).
const POINTER_HIDDEN: [u8; 5] = [0x00, 0x05, 0x05, 0x00, 0x00];

fn image() -> DecodedImage {
    DecodedImage::new(PixelFormat::BgrX32, 64, 64)
}

fn frames(outputs: Vec<ActiveStageOutput>) -> Vec<Vec<u8>> {
    outputs
        .into_iter()
        .filter_map(|output| match output {
            ActiveStageOutput::ResponseFrame(frame) if !frame.is_empty() => Some(frame),
            _ => None,
        })
        .collect()
}

fn opened_user_data(server: &StandardSecurity, frame: &[u8]) -> Vec<u8> {
    match decode::<X224<McsMessage<'_>>>(&server.open(frame).unwrap()).unwrap().0 {
        McsMessage::SendDataRequest(pdu) => pdu.user_data.into_owned(),
        other => panic!("not a Send Data Request: {other:?}"),
    }
}

// oracle: spec MS-RDPBCGR §5.3.8; spec MS-RDPBCGR §2.2.9.1.1.2; spec MS-RDPBCGR §2.2.9.1.2
#[test]
fn received_frames_are_opened_slow_path_and_fast_path() {
    for method in [StandardSecurityMethod::Rc4128Bit, StandardSecurityMethod::Fips] {
        let server = layer(Role::Server, method);
        let mut stage = active_stage(layer(Role::Client, method));
        let mut image = image();

        let sealed = server.seal(&POINTER_HIDDEN, IoChannelPdu::ShareControl).unwrap();
        assert_ne!(sealed, POINTER_HIDDEN);
        let outputs = stage.process(&mut image, Action::FastPath, &sealed, None).unwrap();
        assert!(
            outputs
                .iter()
                .any(|output| matches!(output, ActiveStageOutput::PointerHidden)),
            "{method:?}: {outputs:?}"
        );

        let sealed = server.seal(&set_error_info(), IoChannelPdu::ShareControl).unwrap();
        let outputs = stage.process(&mut image, Action::X224, &sealed, None).unwrap();
        assert!(
            matches!(outputs.as_slice(), [ActiveStageOutput::Terminate(_)]),
            "{method:?}: {outputs:?}"
        );
    }
}

// oracle: spec MS-RDPBCGR §5.3.8; spec MS-RDPBCGR §2.2.8.1.1.2; spec MS-RDPBCGR §2.2.8.1.2
#[test]
fn sent_frames_are_sealed_slow_path_and_fast_path() {
    for method in [StandardSecurityMethod::Rc4128Bit, StandardSecurityMethod::Fips] {
        let server = layer(Role::Server, method);
        let mut stage = active_stage(layer(Role::Client, method));
        let mut image = image();

        // Fast-path input.
        let event = FastPathInputEvent::KeyboardEvent(KeyboardFlags::empty(), 0x1E);
        let sent = frames(stage.process_fastpath_input(&mut image, &[event]).unwrap());
        assert_eq!(sent.len(), 1);
        let plain = encode_vec(&FastPathInput::new(vec![event]).unwrap()).unwrap();
        assert_ne!(sent[0], plain);
        assert_eq!(server.open(&sent[0]).unwrap(), plain, "{method:?}");

        // The graceful shutdown, a Share Data PDU on the I/O channel.
        let sent = frames(stage.graceful_shutdown().unwrap());
        let header = decode::<ShareControlHeader>(&opened_user_data(&server, &sent[0])).unwrap();
        assert!(
            matches!(
                header.share_control_pdu,
                ShareControlPdu::Data(ShareDataHeader {
                    share_data_pdu: ShareDataPdu::ShutdownRequest,
                    ..
                })
            ),
            "{method:?}"
        );

        // A Share Data PDU encoded for the caller, and a full redraw.
        let mut output = WriteBuf::new();
        let written = stage
            .encode_static(
                &mut output,
                ShareDataPdu::SuppressOutput(SuppressOutputPdu { desktop_rect: None }),
            )
            .unwrap();
        assert_eq!(written, output.filled_len());
        opened_user_data(&server, output.filled());
        for frame in stage.request_full_redraw(64, 64, true, true).unwrap() {
            opened_user_data(&server, &frame);
        }
    }
}

// oracle: spec MS-RDPBCGR §3.2.5.9.3; spec MS-RDPBCGR §3.2.5.2
#[test]
fn a_mac_that_fails_and_an_unencrypted_frame_are_values() {
    let server = layer(Role::Server, StandardSecurityMethod::Rc4128Bit);
    let mut stage = active_stage(layer(Role::Client, StandardSecurityMethod::Rc4128Bit));
    let mut image = image();

    let mut sealed = server.seal(&POINTER_HIDDEN, IoChannelPdu::ShareControl).unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 0xFF;
    let error = stage.process(&mut image, Action::FastPath, &sealed, None).unwrap_err();
    assert!(
        matches!(
            error.kind(),
            SessionErrorKind::StandardSecurity(StandardSecurityError::MacMismatch)
        ),
        "{error:?}"
    );

    let mut stage = active_stage(layer(Role::Client, StandardSecurityMethod::Rc4128Bit));
    let error = stage
        .process(&mut image, Action::FastPath, &POINTER_HIDDEN, None)
        .unwrap_err();
    assert!(
        matches!(
            error.kind(),
            SessionErrorKind::StandardSecurity(StandardSecurityError::Unencrypted)
        ),
        "{error:?}"
    );
    let error = stage
        .process(&mut image, Action::X224, &set_error_info(), None)
        .unwrap_err();
    assert!(
        matches!(
            error.kind(),
            SessionErrorKind::StandardSecurity(StandardSecurityError::Unencrypted)
        ),
        "{error:?}"
    );
}

/// Level Low ([MS-RDPBCGR] 5.3.1, 5.3.6): the session takes the server's frames as they come, a Basic Security
/// Header on the slow path and nothing on the fast path, and still encrypts everything it sends; an encrypted Share
/// Data PDU or fast-path update from the server is refused, since the server sends those with a Basic Security Header
/// alone at Low.
// oracle: spec MS-RDPBCGR §5.3.1; spec MS-RDPBCGR §5.3.6; spec MS-RDPBCGR §2.2.9.1.1.3
#[test]
fn at_level_low_frames_are_taken_unencrypted_and_sent_encrypted() {
    for method in [
        StandardSecurityMethod::Rc440Bit,
        StandardSecurityMethod::Rc456Bit,
        StandardSecurityMethod::Rc4128Bit,
    ] {
        let server = layer_at(Role::Server, StandardSecurityLevel::Low, method);
        let mut stage = active_stage(layer_at(Role::Client, StandardSecurityLevel::Low, method));
        let mut image = image();

        let sealed = server.seal(&POINTER_HIDDEN, IoChannelPdu::ShareControl).unwrap();
        assert_eq!(sealed, POINTER_HIDDEN, "the server's fast path is as it is");
        let outputs = stage.process(&mut image, Action::FastPath, &sealed, None).unwrap();
        assert!(
            outputs
                .iter()
                .any(|output| matches!(output, ActiveStageOutput::PointerHidden))
        );

        let sealed = server.seal(&set_error_info(), IoChannelPdu::ShareControl).unwrap();
        let outputs = stage.process(&mut image, Action::X224, &sealed, None).unwrap();
        assert!(
            matches!(outputs.as_slice(), [ActiveStageOutput::Terminate(_)]),
            "{method:?}"
        );

        let event = FastPathInputEvent::KeyboardEvent(KeyboardFlags::empty(), 0x1E);
        let sent = frames(stage.process_fastpath_input(&mut image, &[event]).unwrap());
        assert_ne!(sent[0][0] & 0x80, 0, "{method:?}: the client's fast path is encrypted");
        let plain = encode_vec(&FastPathInput::new(vec![event]).unwrap()).unwrap();
        assert_eq!(server.open(&sent[0]).unwrap(), plain);

        // A server that encrypts its fast path at Low is refused.
        let encrypting = layer_at(Role::Server, StandardSecurityLevel::High, method);
        let mut stage = active_stage(layer_at(Role::Client, StandardSecurityLevel::Low, method));
        let sealed = encrypting.seal(&POINTER_HIDDEN, IoChannelPdu::ShareControl).unwrap();
        let error = stage.process(&mut image, Action::FastPath, &sealed, None).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                SessionErrorKind::StandardSecurity(StandardSecurityError::EncryptedAtLevelLow)
            ),
            "{error:?}"
        );
    }
}
