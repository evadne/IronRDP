//! Credentials with and without the `smart-card` feature.
//!
//! These tests live in the crate rather than in `ironrdp-testsuite-core` because they must also run
//! with the default features off, which the test suite cannot do: its other dependencies enable them.

#[cfg(feature = "smart-card")]
use ironrdp_connector::ConnectorErrorKind;
use ironrdp_connector::credssp::CredsspSequence;
use ironrdp_connector::{Credentials, ServerName};
use ironrdp_core::WriteBuf;
use ironrdp_pdu::nego::SecurityProtocol;
#[cfg(feature = "remote-guard")]
use {ironrdp_dvc as _, ironrdp_rdpear as _};
use {ironrdp_error as _, ironrdp_svc as _, rand as _, serde_json as _, tracing as _, url as _};
#[cfg(feature = "smart-card")]
use {picky as _, picky_asn1_der as _, picky_asn1_x509 as _};

const NTLM_SIGNATURE: &[u8] = b"NTLMSSP\0";

fn password_credentials() -> Credentials {
    Credentials::UsernamePassword {
        username: "user".to_owned(),
        password: "password".to_owned(),
    }
}

fn init(credentials: Credentials) -> ironrdp_connector::ConnectorResult<(CredsspSequence, sspi::credssp::TsRequest)> {
    CredsspSequence::init(
        credentials,
        None,
        SecurityProtocol::HYBRID,
        ServerName::new("server.example"),
        Vec::new(),
        None,
    )
}

#[test]
fn password_credentials_start_ntlm() {
    let (mut sequence, initial_request) = init(password_credentials()).expect("CredSSP accepts a password");

    let state = sequence
        .process_ts_request(initial_request)
        .resolve_to_result()
        .expect("NTLM negotiation needs no network request");

    let mut output = WriteBuf::new();
    sequence
        .handle_process_result(state, &mut output)
        .expect("the first TSRequest is written");

    assert!(
        output
            .filled()
            .windows(NTLM_SIGNATURE.len())
            .any(|w| w == NTLM_SIGNATURE),
        "the first TSRequest carries an NTLM message"
    );
}

#[cfg(feature = "smart-card")]
#[test]
fn smart_card_credentials_without_configuration_are_refused() {
    let credentials = Credentials::SmartCard {
        pin: "1234".to_owned(),
        config: None,
    };

    let error = init(credentials).expect_err("CredSSP refuses a smart card without its configuration");

    assert!(matches!(error.kind(), ConnectorErrorKind::General));
    assert!(error.to_string().contains("smart card configuration missing"));
}

#[cfg(not(feature = "smart-card"))]
#[test]
fn credentials_without_smart_card_are_a_password_alone() {
    // This pattern is irrefutable only when `Credentials::SmartCard` does not exist.
    let Credentials::UsernamePassword { username, password } = password_credentials();

    assert_eq!(username, "user");
    assert_eq!(password, "password");
}
