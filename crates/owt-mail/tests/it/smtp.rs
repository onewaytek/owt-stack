//! `MAIL_URL` → the TLS mode `Smtp` uses: credentials never travel in plaintext.

use owt_mail::{DEFAULT_TIMEOUT, Smtp, SmtpTls};
use owt_runtime::logging::Sensitive;

fn smtp(url: &str) -> anyhow::Result<Smtp> {
    Smtp::from_url(
        &Sensitive::new(url.into()),
        "a@b.c".parse().unwrap(),
        DEFAULT_TIMEOUT,
    )
}

fn tls(url: &str) -> SmtpTls {
    smtp(url).unwrap().tls()
}

fn refusal(url: &str) -> String {
    let err = format!("{:#}", smtp(url).unwrap_err());
    assert!(!err.contains("hunter2"), "{err}");
    err
}

#[test]
fn plain_smtp_is_starttls_required() {
    assert_eq!(
        tls("smtp://u:hunter2@smtp.example.com:587"),
        SmtpTls::StartTls
    );
    assert_eq!(tls("smtp://smtp.example.com"), SmtpTls::StartTls);
    assert_eq!(
        tls("smtp://u:hunter2@smtp.example.com:587?tls=required"),
        SmtpTls::StartTls
    );
}

#[test]
fn smtps_is_implicit_tls() {
    assert_eq!(
        tls("smtps://u:hunter2@smtp.example.com:465"),
        SmtpTls::Implicit
    );
    assert_eq!(tls("smtps://u:hunter2@smtp.example.com"), SmtpTls::Implicit);
}

#[test]
fn plaintext_is_an_explicit_opt_out_for_a_local_catcher() {
    assert_eq!(tls("smtp://mailpit:1025?tls=none"), SmtpTls::None);
    assert_eq!(
        tls("smtp://u:hunter2@localhost:1025?tls=none"),
        SmtpTls::None
    );
    assert_eq!(
        tls("smtp://u:hunter2@127.0.0.1:1025?tls=none"),
        SmtpTls::None
    );
    assert_eq!(tls("smtp://u:hunter2@[::1]:1025?tls=none"), SmtpTls::None);
    assert!(refusal("smtp://u:hunter2@smtp.example.com:25?tls=none").contains("not loopback"));
    assert!(refusal("smtp://u@mailpit:25?tls=none").contains("not loopback"));
}

#[test]
fn downgradable_and_unknown_modes_are_refused() {
    assert!(
        refusal("smtp://u:hunter2@smtp.example.com:587?tls=opportunistic")
            .contains("opportunistic")
    );
    assert!(refusal("smtp://u:hunter2@smtp.example.com?tls=off").contains("tls parameter"));
    assert!(refusal("smtps://u:hunter2@smtp.example.com?tls=none").contains("tls parameter"));
    assert!(refusal("ftp://u:hunter2@h").contains("not an smtp://"));
}

#[test]
fn debug_shows_the_mode_not_the_password() {
    let shown = format!(
        "{:?}",
        smtp("smtp://u:hunter2@smtp.example.com:587").unwrap()
    );
    assert!(
        shown.contains("StartTls") && !shown.contains("hunter2"),
        "{shown}"
    );
}
