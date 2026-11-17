//! The HTTP transports against a fake provider on loopback.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use owt_mail::{Delivery, Email, Error, Mail, Resend, Ses};
use owt_runtime::logging::Sensitive;

type Seen = Arc<Mutex<Vec<(HeaderMap, serde_json::Value)>>>;

/// A fake answering `status` with `body` at `path`, recording each request.
async fn fake(path: &'static str, status: StatusCode, body: &'static str) -> (String, Seen) {
    let seen = Seen::default();
    let keep = seen.clone();
    let app = Router::new().route(
        path,
        post(move |headers: HeaderMap, json: String| {
            let keep = keep.clone();
            async move {
                keep.lock()
                    .unwrap()
                    .push((headers, serde_json::from_str(&json).unwrap()));
                (status, body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (origin, seen)
}

fn email() -> Email {
    Email::new(
        "Ana <ana@example.com>",
        "Your link",
        "https://x.example/l/1",
    )
    .with_html("<a href=\"https://x.example/l/1\">Sign in</a>")
}

#[tokio::test]
async fn resend_gets_both_parts_and_the_key() {
    let (origin, seen) = fake("/emails", StatusCode::OK, "{\"id\":\"1\"}").await;
    let resend = Resend::new(
        Sensitive::new("re_key".into()),
        "Site <noreply@example.com>".parse().unwrap(),
        owt_mail::DEFAULT_TIMEOUT,
    )
    .unwrap()
    .with_endpoint(&origin)
    .unwrap();
    assert_eq!(
        Mail::new(resend).send(&email()).await.unwrap(),
        Delivery::Sent
    );
    let seen = seen.lock().unwrap();
    let (headers, json) = &seen[0];
    assert_eq!(headers["authorization"], "Bearer re_key");
    assert_eq!(json["to"][0], "Ana <ana@example.com>");
    assert_eq!(json["from"], "Site <noreply@example.com>");
    assert_eq!(json["text"], "https://x.example/l/1");
    assert!(json["html"].as_str().unwrap().contains("Sign in"));
}

#[tokio::test]
async fn a_refusal_carries_the_providers_words() {
    let (origin, _) = fake(
        "/emails",
        StatusCode::FORBIDDEN,
        r#"{"message":"The example.com domain is not verified."}"#,
    )
    .await;
    let resend = Resend::new(
        Sensitive::new("re_key".into()),
        "a@example.com".parse().unwrap(),
        owt_mail::DEFAULT_TIMEOUT,
    )
    .unwrap()
    .with_endpoint(&origin)
    .unwrap();
    let err = Mail::new(resend).send(&email()).await.unwrap_err();
    assert!(matches!(
        err,
        Error::Rejected {
            provider: "resend",
            ..
        }
    ));
    let text = err.to_string();
    assert!(
        text.contains("403") && text.contains("not verified") && !text.contains("re_key"),
        "{text}"
    );
}

#[tokio::test]
async fn ses_signs_and_sends_both_parts() {
    let (origin, seen) = fake(
        "/v2/email/outbound-emails",
        StatusCode::OK,
        "{\"MessageId\":\"1\"}",
    )
    .await;
    let ses = Ses::new(
        "eu-west-1",
        "noreply@example.com".parse().unwrap(),
        "AKID".into(),
        Sensitive::new("secret".into()),
        Some(Sensitive::new("token".into())),
        owt_mail::DEFAULT_TIMEOUT,
    )
    .unwrap()
    .with_endpoint(&origin)
    .unwrap();
    assert_eq!(Mail::new(ses).send(&email()).await.unwrap(), Delivery::Sent);
    let seen = seen.lock().unwrap();
    let (headers, json) = &seen[0];
    let auth = headers["authorization"].to_str().unwrap();
    assert!(
        auth.starts_with("AWS4-HMAC-SHA256 Credential=AKID/")
            && auth.contains("/eu-west-1/ses/aws4_request"),
        "{auth}"
    );
    assert!(
        auth.contains("SignedHeaders=content-type;host;x-amz-date;x-amz-security-token"),
        "{auth}"
    );
    assert_eq!(headers["x-amz-security-token"], "token");
    assert_eq!(
        json["Destination"]["ToAddresses"][0],
        "Ana <ana@example.com>"
    );
    assert_eq!(
        json["Content"]["Simple"]["Body"]["Text"]["Data"],
        "https://x.example/l/1"
    );
    assert!(
        json["Content"]["Simple"]["Body"]["Html"]["Data"]
            .as_str()
            .unwrap()
            .contains("Sign in")
    );
}

#[tokio::test]
async fn an_unreachable_provider_is_told_apart() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let resend = Resend::new(
        Sensitive::new("k".into()),
        "a@example.com".parse().unwrap(),
        owt_mail::DEFAULT_TIMEOUT,
    )
    .unwrap()
    .with_endpoint(&origin)
    .unwrap();
    assert!(matches!(
        Mail::new(resend).send(&email()).await,
        Err(Error::Unreachable {
            provider: "resend",
            ..
        })
    ));
}
