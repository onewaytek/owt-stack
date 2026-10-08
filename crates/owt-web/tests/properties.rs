//! Properties of the pieces that read what a client sent.
//!
//! Each states what must hold for *every* input, and lets proptest look for the one
//! where it does not. The inputs lean hostile: slashes, backslashes, control
//! characters, percent-escapes and Unicode, in the proportions an attacker would use
//! rather than the ones a uniform string would have.

use std::net::IpAddr;
use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::response::IntoResponse;
use owt_web::client_ip::Source;
use owt_web::csrf::CrossOrigin;
use owt_web::flash::{self, Flash, HasFlashes, Level};
use owt_web::request::RequestInfo;
use owt_web::session::{Session, Sessions};
use owt_web::{pager::Pager, redirect, sse, text};
use proptest::prelude::*;
use serde::{Deserialize, Serialize};

/// Text built from the fragments URL and header tricks are made of.
fn hostile() -> impl Strategy<Value = String> {
    let piece = prop_oneof![
        8 => prop::sample::select(vec![
            "/", "//", "\\", "/\\", "\\/", "@", ":", "?", "#", "%2f", "%5c", "%09", "%0a",
            "\t", "\n", "\r", "\r\n", " ", ".", "..", ";", ",", "=", "&", "\"", "'", "<", ">",
            "evil.example", "app.example", "https:", "http:", "javascript:", "data:",
            "\u{0}", "\u{7f}", "\u{a0}", "\u{2028}", "\u{feff}", "é", "漢", "😀", "a", "1",
        ])
        .prop_map(str::to_owned),
        2 => any::<char>().prop_map(String::from),
        1 => "[a-z0-9/._-]{0,8}",
    ];
    prop::collection::vec(piece, 0..12).prop_map(|v| v.concat())
}

/// What a browser's URL parser does to a string before parsing it: tabs and newlines
/// are removed, and C0 controls and spaces trimmed from the ends.
fn as_a_browser_reads(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect::<String>()
        .trim_matches(|c: char| c <= ' ')
        .to_owned()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// Whatever `redirect::local` lets through stays on this site when a browser
    /// follows it, and can be sent as a `Location` at all.
    #[test]
    fn an_accepted_redirect_stays_on_this_site(next in hostile()) {
        let Some(path) = redirect::local(&next) else { return Ok(()) };
        prop_assert!(HeaderValue::from_str(path).is_ok(), "not a header value: {path:?}");
        let base = url::Url::parse("https://app.example/accounts/login/?next=x").unwrap();
        let landed = base.join(&as_a_browser_reads(path));
        let landed = landed.map_err(|e| TestCaseError::fail(format!("{path:?}: {e}")))?;
        prop_assert_eq!(landed.origin(), base.origin(), "{:?} leads to {}", path, landed);
        // And the error type's redirect carries it without panicking.
        let response = owt_web::Error::Redirect(path.to_owned()).into_response();
        prop_assert_eq!(response.headers()[header::LOCATION].as_bytes(), path.as_bytes());
    }

    /// `local_or` only ever answers with an accepted path or the fallback.
    #[test]
    fn the_fallback_is_the_only_other_answer(next in prop::option::of(hostile())) {
        let to = redirect::local_or(next.as_deref(), "/home");
        prop_assert!(to == "/home" || redirect::local(to) == Some(to));
    }

    /// The client cannot move its own address by what it writes to the left of the
    /// entries the trusted proxies append.
    #[test]
    fn forged_forwarded_entries_change_nothing(
        forged in hostile(),
        appended in prop::collection::vec(any::<IpAddr>(), 1..4),
        split in any::<bool>(),
    ) {
        let peer: IpAddr = "10.128.0.2".parse().unwrap();
        let tail = appended.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
        let mut headers = HeaderMap::new();
        let Ok(forged_value) = HeaderValue::from_str(&forged) else { return Ok(()) };
        if split {
            headers.append("x-forwarded-for", forged_value);
            headers.append("x-forwarded-for", HeaderValue::from_str(&tail).unwrap());
        } else {
            let joined = format!("{forged}, {tail}");
            headers.append("x-forwarded-for", HeaderValue::from_str(&joined).unwrap());
        }
        let source = Source::ForwardedFor { proxies: appended.len() };
        prop_assert_eq!(source.client_ip(&headers, peer), appended[0]);
    }

    /// Any header at all yields an address: the one named, or the peer.
    #[test]
    fn a_client_address_is_always_found(
        value in prop::collection::vec(any::<u8>(), 0..64),
        proxies in 0usize..5,
    ) {
        let peer: IpAddr = "10.128.0.2".parse().unwrap();
        let Ok(value) = HeaderValue::from_bytes(&value) else { return Ok(()) };
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", value.clone());
        headers.insert("cf-connecting-ip", value.clone());
        let named = Source::Header("cf-connecting-ip".into()).client_ip(&headers, peer);
        let parsed = value.to_str().ok().and_then(|v| v.trim().parse::<IpAddr>().ok());
        prop_assert_eq!(named, parsed.unwrap_or(peer));
        let _ = Source::ForwardedFor { proxies }.client_ip(&headers, peer);
        prop_assert_eq!(Source::Peer.client_ip(&headers, peer), peer);
    }

    /// A frame is one event whose data is the text, whatever line endings the text
    /// holds: nothing in it can start a field of its own.
    #[test]
    fn a_frame_is_one_event_carrying_the_text(data in hostile(), more in hostile()) {
        let expected = |s: &str| {
            s.replace("\r\n", "\n").replace('\r', "\n").lines().collect::<Vec<_>>().join("\n")
        };
        let events = parse_event_stream(&sse::frame(&data));
        prop_assert_eq!(&events, &vec![Event { data: expected(&data), other: vec![] }]);
        // Frames laid end to end stay apart.
        let both = parse_event_stream(&format!("{}{}", sse::frame(&data), sse::frame(&more)));
        prop_assert_eq!(both.len(), 2);
        prop_assert_eq!(&both[1].data, &expected(&more));
        prop_assert!(both.iter().all(|e| e.other.is_empty()));
    }

    /// No request the browser labels as from elsewhere changes state, whatever else
    /// it carries.
    #[test]
    fn a_request_from_elsewhere_changes_nothing(
        site in prop_oneof![Just("cross-site".to_owned()), Just("same-site".to_owned()), "[a-z-]{0,12}"],
        origin in prop::option::of(hostile()),
        host in prop::option::of(hostile()),
        method in prop::sample::select(vec![Method::POST, Method::PUT, Method::PATCH, Method::DELETE]),
        path in hostile(),
    ) {
        prop_assume!(site != "same-origin" && site != "none");
        let mut headers = HeaderMap::new();
        headers.insert("sec-fetch-site", HeaderValue::from_str(&site).unwrap());
        for (name, value) in [(header::ORIGIN, origin), (header::HOST, host)] {
            if let Some(v) = value.and_then(|v| HeaderValue::from_str(&v).ok()) {
                headers.insert(name, v);
            }
        }
        let guard = CrossOrigin::new().trust(["https://partner.example"]);
        prop_assert!(guard.check(&method, &path, &headers).is_err());
    }

    /// Without fetch metadata, an `Origin` passes only if it names the host addressed.
    #[test]
    fn an_origin_passes_only_as_the_host_addressed(origin in hostile()) {
        let Ok(value) = HeaderValue::from_str(&origin) else { return Ok(()) };
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, value);
        headers.insert(header::HOST, HeaderValue::from_static("app.example"));
        if CrossOrigin::new().check(&Method::POST, "/", &headers).is_ok() {
            let url = url::Url::parse(&origin)
                .map_err(|e| TestCaseError::fail(format!("{origin:?} passed: {e}")))?;
            prop_assert_eq!(url.host_str(), Some("app.example"), "{:?} passed", origin);
            prop_assert!(url.port().is_none());
        }
    }

    /// Bytes no browser sends, in either header the decision reads, are a refusal:
    /// they must not read as "no header", which is what lets other clients through.
    #[test]
    fn unreadable_origin_headers_are_refused(
        bytes in prop::collection::vec(prop_oneof![0x80u8..=0xff, 0x20u8..0x7f], 1..24),
        name in prop::sample::select(vec!["origin", "sec-fetch-site"]),
    ) {
        prop_assume!(bytes.iter().any(|b| *b >= 0x80));
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_bytes(&bytes).unwrap());
        headers.insert(header::HOST, HeaderValue::from_static("app.example"));
        prop_assert!(CrossOrigin::new().check(&Method::POST, "/", &headers).is_err());
    }

    /// A bypass prefix exempts itself and what is below it, and nothing beside it.
    #[test]
    fn a_bypass_covers_whole_segments_only(
        prefix in "(/[a-z]{1,4}){1,2}/?",
        path in "(/[a-z-]{0,5}){0,4}/?",
    ) {
        let mut headers = HeaderMap::new();
        headers.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        let guard = CrossOrigin::new().bypass([prefix.clone()]);
        let bare = prefix.trim_end_matches('/');
        let under = path == bare || path.starts_with(&format!("{bare}/"));
        prop_assert_eq!(guard.check(&Method::POST, &path, &headers).is_ok(), under);
    }

    /// A `WebSocket` upgrade from another origin is refused though it is a `GET`.
    #[test]
    fn an_upgrade_from_elsewhere_is_refused(
        upgrade in "[wW][eE][bB][sS][oO][cC][kK][eE][tT]",
        host in "[a-z]{1,8}\\.example",
    ) {
        prop_assume!(host != "app.example");
        let mut headers = HeaderMap::new();
        headers.insert(header::UPGRADE, HeaderValue::from_str(&upgrade).unwrap());
        headers.insert(header::HOST, HeaderValue::from_static("app.example"));
        headers.insert(header::ORIGIN, HeaderValue::from_str(&format!("https://{host}")).unwrap());
        prop_assert!(CrossOrigin::new().check(&Method::GET, "/ws", &headers).is_err());
    }

    /// The request a page is told about never names another host, and its query
    /// helpers round-trip.
    #[test]
    fn request_info_stays_a_path(uri in hostile(), key in "[a-z]{1,4}", value in hostile()) {
        let info = RequestInfo::at(&uri);
        prop_assert!(!info.full_path.starts_with("//"), "{:?}", info.full_path);
        prop_assert!(!info.path.starts_with("//"));
        prop_assert!(!info.path.contains('?'));
        let with = info.query_with(&key, Some(&value));
        prop_assert!(with.starts_with('?'));
        let again = RequestInfo::at(&format!("/x{with}"));
        prop_assert_eq!(again.query_value(&key), Some(value.as_str()));
        let others = |i: &RequestInfo| {
            i.query.iter().filter(|(k, _)| *k != key).cloned().collect::<Vec<_>>()
        };
        prop_assert_eq!(others(&again), others(&info));
        let without_query = info.query_with(&key, None);
        prop_assert!(without_query.starts_with('?'));
        let without = RequestInfo::at(&format!("/x{without_query}"));
        prop_assert_eq!(without.query_value(&key), None);
        // A link is the path and that query, and reads back as the same request.
        for value in [Some(value.as_str()), None] {
            let link = info.url_with(&key, value);
            prop_assert!(!link.starts_with("//"), "{link:?}");
            prop_assert!(link.starts_with(&info.path), "{link:?}");
            prop_assert!(!link.ends_with('?') || info.path.is_empty(), "{link:?}");
            let linked = RequestInfo::at(&link);
            prop_assert_eq!(&linked.path, &info.path);
            prop_assert_eq!(linked.query_value(&key), value);
            prop_assert_eq!(others(&linked), others(&info));
        }
        // Re-pathed to a page, only the path changes.
        let page = info.for_page("/p");
        prop_assert_eq!(page.path.as_str(), "/p");
        prop_assert_eq!(&page.query, &info.query);
    }

    /// Text made into paragraphs holds no markup but the paragraphs' own.
    #[test]
    fn linebreaks_emit_only_their_own_tags(input in hostile()) {
        let html = text::linebreaks(&input);
        let stripped = html.replace("<p>", "").replace("</p>", "").replace("<br>", "");
        prop_assert!(!stripped.contains('<') && !stripped.contains('>'), "{html:?}");
    }

    #[test]
    fn slugs_are_slugs(input in hostile()) {
        let slug = text::slugify(&input);
        prop_assert!(slug.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'));
        prop_assert!(!slug.starts_with('-') && !slug.ends_with('-') && !slug.contains("--"));
    }

    #[test]
    fn truncation_keeps_at_most_n_words(input in hostile(), n in 0usize..6) {
        let cut = text::truncate_words(&input, n);
        let words = cut.split_whitespace().filter(|w| *w != "…").count();
        prop_assert!(words <= n.max(input.split_whitespace().count().min(n)));
    }

    /// Any page number, of any list, is a page that exists.
    #[test]
    fn a_pager_lands_on_a_real_page(
        requested in prop::option::of(prop_oneof![hostile(), any::<u64>().prop_map(|n| n.to_string())]),
        items in prop_oneof![0usize..100, any::<usize>()],
        per_page in prop_oneof![0usize..20, any::<usize>()],
    ) {
        let pager = Pager::clamped(requested.as_deref(), items, per_page);
        prop_assert!(pager.pages >= 1 && (1..=pager.pages).contains(&pager.number));
        let offset = pager.offset(per_page.max(1));
        prop_assert!(offset == 0 || offset < items);
        prop_assert_eq!(pager.has_previous(), pager.number > 1);
        prop_assert_eq!(pager.has_next(), pager.number < pager.pages);
    }

    /// A history URL, pushed or replaced, either becomes its header or is refused; it
    /// never panics, what it sends is plain ASCII, and both ways send the same bytes.
    #[test]
    fn a_fragments_page_url_is_a_header_or_an_error(url in hostile()) {
        use owt_web::fragment::Fragment;
        let page = RequestInfo::at(&url);
        let new = || Fragment::new("", HeaderValue::from_static("no-store"));
        let pushed = new().page(&page).map(IntoResponse::into_response);
        let replaced = new().replace(&page).map(IntoResponse::into_response);
        prop_assert_eq!(pushed.is_ok(), replaced.is_ok());
        if let (Ok(pushed), Ok(replaced)) = (pushed, replaced) {
            let sent = pushed.headers()["hx-push-url"].as_bytes();
            prop_assert!(sent.iter().all(|b| (0x20..0x7f).contains(b) || *b == b'\t'));
            prop_assert_eq!(sent, replaced.headers()["hx-replace-url"].as_bytes());
            prop_assert!(replaced.headers().get("hx-push-url").is_none());
        }
    }
}

// ---------------------------------------------------------------- sessions and flashes

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct Data {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<i64>,
    #[serde(default)]
    epoch: i32,
    #[serde(default)]
    note: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    messages: Vec<Flash>,
}

impl HasFlashes for Data {
    fn flashes(&self) -> &[Flash] {
        &self.messages
    }
    fn flashes_mut(&mut self) -> &mut Vec<Flash> {
        &mut self.messages
    }
}

fn sessions() -> Sessions<Data> {
    Sessions::new(
        cookie::Key::generate(),
        "__Host-session",
        Duration::from_secs(3600),
        true,
    )
}

fn data() -> impl Strategy<Value = Data> {
    (any::<Option<i64>>(), any::<i32>(), hostile()).prop_map(|(user, epoch, note)| Data {
        user,
        epoch,
        note,
        messages: vec![],
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(600))]

    /// What is sealed opens as itself, and only under its own key.
    #[test]
    fn a_sealed_session_opens_as_itself(id in "[a-z0-9]{1,40}", data in data()) {
        let s = sessions();
        let sealed = s.seal(&id, &data);
        prop_assert_eq!(s.unseal(&sealed), Some((id.clone(), data.clone())));
        prop_assert_eq!(sessions().unseal(&sealed), None);
    }

    /// Changing any one character of a sealed session leaves no session: there is no
    /// position an attacker can edit and still be believed.
    #[test]
    fn any_edit_to_a_sealed_session_voids_it(
        data in data(),
        at in any::<prop::sample::Index>(),
        to in "[A-Za-z0-9+/=]",
    ) {
        let s = sessions();
        let sealed = s.seal("abc", &data);
        let at = at.index(sealed.len());
        let to = to.chars().next().unwrap();
        prop_assume!(sealed.as_bytes()[at] != to as u8);
        let mut forged = sealed.clone().into_bytes();
        forged[at] = to as u8;
        let forged = String::from_utf8(forged).unwrap();
        prop_assert_eq!(s.unseal(&forged), None, "edited at {}", at);
        // Nor does cutting it short, or adding to it.
        prop_assert_eq!(s.unseal(&sealed[..at]), None);
        prop_assert_eq!(s.unseal(&format!("{sealed}{to}")), None);
    }

    /// Nothing a client sends as the cookie opens, or panics.
    #[test]
    fn a_made_up_cookie_is_no_session(value in prop_oneof![hostile(), "[A-Za-z0-9+/=]{0,200}"]) {
        prop_assert_eq!(sessions().unseal(&value), None);
    }

    /// However many messages are flashed, of whatever text, each stays within the
    /// bounds, is the text or a cut of it, and the session still fits a cookie.
    #[test]
    fn flashed_messages_always_fit_the_cookie(texts in prop::collection::vec(
        prop_oneof![hostile(), hostile().prop_map(|s| s.repeat(40)), "[漢\"\\\\\u{1}😀]{0,700}"],
        0..12,
    )) {
        let session = Session::<Data>::default();
        for text in &texts {
            session.flash(Level::Info, text.clone());
        }
        let pending = session.read(|d| d.messages.clone());
        prop_assert!(pending.len() <= flash::MAX_PENDING);
        prop_assert_eq!(pending.len(), texts.len().min(flash::MAX_PENDING));
        let kept = &texts[texts.len() - pending.len()..];
        for (message, original) in pending.iter().zip(kept) {
            let text = message.text();
            prop_assert!(text.chars().count() <= flash::MAX_CHARS);
            let json = serde_json::to_string(text).unwrap();
            prop_assert!(json.len() - 2 <= flash::MAX_BYTES, "{} bytes", json.len() - 2);
            let whole = text == original;
            let cut = text.strip_suffix('…').is_some_and(|head| original.starts_with(head));
            prop_assert!(whole || cut, "{text:?} is not a cut of {original:?}");
        }
        let sealed = sessions().seal("abcdefghijklmnopqrstuvwxyz012345", &session.read(Clone::clone));
        prop_assert!(sealed.len() < 3200, "{} bytes sealed", sealed.len());
    }
}

// ------------------------------------------------------------------- the event stream

#[derive(Debug, PartialEq)]
struct Event {
    data: String,
    /// Fields other than `data`: a frame must never produce one.
    other: Vec<(String, String)>,
}

/// The event stream parser of the HTML standard, §9.2.6, as far as it concerns one
/// stream: lines end at CRLF, LF or CR; a blank line dispatches.
fn parse_event_stream(stream: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let (mut data, mut other, mut seen) = (Vec::<String>::new(), Vec::new(), false);
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut chars = stream.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                lines.push(std::mem::take(&mut line));
            }
            '\n' => lines.push(std::mem::take(&mut line)),
            c => line.push(c),
        }
    }
    for line in lines {
        if line.is_empty() {
            if seen {
                events.push(Event {
                    data: data.join("\n"),
                    other: std::mem::take(&mut other),
                });
            }
            data.clear();
            seen = false;
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        let (field, value) = line.split_once(':').unwrap_or((&line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        seen = true;
        if field == "data" {
            data.push(value.to_owned());
        } else {
            other.push((field.to_owned(), value.to_owned()));
        }
    }
    events
}
