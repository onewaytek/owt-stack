//! Page components every app renders the same way: alerts, a form's errors, a form
//! field, pagination, an error page's body.
//!
//! Each is an Askama template compiled into this crate, so an app's page embeds one
//! as a value: `{{ alerts }}`, with no file to copy. The markup carries only `owt-*`
//! classes, defined in `tailwind/owt.css` over semantic tokens (`--color-owt-ink`,
//! `--color-owt-accent`, `--color-owt-danger`…) that an app's own `@theme` sets, so
//! the components take the app's look without the app writing their CSS. An app's
//! stylesheet does not scan this crate, which is why the markup names no utility.
//!
//! Text in them is escaped as in any template; a password field never echoes its
//! value.

use askama::Template;
use askama::filters::HtmlSafe;
use axum::http::StatusCode;

use crate::flash::{Flash, Level};
use crate::pager::Pager;
use crate::request::RequestInfo;

/// The page's flash messages, each an alert (errors) or a status (the rest).
///
/// ```html
/// <div class="owt-alert owt-alert-success" role="status">Saved.</div>
/// ```
#[derive(Template)]
#[template(
    source = r#"{% for f in flashes %}<div class="owt-alert owt-alert-{{ f.level().as_str() }}" role="{% if f.level() == Level::Error %}alert{% else %}status{% endif %}">{{ f.text() }}</div>
{% endfor %}"#,
    ext = "html"
)]
pub struct Alerts<'a> {
    /// The messages, in order.
    pub flashes: &'a [Flash],
}
impl HtmlSafe for Alerts<'_> {}

/// A form's errors as one list; nothing when there are none.
#[derive(Template)]
#[template(
    source = r#"{% if !errors.is_empty() %}<ul class="owt-alert owt-alert-error" role="alert">{% for e in errors %}<li>{{ e }}</li>{% endfor %}</ul>
{% endif %}"#,
    ext = "html"
)]
pub struct Errors<'a, S: std::fmt::Display> {
    /// The sentences the person reads.
    pub errors: &'a [S],
}
impl<S: std::fmt::Display> HtmlSafe for Errors<'_, S> {}

/// A labelled input with its error or hint, wired for assistive technology
/// (`aria-invalid`, `aria-describedby`).
#[derive(Template, Clone, Debug)]
#[template(
    source = r#"<div class="owt-field">
<label class="owt-label" for="{{ name }}">{{ label }}</label>
<input class="owt-input{% if error.is_some() %} owt-input-invalid{% endif %}" id="{{ name }}" name="{{ name }}" type="{{ kind }}"{% if kind != "password" && !value.is_empty() %} value="{{ value }}"{% endif %}{% if !autocomplete.is_empty() %} autocomplete="{{ autocomplete }}"{% endif %}{% if required %} required{% endif %}{% if autofocus %} autofocus{% endif %}{% if error.is_some() %} aria-invalid="true" aria-describedby="{{ name }}-error"{% else if !hint.is_empty() %} aria-describedby="{{ name }}-hint"{% endif %}>
{% if let Some(e) = error %}<p class="owt-field-error" id="{{ name }}-error">{{ e }}</p>
{% else if !hint.is_empty() %}<p class="owt-hint" id="{{ name }}-hint">{{ hint }}</p>
{% endif %}</div>
"#,
    ext = "html"
)]
pub struct Field<'a> {
    /// The input's `name` and `id`.
    pub name: &'a str,
    /// The label's text.
    pub label: &'a str,
    /// The input's `type`: `text`, `email`, `password`, `url`, `number`…
    pub kind: &'a str,
    /// What was typed, shown again after a refused submission. Never for a password.
    pub value: &'a str,
    /// Why the value was refused; replaces the hint.
    pub error: Option<&'a str>,
    /// A line under the field.
    pub hint: &'a str,
    /// The `autocomplete` token (`username`, `current-password`, `email`…).
    pub autocomplete: &'a str,
    /// The `required` attribute.
    pub required: bool,
    /// The `autofocus` attribute: the first field of a sign-in form.
    pub autofocus: bool,
}
impl HtmlSafe for Field<'_> {}

impl<'a> Field<'a> {
    /// A field of `kind`.
    #[must_use]
    pub fn new(kind: &'a str, name: &'a str, label: &'a str) -> Self {
        Self {
            name,
            label,
            kind,
            value: "",
            error: None,
            hint: "",
            autocomplete: "",
            required: false,
            autofocus: false,
        }
    }

    /// A text field.
    #[must_use]
    pub fn text(name: &'a str, label: &'a str) -> Self {
        Self::new("text", name, label)
    }

    /// An email field, with `autocomplete="email"`.
    #[must_use]
    pub fn email(name: &'a str, label: &'a str) -> Self {
        Self::new("email", name, label).autocomplete("email")
    }

    /// A password field. Its value is never rendered; `autocomplete` says which
    /// password it is (`current-password`, `new-password`).
    #[must_use]
    pub fn password(name: &'a str, label: &'a str, autocomplete: &'a str) -> Self {
        Self::new("password", name, label).autocomplete(autocomplete)
    }

    /// What was typed.
    #[must_use]
    pub fn value(mut self, value: &'a str) -> Self {
        self.value = value;
        self
    }

    /// Why it was refused, if it was.
    #[must_use]
    pub fn error(mut self, error: Option<&'a str>) -> Self {
        self.error = error;
        self
    }

    /// A line under the field.
    #[must_use]
    pub fn hint(mut self, hint: &'a str) -> Self {
        self.hint = hint;
        self
    }

    /// The `autocomplete` token.
    #[must_use]
    pub fn autocomplete(mut self, token: &'a str) -> Self {
        self.autocomplete = token;
        self
    }

    /// Required.
    #[must_use]
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Focused when the page opens.
    #[must_use]
    pub fn autofocus(mut self) -> Self {
        self.autofocus = true;
        self
    }
}

/// What one thing in a pager's row is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The link to the page before.
    Previous,
    /// A link to a page.
    Page,
    /// The page shown, not a link.
    Current,
    /// Pages skipped between the first or last and those near the current one.
    Gap,
    /// The link to the page after.
    Next,
}

/// One thing in a pager's row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// Where it links; empty for the current page and a gap.
    pub href: String,
    /// Its text: the page number, or empty.
    pub label: String,
    /// What it is.
    pub kind: Kind,
}

/// Page links for a [`Pager`]: previous, first, a gap, the pages near this one, a
/// gap, last, next; the rest of the query string kept. Nothing for one page.
#[derive(Template, Clone, Debug)]
#[template(
    source = r#"{% if pager.is_paginated() %}<nav class="owt-pager" aria-label="Pages">
{% for item in self.items() %}{% match item.kind %}{% when Kind::Previous %}<a href="{{ item.href }}" rel="prev"><span aria-hidden="true">‹</span><span class="owt-sr">Previous page</span></a>
{% when Kind::Next %}<a href="{{ item.href }}" rel="next"><span class="owt-sr">Next page</span><span aria-hidden="true">›</span></a>
{% when Kind::Current %}<span class="owt-pager-current" aria-current="page">{{ item.label }}</span>
{% when Kind::Gap %}<span class="owt-pager-gap" aria-hidden="true">…</span>
{% when Kind::Page %}<a href="{{ item.href }}">{{ item.label }}</a>
{% endmatch %}{% endfor %}</nav>
{% endif %}"#,
    ext = "html"
)]
pub struct Pagination<'a> {
    /// The page shown.
    pub pager: Pager,
    /// The request, whose query the links keep.
    pub request: &'a RequestInfo,
    /// The query parameter that names the page; `page` for most lists.
    pub param: &'a str,
}
impl HtmlSafe for Pagination<'_> {}

impl<'a> Pagination<'a> {
    /// Links for `pager` on `request`, with `?page=`.
    #[must_use]
    pub fn new(pager: Pager, request: &'a RequestInfo) -> Self {
        Self {
            pager,
            request,
            param: "page",
        }
    }

    /// The link to page `n`.
    #[must_use]
    pub fn href(&self, n: usize) -> String {
        self.request.query_with(self.param, Some(&n.to_string()))
    }

    /// The row, in order: what the template prints. Empty for one page.
    #[must_use]
    pub fn items(&self) -> Vec<Item> {
        let p = self.pager;
        if !p.is_paginated() {
            return Vec::new();
        }
        let page = |n: usize, kind: Kind| Item {
            href: if kind == Kind::Current {
                String::new()
            } else {
                self.href(n)
            },
            label: n.to_string(),
            kind,
        };
        let gap = Item {
            href: String::new(),
            label: String::new(),
            kind: Kind::Gap,
        };
        let mut items = Vec::new();
        if p.has_previous() {
            items.push(Item {
                label: String::new(),
                ..page(p.previous(), Kind::Previous)
            });
        }
        if p.number > 2 {
            items.push(page(1, Kind::Page));
        }
        if p.number > 3 {
            items.push(gap.clone());
        }
        for n in p.numbers() {
            if n == p.number {
                items.push(page(n, Kind::Current));
            } else if p.is_near(n) {
                items.push(page(n, Kind::Page));
            }
        }
        if p.pages > p.number + 2 {
            items.push(gap);
        }
        if p.pages > p.number + 1 {
            items.push(page(p.pages, Kind::Page));
        }
        if p.has_next() {
            items.push(Item {
                label: String::new(),
                ..page(p.next(), Kind::Next)
            });
        }
        items
    }
}

/// The body of an error page, for the app's shell to wrap: the status, a heading, a
/// sentence, and a way back.
#[derive(Template, Clone, Debug)]
#[template(
    source = r#"<section class="owt-errorpage">
<p class="owt-errorpage-code">{{ status }}</p>
<h1>{{ title }}</h1>
<p>{{ detail }}</p>
{% if !home.is_empty() %}<p><a href="{{ home }}">{{ home_label }}</a></p>
{% endif %}</section>
"#,
    ext = "html"
)]
pub struct ErrorBody<'a> {
    /// The HTTP status.
    pub status: u16,
    /// The heading.
    pub title: &'a str,
    /// One sentence for the person.
    pub detail: &'a str,
    /// Where the link goes; empty for no link.
    pub home: &'a str,
    /// The link's text.
    pub home_label: &'a str,
}
impl HtmlSafe for ErrorBody<'_> {}

impl ErrorBody<'static> {
    /// The usual words for `status`, with a link to `/`.
    #[must_use]
    pub fn for_status(status: StatusCode) -> Self {
        let (title, detail) = match status {
            StatusCode::NOT_FOUND => (
                "Page not found",
                "There is nothing at this address. It may have moved, or the link may be wrong.",
            ),
            StatusCode::FORBIDDEN => ("Not allowed", "Your account cannot open this page."),
            StatusCode::UNAUTHORIZED => ("Sign in first", "This page needs you to be signed in."),
            StatusCode::TOO_MANY_REQUESTS => {
                ("Too many requests", "Please wait a moment and try again.")
            }
            StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => (
                "That took too long",
                "The page did not finish in time. Please try again.",
            ),
            s if s.is_client_error() => (
                "That request could not be handled",
                "Something in the request was not right.",
            ),
            _ => (
                "Something went wrong",
                "The problem is on our side. Please try again in a moment.",
            ),
        };
        Self {
            status: status.as_u16(),
            title,
            detail,
            home: "/",
            home_label: "Back to the start",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alerts_render_each_message_escaped_with_a_role_by_level() {
        let flashes = [
            Flash(Level::Success, "Saved.".into()),
            Flash(Level::Error, "<b>No</b>".into()),
        ];
        let html = Alerts { flashes: &flashes }.render().unwrap();
        assert_eq!(
            html,
            "<div class=\"owt-alert owt-alert-success\" role=\"status\">Saved.</div>\n\
             <div class=\"owt-alert owt-alert-error\" role=\"alert\">&#60;b&#62;No&#60;/b&#62;</div>\n"
        );
        assert_eq!(Alerts { flashes: &[] }.render().unwrap(), "");
    }

    #[test]
    fn errors_are_one_list_or_nothing() {
        let none: [String; 0] = [];
        assert_eq!(Errors { errors: &none }.render().unwrap(), "");
        let html = Errors {
            errors: &["Too short.", "Too <similar>."],
        }
        .render()
        .unwrap();
        assert_eq!(
            html,
            "<ul class=\"owt-alert owt-alert-error\" role=\"alert\"><li>Too short.</li><li>Too &#60;similar&#62;.</li></ul>\n"
        );
    }

    #[test]
    fn a_field_carries_its_value_error_and_aria_wiring() {
        let html = Field::text("username", "Username")
            .value("a\"b")
            .required()
            .autofocus()
            .autocomplete("username")
            .hint("Letters and digits.")
            .render()
            .unwrap();
        assert!(html.contains(r#"<input class="owt-input" id="username" name="username" type="text" value="a&#34;b" autocomplete="username" required autofocus aria-describedby="username-hint">"#), "{html}");
        assert!(html.contains(r#"<p class="owt-hint" id="username-hint">Letters and digits.</p>"#));

        let html = Field::email("email", "Email")
            .value("x")
            .hint("hidden by the error")
            .error(Some("Enter a valid email address."))
            .render()
            .unwrap();
        assert!(
            html.contains(r#"class="owt-input owt-input-invalid""#),
            "{html}"
        );
        assert!(html.contains(r#"aria-invalid="true" aria-describedby="email-error""#));
        assert!(html.contains(
            r#"<p class="owt-field-error" id="email-error">Enter a valid email address.</p>"#
        ));
        assert!(!html.contains("hidden by the error"));
    }

    #[test]
    fn a_password_field_never_echoes_its_value() {
        let html = Field::password("password", "Password", "current-password")
            .value("hunter2")
            .render()
            .unwrap();
        assert!(!html.contains("hunter2"), "{html}");
        assert!(
            html.contains(r#"type="password""#)
                && html.contains(r#"autocomplete="current-password""#)
        );
    }

    fn links(html: &str) -> Vec<(String, String)> {
        // (href, text) of each anchor, text with the sr-only span stripped.
        html.split("<a href=\"")
            .skip(1)
            .map(|rest| {
                let (href, after) = rest.split_once('"').unwrap();
                let text = after
                    .split_once('>')
                    .unwrap()
                    .1
                    .split("</a>")
                    .next()
                    .unwrap();
                let text: String = text
                    .split('<')
                    .map(|part| part.split_once('>').map_or(part, |(_, t)| t))
                    .collect();
                (href.to_owned(), text)
            })
            .collect()
    }

    #[test]
    fn pagination_is_compact_and_keeps_the_rest_of_the_query() {
        let request = RequestInfo::at("/items?q=cats&page=5");
        let html = Pagination::new(
            Pager {
                number: 5,
                pages: 10,
            },
            &request,
        )
        .render()
        .unwrap();
        let got = links(&html);
        let hrefs: Vec<&str> = got.iter().map(|(h, _)| h.as_str()).collect();
        assert_eq!(
            hrefs,
            [
                "?q=cats&#38;page=4",
                "?q=cats&#38;page=1",
                "?q=cats&#38;page=4",
                "?q=cats&#38;page=6",
                "?q=cats&#38;page=10",
                "?q=cats&#38;page=6",
            ],
            "{html}"
        );
        let texts: Vec<&str> = got.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(texts, ["‹Previous page", "1", "4", "6", "10", "Next page›"]);
        assert!(html.contains(r#"<span class="owt-pager-current" aria-current="page">5</span>"#));
        assert_eq!(html.matches("owt-pager-gap").count(), 2);
    }

    #[test]
    fn pagination_at_the_edges_and_for_one_page() {
        let request = RequestInfo::at("/items");
        let html = Pagination::new(
            Pager {
                number: 1,
                pages: 3,
            },
            &request,
        )
        .render()
        .unwrap();
        let texts: Vec<String> = links(&html).into_iter().map(|(_, t)| t).collect();
        assert_eq!(texts, ["2", "3", "Next page›"], "{html}");
        assert!(!html.contains("owt-pager-gap"));
        let html = Pagination::new(
            Pager {
                number: 3,
                pages: 3,
            },
            &request,
        )
        .render()
        .unwrap();
        let texts: Vec<String> = links(&html).into_iter().map(|(_, t)| t).collect();
        assert_eq!(texts, ["‹Previous page", "1", "2"], "{html}");
        assert_eq!(
            Pagination::new(
                Pager {
                    number: 1,
                    pages: 1
                },
                &request
            )
            .render()
            .unwrap(),
            ""
        );
    }

    #[test]
    fn an_error_body_has_the_usual_words() {
        let html = ErrorBody::for_status(StatusCode::NOT_FOUND)
            .render()
            .unwrap();
        assert!(
            html.contains("<p class=\"owt-errorpage-code\">404</p>"),
            "{html}"
        );
        assert!(html.contains("<h1>Page not found</h1>"));
        assert!(html.contains("<a href=\"/\">Back to the start</a>"));
        let html = ErrorBody {
            home: "",
            ..ErrorBody::for_status(StatusCode::INTERNAL_SERVER_ERROR)
        }
        .render()
        .unwrap();
        assert!(
            html.contains("Something went wrong") && !html.contains("<a "),
            "{html}"
        );
        assert!(
            ErrorBody::for_status(StatusCode::IM_A_TEAPOT)
                .render()
                .unwrap()
                .contains("could not be handled")
        );
    }

    #[test]
    fn a_component_embeds_in_a_page_unescaped() {
        #[derive(Template)]
        #[template(source = "<main>{{ alerts }}</main>", ext = "html")]
        struct Page<'a> {
            alerts: Alerts<'a>,
        }
        let flashes = [Flash(Level::Info, "Hi".into())];
        let html = Page {
            alerts: Alerts { flashes: &flashes },
        }
        .render()
        .unwrap();
        assert_eq!(
            html,
            "<main><div class=\"owt-alert owt-alert-info\" role=\"status\">Hi</div>\n</main>"
        );
    }
}
