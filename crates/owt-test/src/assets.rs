//! The browser fetches nothing from a third-party origin.
//!
//! Whatever another origin serves into a page runs with that page's authority (its
//! cookies, its buttons), and a page that needs public internet from the browser
//! fails on a network that doesn't have it. So every asset is served from the app's
//! own origin, and each one got there by a route that can be checked:
//!
//! * **from a CDN, hash-pinned:** `vendor.pins` lists `path url sha384-…`, the
//!   template script `vendor-js` is the only thing that downloads, and it refuses
//!   any mismatch. [`assert_vendored_files_match_pins`] re-derives each pin from
//!   disk, so an edited file is caught even though the script never ran;
//! * **built from npm:** the lockfile is the integrity record. An app that commits
//!   the built files should rebuild and diff them in its gate;
//!   nothing here does it for you.
//!
//! [`assert_no_remote_assets`] is the invariant itself: it fails on the next
//! `<script src="https://…">` anyone adds. [`assert_no_dangling_source_maps`] catches
//! a shipped script or stylesheet pointing at a source map that isn't shipped, which
//! breaks asset pipelines that resolve every reference.
//!
//! Each takes paths relative to the crate under test (`CARGO_MANIFEST_DIR`, the
//! working directory of its tests), and fails, rather than passing, when the path
//! holds nothing to check: a mistyped directory is not a clean bill of health.

use std::path::{Path, PathBuf};

use base64::Engine;
use regex::Regex;
use sha2::{Digest, Sha384};

/// Every file under `dir` with one of `exts`, sorted. Symbolic links are not
/// followed (a link back up the tree would repeat or never end).
///
/// # Panics
/// If `dir` can't be read.
fn files(dir: &Path, exts: &[&str]) -> Vec<PathBuf> {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    let mut out = Vec::new();
    for e in entries.flatten() {
        let Ok(kind) = e.file_type() else { continue };
        let p = e.path();
        if kind.is_dir() {
            out.extend(files(&p, exts));
        } else if kind.is_file()
            && p.extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| exts.iter().any(|e| x.eq_ignore_ascii_case(e)))
        {
            out.push(p);
        }
    }
    out.sort();
    out
}

/// A file's text, invalid UTF-8 replaced rather than the file skipped.
fn text(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    String::from_utf8_lossy(&bytes).into_owned()
}

/// `s` with comments and template tags blanked out, newlines kept so offsets still
/// map to lines: a URL in a comment loads nothing, and an Askama/Jinja tag's `>`
/// would otherwise end an HTML tag early.
fn blank_non_markup(s: &str) -> String {
    let spans =
        Regex::new(r"(?s)<!--.*?-->|\{#.*?#\}|\{%.*?%\}|\{\{.*?\}\}").expect("a valid regex");
    spans
        .replace_all(s, |c: &regex::Captures| {
            c[0].chars()
                .map(|ch| if ch == '\n' { '\n' } else { ' ' })
                .collect::<String>()
        })
        .into_owned()
}

/// `<link rel>` values that point somewhere rather than load something.
const LINK_ONLY: &[&str] = &[
    "canonical",
    "alternate",
    "me",
    "author",
    "license",
    "help",
    "next",
    "prev",
    "search",
    "bookmark",
];

/// Where `templates` (HTML and CSS) loads something from another origin, except
/// from an origin in `allowed` (`https://challenges.cloudflare.com/`): `file:line:
/// excerpt` for each. Loads are `src`/`srcset`/`poster`/`data`/`href` on elements that
/// fetch (scripts, styles, images, media, frames, objects), `url(…)` and `@import`.
/// Links people follow, and `<link rel>` values that only point (canonical,
/// alternate, …), are not loads.
///
/// # Panics
/// If `templates` can't be read or holds no HTML or CSS.
#[must_use]
pub fn remote_assets(templates: &Path, allowed: &[&str]) -> Vec<String> {
    let found = files(templates, &["html", "htm", "css"]);
    assert!(
        !found.is_empty(),
        "{} holds no HTML or CSS: is the path right?",
        templates.display()
    );
    let tag = Regex::new(
        r"(?is)<(script|link|img|iframe|frame|source|video|audio|embed|object|track|input)\b[^>]*>",
    )
    .expect("a valid regex");
    let attr = Regex::new(
        r#"(?is)\b(src|srcset|poster|data|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#,
    )
    .expect("a valid regex");
    let rel =
        Regex::new(r#"(?is)\brel\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#).expect("a valid regex");
    let css = Regex::new(
        r#"(?is)url\(\s*["']?\s*((?:https?:)?//[^"')\s]+)|@import\s+["']((?:https?:)?//[^"']+)"#,
    )
    .expect("a valid regex");
    let styles =
        Regex::new(r#"(?is)<style\b[^>]*>(.*?)</style>|\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')"#)
            .expect("a valid regex");
    let remote = |u: &str| {
        let u = u.trim();
        (u.starts_with("//")
            || u.to_ascii_lowercase().starts_with("http://")
            || u.to_ascii_lowercase().starts_with("https://"))
            && !allowed.iter().any(|a| u.starts_with(a))
    };
    let mut offenders = Vec::new();
    for path in found {
        let raw = text(&path);
        let clean = blank_non_markup(&raw);
        let line_of = |at: usize| raw[..at].matches('\n').count() + 1;
        let mut hit = |at: usize, what: &str| {
            offenders.push(format!(
                "{}:{}: {}",
                path.display(),
                line_of(at),
                what.split_whitespace().collect::<Vec<_>>().join(" ")
            ));
        };
        for t in tag.captures_iter(&clean) {
            let whole = t.get(0).expect("the match");
            if t[1].eq_ignore_ascii_case("link") {
                let rels = rel
                    .captures(whole.as_str())
                    .and_then(|r| r.get(1).or(r.get(2)).or(r.get(3)))
                    .map(|m| m.as_str().to_ascii_lowercase());
                if rels.is_some_and(|r| r.split_whitespace().all(|v| LINK_ONLY.contains(&v))) {
                    continue;
                }
            }
            for a in attr.captures_iter(whole.as_str()) {
                let value = a
                    .get(2)
                    .or(a.get(3))
                    .or(a.get(4))
                    .map_or("", |m| m.as_str());
                // srcset: candidates separated by commas, each "url descriptor".
                let urls: Vec<&str> = if a[1].eq_ignore_ascii_case("srcset") {
                    value
                        .split(',')
                        .filter_map(|c| c.split_whitespace().next())
                        .collect()
                } else {
                    vec![value]
                };
                if urls.iter().any(|u| remote(u)) {
                    hit(whole.start(), whole.as_str());
                    break;
                }
            }
        }
        // In HTML, url() and @import load only inside a style attribute or a
        // <style> element; elsewhere they are prose. A stylesheet is all style.
        let is_css = path
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("css"));
        let regions: Vec<(usize, &str)> = if is_css {
            vec![(0, clean.as_str())]
        } else {
            styles
                .captures_iter(&clean)
                .filter_map(|c| c.get(1).or(c.get(2)).or(c.get(3)))
                .map(|m| (m.start(), m.as_str()))
                .collect()
        };
        for (base, region) in regions {
            for c in css.captures_iter(region) {
                let u = c.get(1).or(c.get(2)).map_or("", |m| m.as_str());
                if remote(u) {
                    hit(base + c.get(0).expect("the match").start(), &c[0]);
                }
            }
        }
    }
    offenders
}

/// Fails the test if any template under `templates` loads an asset from another
/// origin.
///
/// # Panics
/// On any, listing every one; or if `templates` holds nothing to check.
pub fn assert_no_remote_assets(templates: impl AsRef<Path>) {
    assert_no_remote_assets_except(templates, &[]);
}

/// [`assert_no_remote_assets`], allowing loads from the origins in `allowed`: a
/// service that can't be self-hosted (a CAPTCHA, a payment form). Each is a hole in
/// the rule; name exactly the origin and path prefix, and say why beside the call.
///
/// # Panics
/// As [`assert_no_remote_assets`].
pub fn assert_no_remote_assets_except(templates: impl AsRef<Path>, allowed: &[&str]) {
    let offenders = remote_assets(templates.as_ref(), allowed);
    assert!(
        offenders.is_empty(),
        "templates load assets from another origin (vendor them: vendor.pins):\n{}",
        offenders.join("\n")
    );
}

/// One line of `vendor.pins`: where the file lives, where it came from, its SRI hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    /// The file, relative to the pins file's directory.
    pub path: String,
    /// Where `vendor-js` downloads it from.
    pub url: String,
    /// `sha384-<base64>`, as in a script's `integrity` attribute.
    pub sha384: String,
}

/// The pins in a `vendor.pins` file: `path url sha384-…` per line; blank lines and
/// `#` comments (whole-line or trailing) are skipped.
///
/// # Panics
/// If the file can't be read, a line is malformed, or a path is absolute or climbs
/// out of the repository.
#[must_use]
pub fn pins(file: impl AsRef<Path>) -> Vec<Pin> {
    let file = file.as_ref();
    text(file)
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            let [path, url, sha] = parts[..] else {
                panic!("{}: `{l}` is not `path url sha384-…`", file.display())
            };
            assert!(
                sha.starts_with("sha384-"),
                "{}: `{sha}` is not a sha384- hash",
                file.display()
            );
            assert!(
                !path.starts_with('/') && !path.split('/').any(|s| s == ".."),
                "{}: `{path}` must stay inside the repository",
                file.display()
            );
            Pin {
                path: path.into(),
                url: url.into(),
                sha384: sha.into(),
            }
        })
        .collect()
}

/// The SRI digest of `bytes`: `sha384-<base64>`.
#[must_use]
pub fn sri(bytes: &[u8]) -> String {
    format!(
        "sha384-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha384::digest(bytes))
    )
}

/// Fails the test if any file `vendor.pins` lists is missing or differs from its
/// pin: an edited or swapped vendored file, or a pin updated without the file.
///
/// # Panics
/// On any mismatch, listing all of them; or if the file pins nothing.
pub fn assert_vendored_files_match_pins(pins_file: impl AsRef<Path>) {
    let pins_file = pins_file.as_ref();
    let root = pins_file.parent().unwrap_or(Path::new("."));
    let pinned = pins(pins_file);
    assert!(!pinned.is_empty(), "{} pins nothing", pins_file.display());
    let mut wrong = Vec::new();
    for pin in pinned {
        match std::fs::read(root.join(&pin.path)) {
            Ok(bytes) => {
                let got = sri(&bytes);
                if got != pin.sha384 {
                    wrong.push(format!(
                        "{}: pinned {}, on disk {got}",
                        pin.path, pin.sha384
                    ));
                }
            }
            Err(e) => wrong.push(format!("{}: {e}", pin.path)),
        }
    }
    assert!(
        wrong.is_empty(),
        "vendored files don't match vendor.pins (re-run vendor-js; never edit them):\n{}",
        wrong.join("\n")
    );
}

/// Fails the test if a script or stylesheet under `static_dir` names a source map
/// (`//# sourceMappingURL=` or `/*# sourceMappingURL= */`, anywhere on a line) that
/// isn't beside it.
///
/// # Panics
/// On any, listing all of them; or if `static_dir` holds no scripts or stylesheets.
pub fn assert_no_dangling_source_maps(static_dir: impl AsRef<Path>) {
    let static_dir = static_dir.as_ref();
    let found = files(static_dir, &["js", "mjs", "cjs", "css"]);
    assert!(
        !found.is_empty(),
        "{} holds no scripts or stylesheets: is the path right?",
        static_dir.display()
    );
    let reference = Regex::new(r"[/][/*][#@]\s*sourceMappingURL=([^\s*]+)").expect("a valid regex");
    let mut dangling = Vec::new();
    for file in found {
        for cap in reference.captures_iter(&text(&file)) {
            let target = &cap[1];
            if target.starts_with("data:") {
                continue;
            }
            let local = target.split(['?', '#']).next().unwrap_or(target);
            if !file.with_file_name(local).exists() {
                dangling.push(format!("{} -> {target}", file.display()));
            }
        }
    }
    assert!(
        dangling.is_empty(),
        "files reference source maps that aren't shipped:\n{}",
        dangling.join("\n")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("owt-assets-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn scan(html: &str) -> Vec<String> {
        let d = dir(&format!(
            "scan-{:x}",
            html.len() * 31 + html.bytes().map(usize::from).sum::<usize>()
        ));
        std::fs::write(d.join("t.html"), html).unwrap();
        remote_assets(&d, &[])
    }

    #[test]
    fn remote_loads_are_found() {
        for html in [
            "<script src=\"https://unpkg.com/htmx.org\"></script>",
            "<link rel=stylesheet href=//fonts.example/a.css>",
            "<link\n  rel=\"stylesheet\"\n  href=\"https://cdn.example/a.css\">",
            "<script\n src='https://cdn.example/x.js'></script>",
            "<img srcset=\"/a.png 1x, https://cdn.example/b.png 2x\">",
            "<video poster=\"https://cdn.example/p.png\"></video>",
            "<object data=\"https://cdn.example/x.svg\"></object>",
            "<img {% if n > 0 %}class=\"big\"{% endif %} src=\"https://cdn.example/a.png\">",
            "<div style=\"background: url('https://x.example/y.png')\"></div>",
            "<style>@import \"https://fonts.example/a.css\";</style>",
            "<link rel=\"preload\" as=\"font\" href=\"https://fonts.example/f.woff2\">",
        ] {
            assert_eq!(scan(html).len(), 1, "missed: {html}");
        }
    }

    #[test]
    fn links_comments_and_local_assets_are_not_loads() {
        for html in [
            "<a href=\"https://example.com\">docs</a>",
            "<link rel=\"canonical\" href=\"https://example.com/x\">",
            "<link rel=\"alternate\" hreflang=\"fr\" href=\"https://example.com/fr\">",
            "<!-- <script src=\"https://cdn.example/old.js\"></script> -->",
            "{# <script src=\"https://cdn.example/old.js\"></script> #}",
            "<script src=\"/static/htmx.min.js\"></script><img src=\"{{ avatar }}\">",
            "<p>see url(https://example.com) in the docs</p>",
        ] {
            assert_eq!(scan(html), Vec::<String>::new(), "flagged: {html}");
        }
    }

    #[test]
    fn line_numbers_point_at_the_tag() {
        let found = scan("<p>\n</p>\n<link\n rel=stylesheet\n href=https://x.example/a.css>\n");
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("t.html:3:"), "{found:?}");
    }

    #[test]
    fn allowed_origins_pass_and_only_those() {
        let d = dir("allow");
        std::fs::write(
            d.join("t.html"),
            "<script src=\"https://challenges.cloudflare.com/turnstile/v0/api.js\"></script>\n<script src=\"https://evil.example/x.js\"></script>",
        )
        .unwrap();
        assert_eq!(
            remote_assets(&d, &["https://challenges.cloudflare.com/"]).len(),
            1
        );
    }

    #[test]
    fn nothing_to_check_is_a_failure_not_a_pass() {
        assert!(std::panic::catch_unwind(|| assert_no_remote_assets("no/such/templates")).is_err());
        let empty = dir("empty");
        assert!(std::panic::catch_unwind(|| assert_no_remote_assets(&empty)).is_err());
        assert!(std::panic::catch_unwind(|| assert_no_dangling_source_maps(&empty)).is_err());
        std::fs::write(empty.join("vendor.pins"), "# nothing yet\n").unwrap();
        assert!(
            std::panic::catch_unwind(|| assert_vendored_files_match_pins(
                empty.join("vendor.pins")
            ))
            .is_err()
        );
    }

    /// Invalid UTF-8 is read, not skipped.
    #[test]
    fn latin1_files_are_scanned() {
        let d = dir("latin1");
        let mut bytes = b"<p>caf\xe9</p>\n".to_vec();
        bytes.extend_from_slice(b"<script src=\"https://cdn.example/x.js\"></script>");
        std::fs::write(d.join("t.html"), bytes).unwrap();
        assert_eq!(remote_assets(&d, &[]).len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_loops_are_not_followed() {
        let d = dir("loop");
        std::fs::write(d.join("t.html"), "<p></p>").unwrap();
        std::os::unix::fs::symlink(".", d.join("l1")).unwrap();
        std::os::unix::fs::symlink(".", d.join("l2")).unwrap();
        assert_eq!(remote_assets(&d, &[]), Vec::<String>::new());
    }

    #[test]
    fn pins_catch_an_edited_file_and_refuse_escaping_paths() {
        let d = dir("pins");
        std::fs::create_dir_all(d.join("static/vendor")).unwrap();
        std::fs::write(d.join("static/vendor/a.js"), b"console.log(1)").unwrap();
        let pin = sri(b"console.log(1)");
        std::fs::write(
            d.join("vendor.pins"),
            format!("# what the browser runs\r\nstatic/vendor/a.js https://cdn.example/a.js {pin}  # htmx\r\n"),
        )
        .unwrap();
        assert_eq!(pins(d.join("vendor.pins")).len(), 1);
        assert_vendored_files_match_pins(d.join("vendor.pins"));
        std::fs::write(d.join("static/vendor/a.js"), b"console.log(2)").unwrap();
        assert!(
            std::panic::catch_unwind(|| assert_vendored_files_match_pins(d.join("vendor.pins")))
                .is_err()
        );
        std::fs::write(
            d.join("bad.pins"),
            format!("../outside.js https://x/y {pin}\n"),
        )
        .unwrap();
        assert!(std::panic::catch_unwind(|| pins(d.join("bad.pins"))).is_err());
    }

    /// The SRI digest of the empty string, as browsers compute it.
    #[test]
    fn sri_is_the_browsers_digest() {
        assert_eq!(
            sri(b""),
            "sha384-OLBgp1GsljhM2TJ+sbHjaiH9txEUvgdDTAzHv2P24donTt6/529l+9Ua0vFImLlb"
        );
    }

    #[test]
    fn dangling_source_maps_are_found_in_scripts_and_styles() {
        let d = dir("maps");
        std::fs::write(d.join("ok.js"), "x\n//# sourceMappingURL=ok.js.map\n").unwrap();
        std::fs::write(d.join("ok.js.map"), "{}").unwrap();
        std::fs::write(d.join("query.js"), "x;//# sourceMappingURL=ok.js.map?v=1\n").unwrap();
        std::fs::write(
            d.join("inline.js"),
            "x\n//# sourceMappingURL=data:application/json;base64,e30=\n",
        )
        .unwrap();
        assert_no_dangling_source_maps(&d);
        std::fs::write(
            d.join("bad.css"),
            "a{}\n/*# sourceMappingURL=bad.css.map */\n",
        )
        .unwrap();
        assert!(std::panic::catch_unwind(|| assert_no_dangling_source_maps(&d)).is_err());
    }
}
