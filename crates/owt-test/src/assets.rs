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
//! * **built from npm:** the lockfile is the integrity record, and the app's gate
//!   rebuilds and diffs the output.
//!
//! [`assert_no_remote_assets`] is the invariant itself: it fails on the next
//! `<script src="https://…">` anyone adds. [`assert_no_dangling_source_maps`] catches
//! a shipped script pointing at a source map that isn't shipped, which breaks
//! asset pipelines that resolve every reference.
//!
//! Each takes paths relative to the crate under test (`CARGO_MANIFEST_DIR`, the
//! working directory of its tests).

use std::path::{Path, PathBuf};

use base64::Engine;
use regex::Regex;
use sha2::{Digest, Sha384};

fn files(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(files(&p, ext));
        } else if p.extension().is_some_and(|x| x == ext) {
            out.push(p);
        }
    }
    out.sort();
    out
}

/// The template lines that load something from another origin: an absolute or
/// protocol-relative `src`/`href`, or a `url(…)` in a style. Links people follow
/// (`<a href>`) are not loads and are allowed.
#[must_use]
pub fn remote_assets(templates: &Path) -> Vec<String> {
    let load = Regex::new(
        r#"(?i)<(?:script|link|img|iframe|source|video|audio|embed)\b[^>]*\b(?:src|href)\s*=\s*["']?(?:https?:)?//|url\(\s*["']?(?:https?:)?//"#,
    )
    .expect("a valid regex");
    let mut offenders = Vec::new();
    for t in files(templates, "html") {
        let Ok(text) = std::fs::read_to_string(&t) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            if load.is_match(line) {
                offenders.push(format!("{}:{}: {}", t.display(), n + 1, line.trim()));
            }
        }
    }
    offenders
}

/// Fails the test if any template under `templates` loads an asset from another
/// origin.
///
/// # Panics
/// On the first such template, listing every offending line.
pub fn assert_no_remote_assets(templates: impl AsRef<Path>) {
    let offenders = remote_assets(templates.as_ref());
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
/// `#` comments are skipped.
///
/// # Panics
/// If the file can't be read or a line is malformed.
#[must_use]
pub fn pins(file: impl AsRef<Path>) -> Vec<Pin> {
    let file = file.as_ref();
    let text = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
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
/// On any mismatch, listing all of them.
pub fn assert_vendored_files_match_pins(pins_file: impl AsRef<Path>) {
    let pins_file = pins_file.as_ref();
    let root = pins_file.parent().unwrap_or(Path::new("."));
    let mut wrong = Vec::new();
    for pin in pins(pins_file) {
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

/// Fails the test if a script under `static_dir` names a source map that isn't
/// beside it.
///
/// # Panics
/// On any, listing all of them.
pub fn assert_no_dangling_source_maps(static_dir: impl AsRef<Path>) {
    let reference = Regex::new(r"(?m)^//# sourceMappingURL=(\S+)\s*$").expect("a valid regex");
    let mut dangling = Vec::new();
    for script in files(static_dir.as_ref(), "js") {
        let Ok(text) = std::fs::read_to_string(&script) else {
            continue;
        };
        for cap in reference.captures_iter(&text) {
            let target = &cap[1];
            if !target.starts_with("data:") && !script.with_file_name(target).exists() {
                dangling.push(format!("{} -> {target}", script.display()));
            }
        }
    }
    assert!(
        dangling.is_empty(),
        "scripts reference source maps that aren't shipped:\n{}",
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

    #[test]
    fn remote_loads_are_found_and_links_are_not() {
        let d = dir("templates");
        std::fs::create_dir_all(d.join("partials")).unwrap();
        std::fs::write(
            d.join("base.html"),
            "<script src=\"/static/htmx.min.js\"></script>\n<a href=\"https://example.com\">docs</a>\n",
        )
        .unwrap();
        std::fs::write(
            d.join("partials/x.html"),
            "<script src=\"https://unpkg.com/htmx.org\"></script>\n<link rel=stylesheet href=//fonts.example/a.css>\n<div style=\"background: url('https://x/y.png')\"></div>\n",
        )
        .unwrap();
        let found = remote_assets(&d);
        assert_eq!(found.len(), 3, "{found:#?}");
        assert!(found.iter().all(|f| f.contains("partials/x.html")));
        assert!(std::panic::catch_unwind(|| assert_no_remote_assets(&d)).is_err());
    }

    #[test]
    fn pins_catch_an_edited_file() {
        let d = dir("pins");
        std::fs::create_dir_all(d.join("static/vendor")).unwrap();
        std::fs::write(d.join("static/vendor/a.js"), b"console.log(1)").unwrap();
        let pin = sri(b"console.log(1)");
        std::fs::write(
            d.join("vendor.pins"),
            format!("# what the browser runs\nstatic/vendor/a.js https://cdn.example/a.js {pin}\n"),
        )
        .unwrap();
        assert_eq!(pins(d.join("vendor.pins")).len(), 1);
        assert_vendored_files_match_pins(d.join("vendor.pins"));
        std::fs::write(d.join("static/vendor/a.js"), b"console.log(2)").unwrap();
        assert!(
            std::panic::catch_unwind(|| assert_vendored_files_match_pins(d.join("vendor.pins")))
                .is_err()
        );
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
    fn dangling_source_maps_are_found() {
        let d = dir("maps");
        std::fs::write(d.join("ok.js"), "x\n//# sourceMappingURL=ok.js.map\n").unwrap();
        std::fs::write(d.join("ok.js.map"), "{}").unwrap();
        std::fs::write(
            d.join("inline.js"),
            "x\n//# sourceMappingURL=data:application/json;base64,e30=\n",
        )
        .unwrap();
        assert_no_dangling_source_maps(&d);
        std::fs::write(d.join("bad.js"), "x\n//# sourceMappingURL=bad.js.map\n").unwrap();
        assert!(std::panic::catch_unwind(|| assert_no_dangling_source_maps(&d)).is_err());
    }
}
