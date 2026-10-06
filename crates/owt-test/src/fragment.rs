//! A page and its htmx fragment agree.
//!
//! When a fragment has its own URL, the page and the fragment are two renderings of
//! one region, and nothing but a test stops them drifting: a class added to the
//! page's copy, a field the fragment forgot. [`same_element`] compares the region in
//! both, rendered from the same inputs.
//!
//! The comparison is modulo layout and escaping ([`crate::golden::Normalizer`]) and
//! ignores `hx-swap-oob`, which a fragment response puts on elements it swaps out of
//! band and the page does not.

use scraper::{Html, Selector};

use crate::golden::Normalizer;

/// The outer HTML of the one element `selector` matches in `html`.
fn element(html: &str, selector: &Selector, which: &str) -> Result<String, String> {
    let doc = Html::parse_document(html);
    let mut found = doc.select(selector);
    let first = found
        .next()
        .ok_or_else(|| format!("the {which} has no element matching the selector"))?;
    if found.next().is_some() {
        return Err(format!(
            "the {which} has more than one element matching the selector"
        ));
    }
    Ok(first.html())
}

/// Whether the element `selector` picks out is the same in `page` and in `fragment`.
/// `Err` says how they differ, at the first differing tag.
///
/// # Panics
/// If `selector` is not a CSS selector.
pub fn same_element(page: &str, fragment: &str, selector: &str) -> Result<(), String> {
    let sel =
        Selector::parse(selector).unwrap_or_else(|e| panic!("bad selector {selector:?}: {e}"));
    let n = Normalizer::new().mask(r#" hx-swap-oob="[^"]*""#, "");
    let (p, f) = (
        n.normalize(&element(page, &sel, "page")?),
        n.normalize(&element(fragment, &sel, "fragment")?),
    );
    if p == f {
        return Ok(());
    }
    let line = p
        .lines()
        .zip(f.lines())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| p.lines().count().min(f.lines().count()));
    Err(format!(
        "{selector} differs at line {}\n  page:     {}\n  fragment: {}",
        line + 1,
        p.lines().nth(line).unwrap_or("<end>"),
        f.lines().nth(line).unwrap_or("<end>")
    ))
}

/// [`same_element`], failing the test on a difference.
///
/// # Panics
/// If the element differs or is missing from either.
pub fn assert_same_element(page: &str, fragment: &str, selector: &str) {
    if let Err(e) = same_element(page, fragment, selector) {
        panic!("page and fragment disagree: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r##"<html><body><nav>chrome</nav><main id="viewport" class="map">
        <svg><use href="#t1"/></svg></main><aside id="overview">old</aside></body></html>"##;

    #[test]
    fn agrees_modulo_layout_and_oob() {
        let fragment = r##"<main id="viewport" class="map"><svg><use href="#t1"></use></svg></main>
            <aside id="overview" hx-swap-oob="true">new</aside>"##;
        assert_eq!(same_element(PAGE, fragment, "#viewport"), Ok(()));
        // Out-of-band elements are compared without their swap attribute.
        let err = same_element(PAGE, fragment, "#overview").unwrap_err();
        assert!(
            err.contains("page:     <aside id=\"overview\">old</aside>"),
            "{err}"
        );
    }

    #[test]
    fn reports_drift_and_missing_elements() {
        let drifted = r#"<main id="viewport" class="map zoomed"><svg></svg></main>"#;
        assert!(
            same_element(PAGE, drifted, "#viewport")
                .unwrap_err()
                .contains("zoomed")
        );
        assert!(
            same_element(PAGE, "<p></p>", "#viewport")
                .unwrap_err()
                .contains("fragment has no element")
        );
    }
}
