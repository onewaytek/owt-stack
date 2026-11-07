//! Configuration parsing: any value either parses or is an error naming the variable
//! and not quoting it.

use std::time::Duration;

use owt_runtime::env::Vars;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn a_bad_value_is_an_error_that_keeps_it_secret(value in "[ -~]{12,40}") {
        let vars: Vars = [("TOKEN", value.clone())].into_iter().collect();
        let trimmed = value.trim();
        prop_assume!(!trimmed.is_empty());
        for error in [
            vars.parse::<u64>("TOKEN").err(),
            vars.flag("TOKEN", false).err(),
            vars.duration("TOKEN", Duration::ZERO).err(),
        ]
        .into_iter()
        .flatten()
        {
            let text = format!("{error:#}");
            prop_assert!(text.contains("TOKEN"));
            prop_assert!(!text.contains(trimmed), "{text:?} quotes the value");
        }
    }

    #[test]
    fn any_value_parses_or_errs(value in any::<String>()) {
        let vars: Vars = [("V", value.clone())].into_iter().collect();
        let _ = vars.parse::<i64>("V");
        let _ = vars.parse::<std::net::SocketAddr>("V");
        let _ = vars.flag("V", true);
        let _ = vars.duration("V", Duration::ZERO);
        // A list holds no blanks and nothing with a comma.
        for item in vars.list("V") {
            prop_assert!(!item.is_empty() && !item.contains(',') && item == item.trim());
        }
        // Blank is unset.
        prop_assert_eq!(vars.var("V").is_none(), value.trim().is_empty());
    }

    #[test]
    fn durations_round_trip(n in 0u64..10_000_000, unit in prop::sample::select(vec!["", "s", "ms"])) {
        let vars: Vars = [("D", format!("{n}{unit}"))].into_iter().collect();
        let expected = if unit == "ms" { Duration::from_millis(n) } else { Duration::from_secs(n) };
        prop_assert_eq!(vars.duration("D", Duration::ZERO).unwrap(), expected);
    }
}
