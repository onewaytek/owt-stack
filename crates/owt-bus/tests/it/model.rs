//! The bus against a model of it.
//!
//! Subscriptions join and leave topics and messages are published, in any order; each
//! subscription must receive exactly the messages published to a topic while it was
//! in it, once each, in the order they were published.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use owt_bus::{Bus, Message, Options, Topic};
use proptest::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Room(u8);

impl fmt::Display for Room {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "room-{}", self.0)
    }
}

impl Topic for Room {
    fn parse(channel: &str) -> Option<Self> {
        channel.strip_prefix("room-")?.parse().ok().map(Room)
    }
}

#[derive(Debug, PartialEq)]
struct Text(String);

impl Message for Text {
    fn decode(text: String) -> Option<Self> {
        Some(Text(text))
    }
    fn text(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug)]
enum Step {
    Join(usize, u8),
    Leave(usize, u8),
    Publish(u8),
    /// Drop the subscription and start a new one in its place.
    Replace(usize),
}

const SUBSCRIBERS: usize = 3;

fn steps() -> impl Strategy<Value = Vec<Step>> {
    let step = prop_oneof![
        3 => (0..SUBSCRIBERS, 0u8..3).prop_map(|(s, t)| Step::Join(s, t)),
        2 => (0..SUBSCRIBERS, 0u8..3).prop_map(|(s, t)| Step::Leave(s, t)),
        4 => (0u8..3).prop_map(Step::Publish),
        1 => (0..SUBSCRIBERS).prop_map(Step::Replace),
    ];
    prop::collection::vec(step, 0..80)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn each_subscription_hears_its_topics_and_nothing_else(steps in steps()) {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        runtime.block_on(async {
            let bus: Bus<Room, Text> = Bus::local(Options::default());
            let mut subs: Vec<_> = (0..SUBSCRIBERS).map(|_| bus.subscribe()).collect();
            let mut joined = vec![HashSet::<u8>::new(); SUBSCRIBERS];
            let mut expected = vec![Vec::<String>::new(); SUBSCRIBERS];
            for (n, step) in steps.into_iter().enumerate() {
                match step {
                    Step::Join(s, t) => {
                        subs[s].join(Room(t));
                        joined[s].insert(t);
                    }
                    Step::Leave(s, t) => {
                        subs[s].leave(Room(t));
                        joined[s].remove(&t);
                    }
                    Step::Publish(t) => {
                        let text = format!("{n}@{t}");
                        bus.publish(Room(t), Arc::new(Text(text.clone()))).await;
                        for s in 0..SUBSCRIBERS {
                            if joined[s].contains(&t) {
                                expected[s].push(text.clone());
                            }
                        }
                    }
                    Step::Replace(s) => {
                        // What the old one was owed dies with it.
                        subs[s] = bus.subscribe();
                        joined[s].clear();
                        expected[s].clear();
                    }
                }
                for t in 0..3 {
                    let anyone = joined.iter().any(|j| j.contains(&t));
                    prop_assert_eq!(bus.has_subscribers(Room(t)), anyone, "topic {} after step {}", t, n);
                }
            }
            for (s, sub) in subs.iter_mut().enumerate() {
                let mut heard = Vec::new();
                while let Ok(m) = sub.rx.try_recv() {
                    heard.push(m.0.clone());
                }
                prop_assert_eq!(&heard, &expected[s], "subscription {}", s);
            }
            Ok(())
        })?;
    }

    /// A slow subscriber loses messages past its queue; it never holds up the
    /// publisher or the others.
    #[test]
    fn a_full_queue_costs_only_its_owner(capacity in 1usize..8, published in 0usize..40) {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        runtime.block_on(async {
            let bus: Bus<Room, Text> = Bus::local(Options { capacity, ..Options::default() });
            let (mut slow, mut quick) = (bus.subscribe(), bus.subscribe());
            slow.join(Room(0));
            quick.join(Room(0));
            let mut heard_by_quick = 0;
            for n in 0..published {
                bus.publish(Room(0), Arc::new(Text(n.to_string()))).await;
                // The quick one keeps up.
                prop_assert_eq!(quick.rx.try_recv().unwrap().0.clone(), n.to_string());
                heard_by_quick += 1;
            }
            prop_assert_eq!(heard_by_quick, published);
            let mut kept = Vec::new();
            while let Ok(m) = slow.rx.try_recv() {
                kept.push(m.0.clone());
            }
            let oldest: Vec<String> = (0..published.min(capacity)).map(|n| n.to_string()).collect();
            prop_assert_eq!(kept, oldest, "the first {} are kept, the rest dropped", capacity);
            Ok(())
        })?;
    }
}
