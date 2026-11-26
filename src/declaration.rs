//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48).

use std::time::Duration;

use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// How long a node waits for a datagram's next fragment unless told
/// otherwise.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// Every setting a Location takes beyond its address, which names the
/// radio. `loopback`, the in-process node, is the one the estate has; an
/// 802.15.4 radio joins when it exposes one.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        Setting {
            name: "rloc16",
            kind: Kind::Integer {
                minimum: 0,
                maximum: 0xfffe,
            },
            presence: Presence::Required,
            meaning: "This node's short address, from which its mesh-local address is \
                      derived.",
            applies: Applies::Both,
        },
        transport::configured::timeout(
            Applies::Receive,
            Some(TIMEOUT),
            "How long a receive waits for a datagram and each of its fragments.",
        ),
    ],
};

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["thread"];
