//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`.

use std::time::Duration;

use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// How long a node waits for a datagram's next fragment unless told
/// otherwise.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// Every setting a Location takes beyond its address, which names the
/// radio — an 802.15.4 interface of Linux's kernel, `wpan0`, or `loopback`,
/// the in-process node — and then, for a send, where it goes.
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
                      derived: on an interface, the interface's own.",
            applies: Applies::Both,
        },
        transport::configured::timeout(
            Applies::Receive,
            Some(TIMEOUT),
            "How long a receive waits for a datagram and each of its fragments.",
        ),
    ],
};

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["thread"];
