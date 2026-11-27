#![forbid(unsafe_code)]

//! Streams that arrive over Thread. One UDP datagram is one Stream: whole
//! in one 802.15.4 frame where it fits, else in 6LoWPAN fragments put back
//! together by tag at the node it was sent to.
//!
//! Thread is IPv6 on the 802.15.4 radio of the building's locks, lights
//! and thermostats: a mesh of routers and end devices with mesh-local
//! addresses derived from their short addresses, and a border router where
//! the mesh meets the rest of the network. What is here is the uncompressed
//! IPv6 dispatch and the FRAG1 and FRAGN headers of RFC 4944, the IPv6 and
//! UDP headers with the checksum, and the reassembly. A Send Location
//! addresses a node's mesh-local address and port; a Receive Location is a
//! node taking the datagrams sent to its port.
//!
//! **Acceptance is at-most-once here** ([`AT_MOST_ONCE`]): a UDP datagram
//! has no reply, so nobody waits to be told how the receive cycle ended.
//! Each datagram arrives whole, its fragments put back together.
//!
//! The radio is the capability's `ieee802154::Radio`, and its frame's MAC
//! header and check sequence are the radio's: a Location's address names an
//! interface of Linux's kernel, `thread://wpan0`, a frame to the next hop's
//! short address on its PAN, the node's `rloc16` the interface's own; or
//! [`LoopbackRadio`], the receiving node in process, which every test and
//! every box without an 802.15.4 radio drives, the way can-bus drives its
//! loopback bus. A Send Location's address may name where it sends after
//! the radio, `thread://wpan0/[fd00::ff:fe00:2]:5683`, as a target does;
//! the leader on port 5683 where it names none. The origin URI names the
//! radio and the sender: `thread://loopback/[fd00::ff:fe00:1a2b]:49152`.
//!
//! **Built with its `declaration` feature alone** the crate is
//! [`declaration`].

#[cfg(feature = "default")]
pub mod datagram;
#[cfg(feature = "declaration")]
pub mod declaration;
#[cfg(feature = "default")]
pub mod lowpan;

#[cfg(feature = "default")]
use std::{
    collections::VecDeque,
    net::{Ipv6Addr, SocketAddrV6},
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(feature = "default")]
pub use datagram::{Datagram, MAX_UDP_PAYLOAD, Reassembly};
#[cfg(feature = "default")]
use declaration::TIMEOUT;
#[cfg(feature = "default")]
pub use lowpan::Lowpan;
#[cfg(feature = "default")]
use net::{Target, ieee802154::Heard};
#[cfg(feature = "default")]
use transport::error::{Result, TransportError, protocol_error};
#[cfg(feature = "default")]
use transport::ieee802154::{self, Radio};
#[cfg(feature = "default")]
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
#[cfg(feature = "default")]
use transport::{
    Acknowledgement, ArrivalIdentity, Arrived, Configured, Directions, Taken, Transport, Waiting,
    held::Held,
};
#[cfg(feature = "default")]
use xcore::{
    lock::Locked,
    settings::{Read, Settings},
};

/// Why a datagram over Thread cannot be acknowledged after the receive
/// cycle.
#[cfg(feature = "default")]
pub const AT_MOST_ONCE: &str = "a UDP datagram over Thread has no reply: the sender's last \
                                fragment left with nobody waiting on an answer";

/// The receiving node in-process: what the sender transmits, the node puts
/// back together, and the datagram is held until taken.
#[cfg(feature = "default")]
#[derive(Default)]
pub struct LoopbackRadio {
    reassembly: Mutex<Reassembly>,
    arrived: Mutex<VecDeque<Datagram>>,
}

#[cfg(feature = "default")]
impl LoopbackRadio {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The next datagram the node took whole.
    #[must_use]
    pub fn take(&self) -> Option<Datagram> {
        self.arrived.locked().pop_front()
    }
}

#[cfg(feature = "default")]
impl Radio for LoopbackRadio {
    fn name(&self) -> &'static str {
        "loopback"
    }

    /// The node takes every frame, whatever short address it names: it is
    /// the one node on its air.
    fn transmit(&self, _destination: u16, payload: &[u8]) -> Result<()> {
        let whole = self.reassembly.locked().take(Lowpan::decode(payload)?)?;
        if let Some(bytes) = whole {
            self.arrived.locked().push_back(Datagram::decode(&bytes)?);
        }
        Ok(())
    }

    fn receive(&self, _timeout: Duration) -> Result<Option<Heard>> {
        // A node on this radio only sends; nothing comes back down.
        Ok(None)
    }

    fn waiting(&self) -> Waiting {
        Waiting::Polled("a read of the loopback radio returns at once")
    }
}

/// One node on one radio: its short address, the port it listens on, and
/// where it sends.
#[cfg(feature = "default")]
#[derive(Clone)]
pub struct ThreadTransport {
    radio: Arc<dyn Radio>,
    rloc16: u16,
    port: u16,
    destination: SocketAddrV6,
    /// The datagram tag, shared by every clone.
    tag: Arc<Mutex<u16>>,
    timeout: Duration,
    /// Set on a loopback: the radio holds what the node took.
    loopback: Option<Arc<LoopbackRadio>>,
}

#[cfg(feature = "default")]
impl ThreadTransport {
    /// A node at short address `rloc16` on `radio`, on port 5683 — CoAP's,
    /// which is what Thread applications speak — sending to the leader.
    #[must_use]
    pub fn new(radio: Arc<dyn Radio>, rloc16: u16) -> Self {
        Self {
            radio,
            rloc16,
            port: 5683,
            destination: SocketAddrV6::new(Datagram::address_of(0x0000), 5683, 0, 0),
            tag: Arc::new(Mutex::new(0)),
            timeout: TIMEOUT,
            loopback: None,
        }
    }

    /// This node's mesh-local address.
    #[must_use]
    pub const fn address(&self) -> Ipv6Addr {
        Datagram::address_of(self.rloc16)
    }

    /// `thread://<radio>/[<address>]:<port>`.
    #[must_use]
    pub fn origin(&self, address: &Ipv6Addr, port: u16) -> String {
        format!("thread://{}/[{address}]:{port}", self.radio.name())
    }

    /// The short address a mesh-local address names, or `None` off the
    /// mesh, where the leader forwards for the border router.
    #[must_use]
    fn rloc16_of(address: &Ipv6Addr) -> Option<u16> {
        let segments = address.segments();
        (segments[..7] == [0xfd00, 0, 0, 0, 0, 0x00ff, 0xfe00]).then_some(segments[7])
    }

    /// Where a target's or an address's path sends: `[address]:port`.
    fn destination_of(path: &str) -> Result<SocketAddrV6> {
        path.parse()
            .map_err(|_| protocol_error(format!("{path:?} is not [address]:port")))
    }

    fn next_tag(&self) -> u16 {
        let mut tag = self.tag.locked();
        let next = *tag;
        *tag = tag.wrapping_add(1);
        next
    }

    /// Send `bytes` as one datagram to `to`, in as many frames as it takes,
    /// each to the next hop: the node `to` names on the mesh, or the leader.
    ///
    /// # Errors
    /// More than one datagram carries, or a radio that refused a frame.
    fn send_datagram(&self, to: SocketAddrV6, bytes: &[u8]) -> Result<()> {
        let datagram = Datagram {
            source: self.address(),
            destination: *to.ip(),
            source_port: self.port,
            destination_port: to.port(),
            payload: bytes.to_vec(),
        };
        let hop = Self::rloc16_of(to.ip()).unwrap_or(0x0000);
        for lowpan in datagram::fragments(&datagram.encode()?, self.next_tag())? {
            self.radio.transmit(hop, &lowpan.encode())?;
        }
        Ok(())
    }

    /// Take one datagram sent to this node's port, whole, or `None` when
    /// nothing arrived in time. Acceptance is at-most-once
    /// ([`AT_MOST_ONCE`]).
    ///
    /// # Errors
    /// Where the radio could not be read, a fragment was out of place, or
    /// the datagram does not read.
    pub fn receive_one(&self) -> Result<Option<Arrived>> {
        let mut reassembly = Reassembly::default();
        let Some(mut heard) = self.radio.receive(self.timeout)? else {
            return Ok(None);
        };
        loop {
            if let Some(whole) = reassembly.take(Lowpan::decode(&heard.payload)?)? {
                let datagram = Datagram::decode(&whole)?;
                if datagram.destination_port != self.port {
                    return Err(protocol_error("a datagram for another port"));
                }
                let origin = self.origin(&datagram.source, datagram.source_port);
                let peer = SocketAddrV6::new(datagram.source, datagram.source_port, 0, 0);
                return Ok(Some(
                    Arrived::whole(
                        origin,
                        datagram.payload,
                        Acknowledgement::at_most_once(AT_MOST_ONCE),
                    )
                    .from_peer(peer.into()),
                ));
            }
            heard = self
                .radio
                .receive(self.timeout)?
                .ok_or_else(|| TransportError::retryable("the fragments stopped coming"))?;
        }
    }
}

#[cfg(feature = "default")]
impl Transport for ThreadTransport {
    fn name(&self) -> &'static str {
        "thread"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Unordered("each datagram is its own")
    }

    fn waiting(&self) -> Waiting {
        self.radio.waiting()
    }

    /// Nothing on the air is not an error: an empty vector. Acceptance is
    /// at-most-once here: a UDP datagram has no reply ([`AT_MOST_ONCE`]).
    fn receive_up_to(&self, _most: usize) -> Result<Vec<Arrived>> {
        Ok(self.receive_one()?.into_iter().collect())
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Gathered("one Thread datagram carries the whole body")
    }

    /// `target` may name an address and port, `thread://radio/[fd00::1]:5683`,
    /// overriding the transport's.
    fn send_from(&self, target: &str, outgoing: transport::Outgoing<'_>) -> Result<()> {
        let bytes: &[u8] = &outgoing.gather()?;
        let to = match Target::under(Self::SCHEMES, target).map(|named| named.path()) {
            Some(path) if !path.is_empty() => Self::destination_of(path)?,
            _ => self.destination,
        };
        self.send_datagram(to, bytes)
    }
}

/// The address names the radio, then where a send goes:
/// `wpan0/[fd00::ff:fe00:2]:5683`, or `loopback`.
#[cfg(feature = "default")]
impl Configured for ThreadTransport {
    const SETTINGS: &'static Settings = declaration::SETTINGS;
    const SCHEMES: &'static [&'static str] = declaration::SCHEMES;

    fn timeout_kept(&mut self) -> Option<&mut dyn transport::configured::TimeoutKept> {
        Some(&mut self.timeout)
    }

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let rloc16 = u16::try_from(settings.integer("rloc16"))
            .map_err(|_| protocol_error("a short address over 0xfffe"))?;
        let named = Target::bare(address);
        let radio: Arc<dyn Radio> = match named.authority() {
            "loopback" => Arc::new(LoopbackRadio::new()),
            name => {
                let (radio, at) = ieee802154::interface(name)?;
                ieee802154::agreeing(name, "rloc16", rloc16, at.short)?;
                radio
            }
        };
        let mut node = Self::new(radio, rloc16);
        if !named.path().is_empty() {
            node.destination = Self::destination_of(named.path())?;
        }
        Ok(node)
    }
}

#[cfg(feature = "default")]
impl ThreadTransport {
    /// Both ends on one in-process radio: a node at `0x1a2b` sending to the
    /// leader, and the leader taking, the loopback timeout on the fragments.
    #[must_use]
    pub fn loopback() -> Self {
        let radio = Arc::new(LoopbackRadio::new());
        let mut transport = Self::new(Arc::clone(&radio) as Arc<dyn Radio>, 0x1a2b)
            .timing_out_after(LOOPBACK_TIMEOUT);
        transport.loopback = Some(radio);
        transport
    }
}

#[cfg(feature = "default")]
impl Loopback for ThreadTransport {
    fn arrival_identity(&self) -> ArrivalIdentity {
        ArrivalIdentity::PEER
    }

    /// Eleven bits size a 6LoWPAN datagram, and the IPv6 and UDP headers
    /// take forty-eight of them.
    fn ceiling(&self) -> Option<usize> {
        Some(MAX_UDP_PAYLOAD)
    }

    /// The leader, holding the datagram it took whole.
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let radio = self
            .loopback
            .as_ref()
            .ok_or_else(|| protocol_error("a radio, not a loopback radio"))?;
        let transport = self.clone();
        let radio = Arc::clone(radio);
        Ok(Box::new(Held::new(
            self.origin(self.destination.ip(), self.destination.port()),
            move || {
                let datagram = radio
                    .take()
                    .ok_or_else(|| protocol_error("no datagram came together"))?;
                let origin = transport.origin(&datagram.source, datagram.source_port);
                let peer = SocketAddrV6::new(datagram.source, datagram.source_port, 0, 0);
                Ok(Taken::new(origin, datagram.payload).from_peer(peer.into()))
            },
        )))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        self.clone().send(address, payload)
    }

    /// In order on one thread: the leader lives in the radio and reassembles
    /// as the node sends, so the send goes first and the take finds the
    /// datagram whole.
    fn exchanges_in_order(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::payload::{edge_payloads, patterned};
    use xcore::settings::{Applies, Given};

    #[test]
    fn thread_declares_its_settings_and_reads_through_them() {
        assert_eq!(ThreadTransport::SETTINGS.problems(), Vec::<String>::new());
        let given = [
            ("rloc16".to_string(), Given::Integer(0x1a2b)),
            ("timeout".to_string(), Given::Text("250ms".to_string())),
        ];
        let built = ThreadTransport::open("loopback", Applies::Receive, &given).expect("built");
        assert_eq!(built.rloc16, 0x1a2b);
        assert_eq!(built.timeout, Duration::from_millis(250));
        assert!(
            built.waiting().polled(),
            "the loopback radio returns at once"
        );
        let rloc16 = [("rloc16".to_string(), Given::Integer(7))];
        let sent = ThreadTransport::open("loopback", Applies::Send, &rloc16).expect("built");
        assert_eq!(sent.timeout, TIMEOUT);
        let Err(refused) = ThreadTransport::open("loopback", Applies::Receive, &[]) else {
            panic!("rloc16 is required");
        };
        assert!(refused.message.contains("rloc16"), "{}", refused.message);
        // No interface of the name, no 802.15.4 sockets, or one whose own
        // short address is not 0x0007: each refused.
        assert!(ThreadTransport::open("wpan0", Applies::Send, &rloc16).is_err());
    }

    #[test]
    fn an_address_names_the_radio_and_where_a_send_goes() {
        let rloc16 = [("rloc16".to_string(), Given::Integer(1))];
        let at = "thread://loopback/[fd00::ff:fe00:2]:61631";
        let sent = ThreadTransport::open(at, Applies::Send, &rloc16).expect("built");
        assert_eq!(sent.destination.to_string(), "[fd00::ff:fe00:2]:61631");
        let leader =
            ThreadTransport::open("thread://loopback", Applies::Send, &rloc16).expect("built");
        assert_eq!(leader.destination.to_string(), "[fd00::ff:fe00:0]:5683");
        let bad = ThreadTransport::open("thread://loopback/two", Applies::Send, &rloc16);
        assert!(bad.is_err(), "not [address]:port");
    }

    /// The shapes a protocol breaks on, as the System Tests list them, up to
    /// the ceiling.
    fn payloads() -> Vec<(&'static str, Vec<u8>)> {
        let mut payloads = edge_payloads();
        payloads.extend([
            ("mtu", patterned(1_472)),
            ("the brim", patterned(MAX_UDP_PAYLOAD)),
        ]);
        payloads
    }

    #[test]
    fn a_loopback_round_carries_a_datagram_to_the_leader() {
        let loopback = ThreadTransport::loopback();
        let arrived = loopback.round(b"unlock").expect("round");
        assert_eq!(arrived.bytes, b"unlock");
        assert_eq!(
            arrived.origin_uri,
            "thread://loopback/[fd00::ff:fe00:1a2b]:5683"
        );
        let long = vec![7; 1000];
        assert_eq!(loopback.round(&long).expect("fragments").bytes, long);
        assert_eq!(loopback.ceiling(), Some(1_999));
        assert!(loopback.refuses(b"anything").is_none());
        assert_eq!(loopback.name(), "thread");
        assert!(loopback.directions().receives() && loopback.directions().sends());
        assert!(loopback.claims().is_none());
    }

    #[test]
    fn the_loopback_returns_the_edges_whole_and_refuses_over_the_brim() {
        let loopback = ThreadTransport::loopback();
        for (name, bytes) in payloads() {
            let arrived = loopback
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
        }
        let error = loopback
            .round(&vec![0; MAX_UDP_PAYLOAD + 1])
            .expect_err("over");
        assert!(error.message.contains("over the 1999"), "{error}");
    }

    #[test]
    fn a_target_names_an_address_and_port_and_a_bad_one_is_refused() {
        let loopback = ThreadTransport::loopback();
        loopback
            .send("thread://loopback/[fd00::ff:fe00:7]:61631", b"to seven")
            .expect("sending");
        let radio = loopback.loopback.as_ref().expect("loopback");
        let datagram = radio.take().expect("taken");
        assert_eq!(datagram.destination, Datagram::address_of(7));
        assert_eq!(datagram.destination_port, 61631);
        assert_eq!(datagram.payload, b"to seven");
        assert_eq!(ThreadTransport::rloc16_of(&datagram.destination), Some(7));
        assert!(ThreadTransport::rloc16_of(&"2001:db8::1".parse().expect("ip")).is_none());
        assert!(loopback.send("thread://loopback/seven", b"x").is_err());
    }

    #[test]
    fn the_node_takes_a_datagram_over_any_radio() {
        // Two ends of one air: what one transmits, the other hears, from
        // the short address it sent from, each frame to the next hop. The
        // sender runs on another thread and the node takes the datagram.
        struct Air(Mutex<VecDeque<(u16, Heard)>>);
        struct End(Arc<Air>, bool, u16);
        impl Radio for End {
            fn name(&self) -> &'static str {
                "air"
            }
            fn transmit(&self, destination: u16, payload: &[u8]) -> Result<()> {
                let heard = Heard {
                    source: self.2,
                    payload: payload.to_vec(),
                };
                self.0
                    .0
                    .lock()
                    .expect("lock")
                    .push_back((destination, heard));
                Ok(())
            }
            fn receive(&self, timeout: Duration) -> Result<Option<Heard>> {
                if !self.1 {
                    return Ok(None);
                }
                let deadline = std::time::Instant::now() + timeout;
                loop {
                    if let Some((to, heard)) = self.0.0.lock().expect("lock").pop_front() {
                        assert_eq!(to, self.2, "a frame to the next hop");
                        return Ok(Some(heard));
                    }
                    if std::time::Instant::now() > deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            fn waiting(&self) -> Waiting {
                Waiting::Waits("the air waits")
            }
        }
        let air = Arc::new(Air(Mutex::new(VecDeque::new())));
        let node = ThreadTransport::new(Arc::new(End(Arc::clone(&air), true, 0)), 0)
            .timing_out_after(Duration::from_secs(2));
        assert!(node.far_end().is_err(), "a real radio has no node inside");
        assert!(!node.waiting().polled(), "the radio's own way of waiting");
        assert!(
            node.receive().expect("quiet").is_empty(),
            "nothing is not an error"
        );
        let sender = ThreadTransport::new(Arc::new(End(air, false, 0x1a2b)), 0x1a2b);
        let sending = std::thread::spawn(move || sender.send("thread://air", &[9; 300]));
        let mut arrived = node.receive().expect("taking");
        sending.join().expect("thread").expect("sending");
        assert_eq!(arrived.len(), 1);
        let arrived = arrived.remove(0);
        assert!(!arrived.defers(), "a datagram is at-most-once");
        let arrived = arrived.taken().expect("taken");
        assert_eq!(arrived.bytes, [9; 300]);
        assert_eq!(arrived.origin_uri, "thread://air/[fd00::ff:fe00:1a2b]:5683");
        let sender = ThreadTransport::new(
            Arc::new(End(Arc::new(Air(Mutex::new(VecDeque::new()))), false, 1)),
            1,
        );
        assert!(
            sender.send("thread://air/[fd00::1]:9", b"x").is_ok(),
            "off-mesh goes to the leader"
        );
    }
}
