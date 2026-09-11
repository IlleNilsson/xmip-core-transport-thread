#![forbid(unsafe_code)]

//! Streams that arrive over Thread. One UDP datagram is one Stream: whole
//! in one 802.15.4 frame where it fits, else in 6LoWPAN fragments put back
//! together by tag at the node it was sent to.
//!
//! Thread is IPv6 on the 802.15.4 radio of the building's locks, lights
//! and thermostats: a mesh of routers and end devices with mesh-local
//! addresses derived from their short addresses, and a border router where
//! the mesh meets the rest of the network. What is here is the data frame,
//! the uncompressed IPv6 dispatch and the FRAG1 and FRAGN headers of RFC
//! 4944, the IPv6 and UDP headers with the checksum, and the reassembly. A
//! Send Location addresses a node's mesh-local address and port; a Receive
//! Location is a node taking the datagrams sent to its port.
//!
//! The radio is a trait: [`LoopbackRadio`] is the receiving node
//! in-process, which every test and every box without an 802.15.4 radio
//! drives, the way can-bus drives its loopback bus. The origin URI names
//! the radio and the sender: `thread://loopback/[fd00::ff:fe00:1a2b]:49152`.

pub mod datagram;
pub mod frame;

use std::collections::VecDeque;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

pub use datagram::{Datagram, MAX_UDP_PAYLOAD, Reassembly};
pub use frame::{Frame, Lowpan};
use transport::error::{Result, TransportError, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::{Arrived, Directions, Transport};

/// Where frames go and come from: the air, as one node hears it.
pub trait Radio: Send + Sync {
    /// The radio's name, for the origin URI.
    fn name(&self) -> &str;
    /// Put a frame on the air.
    ///
    /// # Errors
    /// Where the radio refused it.
    fn transmit(&self, frame: &[u8]) -> Result<()>;
    /// The next frame, or `None` when nothing arrived within `timeout`.
    ///
    /// # Errors
    /// Where the radio could not be read.
    fn receive(&self, timeout: Duration) -> Result<Option<Vec<u8>>>;
}

/// The receiving node in-process: what the sender transmits, the node puts
/// back together, and the datagram is held until taken.
#[derive(Default)]
pub struct LoopbackRadio {
    reassembly: Mutex<Reassembly>,
    arrived: Mutex<VecDeque<Datagram>>,
}

impl LoopbackRadio {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The next datagram the node took whole.
    #[must_use]
    pub fn take(&self) -> Option<Datagram> {
        self.arrived
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }
}

impl Radio for LoopbackRadio {
    fn name(&self) -> &'static str {
        "loopback"
    }

    fn transmit(&self, bytes: &[u8]) -> Result<()> {
        let frame = Frame::decode(bytes)?;
        let whole = self
            .reassembly
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take(Lowpan::decode(&frame.payload)?)?;
        if let Some(bytes) = whole {
            self.arrived
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back(Datagram::decode(&bytes)?);
        }
        Ok(())
    }

    fn receive(&self, _timeout: Duration) -> Result<Option<Vec<u8>>> {
        // A node on this radio only sends; nothing comes back down.
        Ok(None)
    }
}

/// One node on one radio: its short address, the port it listens on, and
/// where it sends.
#[derive(Clone)]
pub struct ThreadTransport {
    radio: Arc<dyn Radio>,
    rloc16: u16,
    port: u16,
    destination: SocketAddrV6,
    /// The MAC sequence and the datagram tag, shared by every clone.
    counters: Arc<Mutex<(u8, u16)>>,
    timeout: Duration,
    /// Set on a loopback: the radio holds what the node took.
    loopback: Option<Arc<LoopbackRadio>>,
}

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
            counters: Arc::new(Mutex::new((0, 0))),
            timeout: Duration::from_secs(5),
            loopback: None,
        }
    }

    /// Give up on a datagram whose fragments stop coming for `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
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
    pub fn rloc16_of(address: &Ipv6Addr) -> Option<u16> {
        let segments = address.segments();
        (segments[..7] == [0xfd00, 0, 0, 0, 0, 0x00ff, 0xfe00]).then_some(segments[7])
    }

    fn next_counters(&self) -> (u8, u16) {
        let mut counters = self.counters.lock().unwrap_or_else(PoisonError::into_inner);
        let next = *counters;
        counters.0 = counters.0.wrapping_add(1);
        counters.1 = counters.1.wrapping_add(1);
        next
    }

    /// Send `bytes` as one datagram to `to`, in as many frames as it takes.
    ///
    /// # Errors
    /// More than one datagram carries, or a radio that refused a frame.
    pub fn send_datagram(&self, to: SocketAddrV6, bytes: &[u8]) -> Result<()> {
        let datagram = Datagram {
            source: self.address(),
            destination: *to.ip(),
            source_port: self.port,
            destination_port: to.port(),
            payload: bytes.to_vec(),
        };
        let (sequence, tag) = self.next_counters();
        let hop = Self::rloc16_of(to.ip()).unwrap_or(0x0000);
        for (offset, lowpan) in datagram::fragments(&datagram.encode()?, tag)?
            .iter()
            .enumerate()
        {
            let sequence = sequence.wrapping_add(u8::try_from(offset).unwrap_or(0));
            let frame = Frame::new(sequence, hop, self.rloc16, &lowpan.encode())?;
            self.radio.transmit(&frame.encode())?;
        }
        Ok(())
    }

    /// Take one datagram sent to this node's port, or `None` when nothing
    /// arrived in time.
    ///
    /// # Errors
    /// Where the radio could not be read, a fragment was out of place, or
    /// the datagram does not read.
    pub fn receive_one(&self) -> Result<Option<Arrived>> {
        let mut reassembly = Reassembly::default();
        let Some(first) = self.radio.receive(self.timeout)? else {
            return Ok(None);
        };
        let mut bytes = first;
        loop {
            let frame = Frame::decode(&bytes)?;
            if let Some(whole) = reassembly.take(Lowpan::decode(&frame.payload)?)? {
                let datagram = Datagram::decode(&whole)?;
                if datagram.destination_port != self.port {
                    return Err(protocol_error("a datagram for another port"));
                }
                let origin = self.origin(&datagram.source, datagram.source_port);
                return Ok(Some(Arrived::new(origin, datagram.payload)));
            }
            bytes = self
                .radio
                .receive(self.timeout)?
                .ok_or_else(|| TransportError::retryable("the fragments stopped coming"))?;
        }
    }
}

impl Transport for ThreadTransport {
    fn name(&self) -> &'static str {
        "thread"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// Nothing on the air is not an error: an empty vector.
    fn receive(&self) -> Result<Vec<Arrived>> {
        Ok(self.receive_one()?.into_iter().collect())
    }

    /// `target` may name an address and port, `thread://radio/[fd00::1]:5683`,
    /// overriding the transport's.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let to = match transport::socket::target("thread", target) {
            Some((_, path)) if !path.is_empty() => path
                .parse()
                .map_err(|_| protocol_error(format!("{path:?} is not [address]:port")))?,
            _ => self.destination,
        };
        self.send_datagram(to, bytes)
    }
}

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

/// The leader, holding the datagram it took whole.
struct Served {
    transport: ThreadTransport,
    radio: Arc<LoopbackRadio>,
    address: String,
}

impl FarEnd for Served {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        let datagram = self
            .radio
            .take()
            .ok_or_else(|| protocol_error("no datagram came together"))?;
        let origin = self
            .transport
            .origin(&datagram.source, datagram.source_port);
        Ok(Arrived::new(origin, datagram.payload))
    }
}

impl Loopback for ThreadTransport {
    /// Eleven bits size a 6LoWPAN datagram, and the IPv6 and UDP headers
    /// take forty-eight of them.
    fn ceiling(&self) -> Option<usize> {
        Some(MAX_UDP_PAYLOAD)
    }

    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let radio = self
            .loopback
            .as_ref()
            .ok_or_else(|| protocol_error("a radio, not a loopback radio"))?;
        Ok(Box::new(Served {
            transport: self.clone(),
            radio: Arc::clone(radio),
            address: self.origin(self.destination.ip(), self.destination.port()),
        }))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        self.clone().send(address, payload)
    }

    fn unblock(&self, _address: &str) {
        // The air is in-process; nothing listens on a socket.
    }

    /// In order on one thread: the leader lives in the radio and reassembles
    /// as the node sends, so the send goes first and the take finds the
    /// datagram whole.
    fn round(&self, payload: &[u8]) -> Result<Arrived> {
        let far = self.far_end()?;
        self.send_to(far.address(), payload)?;
        let arrived = far.take_one()?;
        if arrived.bytes != payload {
            return Err(protocol_error("sent, but what the leader took differs"));
        }
        Ok(arrived)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shapes a protocol breaks on, as the Playground lists them, up to
    /// the ceiling.
    fn edge_payloads() -> Vec<(&'static str, Vec<u8>)> {
        let patterned = |len: usize| -> Vec<u8> {
            (0..len)
                .map(|at| u8::try_from((at * 31 + at / 251) % 256).unwrap_or(0))
                .collect()
        };
        vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x2a]),
            ("every byte", (0..=255).collect()),
            ("nul run", vec![0; 512]),
            ("high bytes", vec![0xff; 512]),
            ("crlf storm", b"\r\n".repeat(400)),
            ("mtu", patterned(1_472)),
            ("the brim", patterned(MAX_UDP_PAYLOAD)),
        ]
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
        for (name, bytes) in edge_payloads() {
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
        // Two ends of one air: what one transmits, the other receives. The
        // sender runs on another thread and the node takes the datagram.
        struct Air(Mutex<VecDeque<Vec<u8>>>);
        struct End(Arc<Air>, bool);
        impl Radio for End {
            fn name(&self) -> &'static str {
                "air"
            }
            fn transmit(&self, frame: &[u8]) -> Result<()> {
                self.0.0.lock().expect("lock").push_back(frame.to_vec());
                Ok(())
            }
            fn receive(&self, timeout: Duration) -> Result<Option<Vec<u8>>> {
                if !self.1 {
                    return Ok(None);
                }
                let deadline = std::time::Instant::now() + timeout;
                loop {
                    if let Some(frame) = self.0.0.lock().expect("lock").pop_front() {
                        return Ok(Some(frame));
                    }
                    if std::time::Instant::now() > deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        let air = Arc::new(Air(Mutex::new(VecDeque::new())));
        let node = ThreadTransport::new(Arc::new(End(Arc::clone(&air), true)), 0)
            .timing_out_after(Duration::from_secs(2));
        assert!(node.far_end().is_err(), "a real radio has no node inside");
        assert!(
            node.receive().expect("quiet").is_empty(),
            "nothing is not an error"
        );
        let sender = ThreadTransport::new(Arc::new(End(air, false)), 0x1a2b);
        let sending = std::thread::spawn(move || sender.send("thread://air", &[9; 300]));
        let arrived = node.receive().expect("taking");
        sending.join().expect("thread").expect("sending");
        assert_eq!(arrived.len(), 1);
        assert_eq!(arrived[0].bytes, [9; 300]);
        assert_eq!(
            arrived[0].origin_uri,
            "thread://air/[fd00::ff:fe00:1a2b]:5683"
        );
        let sender = ThreadTransport::new(
            Arc::new(End(Arc::new(Air(Mutex::new(VecDeque::new()))), false)),
            1,
        );
        assert!(
            sender.send("thread://air/[fd00::1]:9", b"x").is_ok(),
            "off-mesh goes to the leader"
        );
    }
}
