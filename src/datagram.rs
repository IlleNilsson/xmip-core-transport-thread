//! The IPv6 datagram a Thread node sends: a forty-byte header, a UDP header
//! with its checksum over the pseudo-header, and the payload — and how the
//! datagram is cut into 6LoWPAN fragments and put back together by tag.

use std::net::Ipv6Addr;

use transport::ceiling;
use transport::error::{Result, protocol_error};

use crate::frame::{self, Lowpan, MAX_DATAGRAM};

/// The IPv6 header.
pub const IPV6_HEADER: usize = 40;
/// The UDP header.
pub const UDP_HEADER: usize = 8;
/// What a whole datagram carries: the size field is eleven bits and the two
/// headers take forty-eight.
pub const MAX_UDP_PAYLOAD: usize = MAX_DATAGRAM - IPV6_HEADER - UDP_HEADER;
/// The IPv6 dispatch byte, then the datagram: what fits one frame whole.
pub const MAX_UNFRAGMENTED: usize = frame::MAX_PAYLOAD - 1 - IPV6_HEADER - UDP_HEADER;
/// What a first fragment carries: the frame less four of FRAG1 header and
/// the dispatch, rounded down to eight-byte units so the offsets that follow
/// are whole.
pub const FRAG1_BYTES: usize = (frame::MAX_PAYLOAD - 5) / 8 * 8;
/// What a later fragment carries: the frame less five of FRAGN header.
pub const FRAGN_BYTES: usize = (frame::MAX_PAYLOAD - 5) / 8 * 8;

const NEXT_HEADER_UDP: u8 = 17;

/// One UDP datagram between two addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: Vec<u8>,
}

impl Datagram {
    /// The mesh-local address Thread derives from a short address: the
    /// interface identifier `0000:00ff:fe00:<rloc16>` on the mesh prefix.
    #[must_use]
    pub const fn address_of(rloc16: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0x00ff, 0xfe00, rloc16)
    }

    /// The datagram as IPv6 carries it, checksum computed.
    ///
    /// # Errors
    /// More payload than [`MAX_UDP_PAYLOAD`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        ceiling::within(
            self.payload.len(),
            MAX_UDP_PAYLOAD,
            "one 6LoWPAN datagram carries",
        )?;
        let udp_length = u16::try_from(UDP_HEADER + self.payload.len()).unwrap_or(u16::MAX);
        let mut out = vec![0x60, 0, 0, 0];
        out.extend_from_slice(&udp_length.to_be_bytes());
        out.push(NEXT_HEADER_UDP);
        out.push(64);
        out.extend_from_slice(&self.source.octets());
        out.extend_from_slice(&self.destination.octets());
        out.extend_from_slice(&self.source_port.to_be_bytes());
        out.extend_from_slice(&self.destination_port.to_be_bytes());
        out.extend_from_slice(&udp_length.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.payload);
        // A computed zero travels as all ones: zero on the wire means none.
        let check = match checksum(&self.source, &self.destination, &out[IPV6_HEADER..]) {
            0 => 0xffff,
            check => check,
        };
        out[IPV6_HEADER + 6..IPV6_HEADER + 8].copy_from_slice(&check.to_be_bytes());
        Ok(out)
    }

    /// The datagram `bytes` carry, checksum checked.
    ///
    /// # Errors
    /// Not IPv6 over UDP, a length the bytes do not match, or a checksum
    /// that does not check.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (ip, udp) = bytes
            .split_at_checked(IPV6_HEADER)
            .ok_or_else(|| protocol_error("a datagram cut off inside its IPv6 header"))?;
        if ip[0] >> 4 != 6 || ip[6] != NEXT_HEADER_UDP {
            return Err(protocol_error("not IPv6 carrying UDP"));
        }
        let length = usize::from(u16::from_be_bytes([ip[4], ip[5]]));
        if udp.len() != length || length < UDP_HEADER {
            return Err(protocol_error("a length the datagram does not match"));
        }
        if u16::from_be_bytes([udp[4], udp[5]]) != u16::try_from(length).unwrap_or(0) {
            return Err(protocol_error("a UDP length that disagrees with IPv6"));
        }
        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap_or([0; 16]));
        let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap_or([0; 16]));
        if checksum(&source, &destination, udp) != 0 {
            return Err(protocol_error("a checksum that does not check"));
        }
        Ok(Self {
            source,
            destination,
            source_port: u16::from_be_bytes([udp[0], udp[1]]),
            destination_port: u16::from_be_bytes([udp[2], udp[3]]),
            payload: udp[UDP_HEADER..].to_vec(),
        })
    }
}

/// The Internet checksum of `udp` under the IPv6 pseudo-header: the ones'
/// complement of the ones' complement sum. With the checksum field filled
/// in, a correct datagram comes to zero.
#[must_use]
pub fn checksum(source: &Ipv6Addr, destination: &Ipv6Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + udp.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&u32::try_from(udp.len()).unwrap_or(u32::MAX).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, NEXT_HEADER_UDP]);
    pseudo.extend_from_slice(udp);
    let mut sum: u32 = pseudo
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

/// `datagram` as the 6LoWPAN payloads that carry it under `tag`: whole
/// where it fits, else a FRAG1 and the FRAGNs after it.
///
/// # Errors
/// A datagram over [`MAX_DATAGRAM`].
pub fn fragments(datagram: &[u8], tag: u16) -> Result<Vec<Lowpan>> {
    if datagram.len() > MAX_DATAGRAM {
        return Err(protocol_error("a datagram over what eleven bits size"));
    }
    if datagram.len() < frame::MAX_PAYLOAD {
        return Ok(vec![Lowpan::Ipv6(datagram.to_vec())]);
    }
    let size = u16::try_from(datagram.len()).unwrap_or(u16::MAX);
    let (first, rest) = datagram.split_at(FRAG1_BYTES);
    let mut out = vec![Lowpan::Frag1 {
        size,
        tag,
        bytes: first.to_vec(),
    }];
    for (index, bytes) in rest.chunks(FRAGN_BYTES).enumerate() {
        let offset = (FRAG1_BYTES + index * FRAGN_BYTES) / 8;
        out.push(Lowpan::FragN {
            size,
            tag,
            offset: u8::try_from(offset).unwrap_or(u8::MAX),
            bytes: bytes.to_vec(),
        });
    }
    Ok(out)
}

/// One datagram being put back together from its fragments.
#[derive(Debug, Default)]
pub struct Reassembly {
    tag: Option<u16>,
    bytes: Vec<u8>,
    filled: usize,
}

impl Reassembly {
    /// One 6LoWPAN payload; the datagram when this completes it.
    ///
    /// # Errors
    /// A later fragment before a first, a fragment under another tag, a
    /// fragment past the size, or more bytes than the size.
    pub fn take(&mut self, lowpan: Lowpan) -> Result<Option<Vec<u8>>> {
        match lowpan {
            Lowpan::Ipv6(bytes) => Ok(Some(bytes)),
            Lowpan::Frag1 { size, tag, bytes } => {
                *self = Self {
                    tag: Some(tag),
                    bytes: vec![0; usize::from(size)],
                    filled: 0,
                };
                self.place(0, &bytes)
            }
            Lowpan::FragN {
                tag, offset, bytes, ..
            } => {
                if self.tag != Some(tag) {
                    return Err(protocol_error(
                        "a fragment of a datagram that did not start",
                    ));
                }
                self.place(usize::from(offset) * 8, &bytes)
            }
        }
    }

    fn place(&mut self, at: usize, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
        let slot = self
            .bytes
            .get_mut(at..at + bytes.len())
            .ok_or_else(|| protocol_error("a fragment past the datagram's size"))?;
        slot.copy_from_slice(bytes);
        self.filled += bytes.len();
        if self.filled > self.bytes.len() {
            return Err(protocol_error("more fragment than datagram"));
        }
        if self.filled == self.bytes.len() {
            self.tag = None;
            return Ok(Some(std::mem::take(&mut self.bytes)));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(payload: &[u8]) -> Datagram {
        Datagram {
            source: Datagram::address_of(0x1a2b),
            destination: Datagram::address_of(0x0000),
            source_port: 49152,
            destination_port: 5683,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn a_datagram_carries_its_checksum_and_reads_back() {
        let sent = datagram(b"hello");
        let bytes = sent.encode().expect("encode");
        assert_eq!(bytes.len(), 48 + 5);
        assert_eq!(bytes[0], 0x60);
        assert_eq!(&bytes[4..8], &[0, 13, 17, 64]);
        assert_eq!(&bytes[40..46], &[0xc0, 0x00, 0x16, 0x33, 0, 13]);
        assert_eq!(Datagram::decode(&bytes).expect("decode"), sent);
        let mut bad = bytes.clone();
        bad[50] ^= 1;
        assert!(Datagram::decode(&bad).is_err(), "checksum");
        assert!(Datagram::decode(&bytes[..52]).is_err(), "length");
        let mut tcp = bytes.clone();
        tcp[6] = 6;
        assert!(Datagram::decode(&tcp).is_err(), "not UDP");
        assert!(Datagram::decode(&bytes[..30]).is_err(), "cut off");
        assert!(datagram(&[0; MAX_UDP_PAYLOAD + 1]).encode().is_err());
        assert!(datagram(&[0; MAX_UDP_PAYLOAD]).encode().is_ok());
        assert_eq!(
            Datagram::address_of(0x1a2b).to_string(),
            "fd00::ff:fe00:1a2b"
        );
    }

    #[test]
    fn a_long_datagram_is_fragments_that_come_back_together() {
        let payload: Vec<u8> = (0..600u32)
            .map(|n| u8::try_from(n % 256).unwrap_or(0))
            .collect();
        let bytes = datagram(&payload).encode().expect("encode");
        let fragments = fragments(&bytes, 0x0042).expect("fragments");
        assert_eq!(fragments.len(), 7, "648 bytes: 104 and six of up to 104");
        assert!(matches!(fragments[0], Lowpan::Frag1 { size: 648, .. }));
        assert!(matches!(fragments[1], Lowpan::FragN { offset: 13, .. }));
        for fragment in &fragments {
            assert!(fragment.encode().len() <= frame::MAX_PAYLOAD);
        }
        let mut reassembly = Reassembly::default();
        let mut whole = None;
        for fragment in fragments {
            assert!(whole.is_none(), "not complete before the last");
            whole = reassembly.take(fragment).expect("fragment");
        }
        assert_eq!(whole, Some(bytes));
        let short = super::fragments(&[6; 100], 1).expect("whole");
        assert_eq!(short, vec![Lowpan::Ipv6(vec![6; 100])]);
        assert!(super::fragments(&[0; MAX_DATAGRAM + 1], 1).is_err());
    }

    #[test]
    fn a_fragment_out_of_place_is_refused() {
        let mut reassembly = Reassembly::default();
        let stray = Lowpan::FragN {
            size: 200,
            tag: 1,
            offset: 13,
            bytes: vec![0; 8],
        };
        assert!(reassembly.take(stray.clone()).is_err(), "no first");
        let first = Lowpan::Frag1 {
            size: 200,
            tag: 2,
            bytes: vec![0; 104],
        };
        assert!(reassembly.take(first).expect("first").is_none());
        assert!(reassembly.take(stray).is_err(), "another tag");
        let beyond = Lowpan::FragN {
            size: 200,
            tag: 2,
            offset: 25,
            bytes: vec![0; 8],
        };
        assert!(reassembly.take(beyond).is_err(), "past the size");
        let last = Lowpan::FragN {
            size: 200,
            tag: 2,
            offset: 13,
            bytes: vec![1; 96],
        };
        let whole = reassembly.take(last).expect("last").expect("complete");
        assert_eq!(whole.len(), 200);
        assert_eq!(whole[104], 1);
    }
}
