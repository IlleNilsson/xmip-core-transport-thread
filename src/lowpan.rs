//! The 6LoWPAN headers a Thread radio's frame carries (RFC 4944): an
//! uncompressed IPv6 dispatch where the datagram fits one frame, else a
//! FRAG1 header on the first fragment and a FRAGN header, with an offset in
//! eight-byte units, on every other. The frame around them — its MAC header
//! and check sequence — is the radio's (`transport::ieee802154`).

use transport::error::{Result, protocol_error};

/// The largest datagram a fragmented transmission carries: the size field
/// is eleven bits.
pub const MAX_DATAGRAM: usize = 2047;

const DISPATCH_IPV6: u8 = 0x41;
const DISPATCH_FRAG1: u8 = 0xc0;
const DISPATCH_FRAGN: u8 = 0xe0;
const DISPATCH_MASK: u8 = 0xf8;

/// What a frame's payload says in 6LoWPAN terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lowpan {
    /// A whole IPv6 datagram, uncompressed.
    Ipv6(Vec<u8>),
    /// The first fragment of a datagram of `size` bytes, under `tag`.
    Frag1 { size: u16, tag: u16, bytes: Vec<u8> },
    /// A later fragment, `offset` eight-byte units into the datagram.
    FragN {
        size: u16,
        tag: u16,
        offset: u8,
        bytes: Vec<u8>,
    },
}

impl Lowpan {
    /// The headers and bytes as the frame's payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Ipv6(bytes) => {
                let mut out = vec![DISPATCH_IPV6];
                out.extend_from_slice(bytes);
                out
            }
            Self::Frag1 { size, tag, bytes } => {
                let head = u16::from(DISPATCH_FRAG1) << 8 | (size & 0x07ff);
                let mut payload = head.to_be_bytes().to_vec();
                payload.extend_from_slice(&tag.to_be_bytes());
                payload.push(DISPATCH_IPV6);
                payload.extend_from_slice(bytes);
                payload
            }
            Self::FragN {
                size,
                tag,
                offset,
                bytes,
            } => {
                let head = u16::from(DISPATCH_FRAGN) << 8 | (size & 0x07ff);
                let mut payload = head.to_be_bytes().to_vec();
                payload.extend_from_slice(&tag.to_be_bytes());
                payload.push(*offset);
                payload.extend_from_slice(bytes);
                payload
            }
        }
    }

    /// The headers at the start of a frame's payload.
    ///
    /// # Errors
    /// A dispatch this crate does not carry, or a header cut off.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let cut = || protocol_error("a 6LoWPAN header cut off");
        let first = *payload.first().ok_or_else(cut)?;
        if first == DISPATCH_IPV6 {
            return Ok(Self::Ipv6(payload[1..].to_vec()));
        }
        let head = payload.get(..4).ok_or_else(cut)?;
        let size = u16::from_be_bytes([head[0] & 0x07, head[1]]);
        let tag = u16::from_be_bytes([head[2], head[3]]);
        match first & DISPATCH_MASK {
            DISPATCH_FRAG1 => {
                if payload.get(4) != Some(&DISPATCH_IPV6) {
                    return Err(protocol_error("a first fragment without its IPv6 dispatch"));
                }
                Ok(Self::Frag1 {
                    size,
                    tag,
                    bytes: payload[5..].to_vec(),
                })
            }
            DISPATCH_FRAGN => Ok(Self::FragN {
                size,
                tag,
                offset: *payload.get(4).ok_or_else(cut)?,
                bytes: payload[5..].to_vec(),
            }),
            other => Err(protocol_error(format!(
                "a dispatch this crate does not carry: {other:#04x}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_lowpan_headers_read_back_as_written() {
        let whole = Lowpan::Ipv6(vec![6, 0, 0, 0]);
        assert_eq!(whole.encode(), [0x41, 6, 0, 0, 0]);
        assert_eq!(Lowpan::decode(&whole.encode()).expect("decode"), whole);
        let first = Lowpan::Frag1 {
            size: 1000,
            tag: 0x1234,
            bytes: vec![6, 0],
        };
        assert_eq!(first.encode(), [0xc3, 0xe8, 0x12, 0x34, 0x41, 6, 0]);
        assert_eq!(Lowpan::decode(&first.encode()).expect("decode"), first);
        let later = Lowpan::FragN {
            size: 1000,
            tag: 0x1234,
            offset: 13,
            bytes: vec![9],
        };
        assert_eq!(later.encode(), [0xe3, 0xe8, 0x12, 0x34, 13, 9]);
        assert_eq!(Lowpan::decode(&later.encode()).expect("decode"), later);
        assert!(Lowpan::decode(&[]).is_err(), "empty");
        assert!(Lowpan::decode(&[0xc3, 0xe8]).is_err(), "cut off");
        assert!(
            Lowpan::decode(&[0xc3, 0xe8, 0x12, 0x34, 0x00]).is_err(),
            "no IPv6"
        );
        assert!(
            Lowpan::decode(&[0x60, 0, 0, 0]).is_err(),
            "IPHC is not carried"
        );
    }
}
