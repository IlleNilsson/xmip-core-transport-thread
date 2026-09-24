//! The IEEE 802.15.4 data frame as a Thread radio carries it — frame
//! control, sequence, PAN and two short addresses, the payload and a CRC-16
//! — and the 6LoWPAN headers inside it (RFC 4944): an uncompressed IPv6
//! dispatch where the datagram fits one frame, else a FRAG1 header on the
//! first fragment and a FRAGN header, with an offset in eight-byte units,
//! on every other.

use codec::crc::CRC_16_KERMIT;
use transport::error::{Result, protocol_error};

/// The most a PHY packet holds.
pub const MAX_PHY: usize = 127;
/// A data frame with short addresses: two of frame control, a sequence, the
/// PAN, two addresses — and the two-byte check sequence at the end.
pub const MAC_OVERHEAD: usize = 9 + 2;
/// What one frame's payload holds.
pub const MAX_PAYLOAD: usize = MAX_PHY - MAC_OVERHEAD;
/// The largest datagram a fragmented transmission carries: the size field
/// is eleven bits.
pub const MAX_DATAGRAM: usize = 2047;

/// Frame control: data frame, PAN identifier compression, short addresses.
const DATA_FRAME: [u8; 2] = [0x41, 0x88];
const DISPATCH_IPV6: u8 = 0x41;
const DISPATCH_FRAG1: u8 = 0xc0;
const DISPATCH_FRAGN: u8 = 0xe0;
const DISPATCH_MASK: u8 = 0xf8;

/// One MAC frame between two short addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub sequence: u8,
    pub pan: u16,
    pub destination: u16,
    pub source: u16,
    pub payload: Vec<u8>,
}

impl Frame {
    /// A frame, refusing more payload than the PHY holds.
    ///
    /// # Errors
    /// A payload over [`MAX_PAYLOAD`].
    pub fn new(sequence: u8, destination: u16, source: u16, payload: &[u8]) -> Result<Self> {
        if payload.len() > MAX_PAYLOAD {
            return Err(protocol_error("more than one 802.15.4 frame holds"));
        }
        Ok(Self {
            sequence,
            pan: 0xface,
            destination,
            source,
            payload: payload.to_vec(),
        })
    }

    /// The frame as the radio carries it, check sequence last.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = DATA_FRAME.to_vec();
        out.push(self.sequence);
        out.extend_from_slice(&self.pan.to_le_bytes());
        out.extend_from_slice(&self.destination.to_le_bytes());
        out.extend_from_slice(&self.source.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&CRC_16_KERMIT.checksum(&out).to_le_bytes());
        out
    }

    /// Exactly one frame, its check sequence checked.
    ///
    /// # Errors
    /// More than the PHY holds, a frame cut off, a frame that is not data
    /// with short addresses, or a check sequence that does not check.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PHY {
            return Err(protocol_error("more than the PHY holds"));
        }
        if bytes.len() < MAC_OVERHEAD {
            return Err(protocol_error("a frame cut off inside its header"));
        }
        let (body, check) = bytes.split_at(bytes.len() - 2);
        if CRC_16_KERMIT.checksum(body) != u16::from_le_bytes([check[0], check[1]]) {
            return Err(protocol_error("a check sequence that does not check"));
        }
        if body[..2] != DATA_FRAME {
            return Err(protocol_error("not a data frame with short addresses"));
        }
        Ok(Self {
            sequence: body[2],
            pan: u16::from_le_bytes([body[3], body[4]]),
            destination: u16::from_le_bytes([body[5], body[6]]),
            source: u16::from_le_bytes([body[7], body[8]]),
            payload: body[9..].to_vec(),
        })
    }
}

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
    fn a_data_frame_ends_in_the_check_sequence_the_standard_computes() {
        // The check sequence is CRC-16/KERMIT, which codec holds to its
        // catalogue check value.
        let frame = Frame::new(7, 0x0000, 0x1a2b, b"hi").expect("frame");
        let bytes = frame.encode();
        assert_eq!(&bytes[..9], &[0x41, 0x88, 7, 0xce, 0xfa, 0, 0, 0x2b, 0x1a]);
        assert_eq!(bytes.len(), 9 + 2 + 2);
        assert_eq!(Frame::decode(&bytes).expect("decode"), frame);
        let mut bad = bytes.clone();
        bad[10] ^= 1;
        assert!(Frame::decode(&bad).is_err(), "check sequence");
        assert!(Frame::decode(&bytes[..8]).is_err(), "cut off");
        assert!(Frame::decode(&[0; MAX_PHY + 1]).is_err(), "too long");
        let mut beacon = bytes;
        beacon[0] = 0x40;
        let crc = CRC_16_KERMIT
            .checksum(&beacon[..beacon.len() - 2])
            .to_le_bytes();
        beacon.truncate(beacon.len() - 2);
        beacon.extend_from_slice(&crc);
        assert!(Frame::decode(&beacon).is_err(), "not a data frame");
        assert!(Frame::new(0, 0, 0, &[0; MAX_PAYLOAD + 1]).is_err());
        assert!(Frame::new(0, 0, 0, &[0; MAX_PAYLOAD]).is_ok());
    }

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
