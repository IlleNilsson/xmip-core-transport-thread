# xmip-core-transport-thread

Thread transport: IPv6 and UDP over IEEE 802.15.4 with 6LoWPAN — a Stream is one UDP datagram, whole in a frame or in FRAG1 and FRAGN fragments reassembled by datagram tag; an 802.15.4 interface of Linux's kernel, or a loopback radio in process. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## The radio

The radio is the transport capability's `ieee802154::Radio`, and a frame's
MAC header and check sequence are the radio's: this crate hands it the
6LoWPAN headers and the datagram (`src/lowpan.rs`), to the next hop's short
address, and takes them back with the short address that sent them
(ADR-0051, amendment 2026-11-27). A Location's address names the radio:

- **an interface of Linux's kernel**, `thread://wpan0`, an `AF_IEEE802154`
  datagram socket bound to the interface's own PAN and short address
  (`net::ieee802154::Interface`), which a user opens with no capability.
  The Location's `rloc16` must be the interface's short address, since the
  kernel's MAC sends from it; another is refused, naming both. Elsewhere,
  and on a Linux whose kernel carries no 802.15.4 sockets, it is refused in
  words, so `xmip-service` links Thread on Linux alone;
- **`loopback`**, the receiving node in process, the leader putting each
  datagram back together, which every test and the System Tests drive.

A Send Location's address may name where it sends after the radio, as a
target does: `thread://wpan0/[fd00::ff:fe00:2]:5683`; the leader on port
5683 where it names none. Proven through a node on Linux's two virtual
radios, `mac802154_hwsim`'s `wpan0` and `wpan1`, by the estate's service
test (`aired.rs`). Until 2026-11-27 the crate wrote the MAC frame itself,
its PAN fixed at `0xface`, and had no radio but the loopback.

## Acknowledgement

Acceptance is at-most-once here. A UDP datagram over Thread has no reply: the
sender's last fragment leaves with nobody waiting on an answer, so nobody is
left to tell how the receive cycle ended. Each datagram arrives whole, its
6LoWPAN fragments put back together.

## The declaration

What a Location of this technology is configured with is two `const`s in its
`declaration` module, `src/declaration.rs`, beside the code, which
`Configured` reads (ADR-0064, amendment 2026-11-26):
`declaration::SETTINGS`, `rloc16` and `timeout`, and `SCHEMES`, `thread`.
The wait `timeout` defaults to, `TIMEOUT`, is there too, and the code reads
it from there. Built with its `declaration` feature alone
(`--no-default-features --features declaration`), the crate is those and
nothing more: its code and every crate the code is built on are behind the
default feature. So the library the surfaces load carries it without the
code, through the gathering crate xmip-core-declaration (open problem 48),
and the language server and the desktop suggest and check a Thread
Location's settings though no node in their process loaded the technology.
`test/Declaration.Test.ps1` in the estate holds that the declaration builds
nothing the transport capability does not.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
