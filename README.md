# xmip-core-transport-thread

Thread transport: IPv6 and UDP over IEEE 802.15.4 with 6LoWPAN — a Stream is one UDP datagram, whole in a frame or in FRAG1 and FRAGN fragments reassembled by datagram tag; a loopback radio stands in for the mesh. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

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

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
