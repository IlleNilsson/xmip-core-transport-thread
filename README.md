# xmip-core-transport-thread

Thread transport: IPv6 and UDP over IEEE 802.15.4 with 6LoWPAN — a Stream is one UDP datagram, whole in a frame or in FRAG1 and FRAGN fragments reassembled by datagram tag; a loopback radio stands in for the mesh. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Acknowledgement

Acceptance is at-most-once here. A UDP datagram over Thread has no reply: the
sender's last fragment leaves with nobody waiting on an answer, so nobody is
left to tell how the receive cycle ended. Each datagram arrives whole, its
6LoWPAN fragments put back together.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
