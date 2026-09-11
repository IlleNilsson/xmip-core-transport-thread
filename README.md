# xmip-core-transport-thread

Thread transport: IPv6 and UDP over IEEE 802.15.4 with 6LoWPAN — a Stream is one UDP datagram, whole in a frame or in FRAG1 and FRAGN fragments reassembled by datagram tag; a loopback radio stands in for the mesh. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
