# fujisaki-ringsig
[![Version](https://img.shields.io/crates/v/fujisaki_ringsig.svg)](https://crates.io/crates/fujisaki_ringsig)
[![Docs](https://docs.rs/fujisaki_ringsig/badge.svg)](https://docs.rs/fujisaki_ringsig)
[![CI](https://github.com/rozbb/fujisaki-ringsig/workflows/CI/badge.svg)](https://github.com/rozbb/fujisaki-ringsig/actions)

This is an implementation of the [Traceable Ring Signature algorithm by Eiichiro Fujisaki and Koutarou Suzuki](https://eprint.iacr.org/2006/389.pdf). This crate uses the `curve25519-dalek` library. In particular, it uses the `ristretto` module for its elligator implementation.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your choice.

## Warning

This crate should not be used in any serious contexts. It is not secure.
