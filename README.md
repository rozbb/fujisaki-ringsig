# fujisaki-ringsig

This is an implementation of the [Traceable Ring Signature algorithm by Eiichiro Fujisaki and
Koutarou Suzuki](https://eprint.iacr.org/2006/389.pdf). This crate uses the `curve25519-dalek`
library. In particular it uses the experimental `decaf` module for its elligator implementation.

## Warning
This crate should not be used in any serious contexts. It is not secure.
