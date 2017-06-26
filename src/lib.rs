//! WARNING: THIS CRATE SHOULD NOT BE USED IN ANY SERIOUS CONTEXTS. IT IS NOT SECURE.
//!
//! This is an implementation of the [Traceable Ring Signature algorithm by Eiichiro Fujisaki and
//! Koutaro Suzuki](https://eprint.iacr.org/2006/389.pdf). This crate uses the `curve25519-dalek`
//! library. In particular it uses the experimental `decaf` module for its elligator
//! implementation.
//!
//! Example usage:
//!
//! ```
//! # fn main() {
//! use fujisaki_ringsig::{sign, trace, verify, KeyPair, Tag, Trace};
//!
//! let msg1 = b"now that the party is jumping";
//! let msg2 = b"magnetized by the mic while I kick my juice";
//! let issue_number: usize = 12345;
//!
//! // Make some keypairs for our ring
//! let kp1 = KeyPair::generate();
//! let kp2 = KeyPair::generate();
//! let kp3 = KeyPair::generate();
//!
//! // Pretend we only have the private key of the first keypair
//! let my_kp = kp1;
//! let pubkeys = vec![my_kp.pubkey.clone(), kp2.pubkey, kp3.pubkey];
//!
//! // Make the tag corresponding to this issue and ring
//! let tag = Tag {
//!     issue: issue_number,
//!     pubkeys: pubkeys,
//! };
//!
//! // Make two signatures. Sign different messages with the same key and the same tag. This is a
//! // no-no. We will get caught.
//! let sig1 = sign(&*msg1, &tag, &my_kp.privkey);
//! let sig2 = sign(&*msg2, &tag, &my_kp.privkey);
//!
//! // The signatures are all valid
//! assert!(verify(&*msg1, &tag, &sig1));
//! assert!(verify(&*msg2, &tag, &sig2));
//!
//! // Can't mix signatures
//! assert!(!verify(&*msg1, &tag, &sig2));
//!
//! // But we have been caught double-signing!
//! assert_eq!(trace(&*msg1, &sig1, &*msg2, &sig2, &tag), Trace::Revealed(&my_kp.pubkey));
//! # }

extern crate curve25519_dalek;
extern crate digest;
extern crate generic_array;
extern crate rand;
extern crate blake2;

pub mod key;
pub mod sig;
pub mod trace;

pub use key::*;
pub use sig::*;
pub use trace::*;

#[cfg(test)]
mod test;
