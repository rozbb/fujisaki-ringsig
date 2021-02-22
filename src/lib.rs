//! WARNING: THIS CRATE SHOULD NOT BE USED IN ANY SERIOUS CONTEXTS. IT IS NOT SECURE.
//!
//! This is an implementation of the [Traceable Ring Signature algorithm by Eiichiro Fujisaki and
//! Koutarou Suzuki](https://eprint.iacr.org/2006/389.pdf). This crate uses the `curve25519-dalek`
//! library. In particular, it uses the `ristretto` module for its elligator implementation.
//!
//! Example usage:
//!
//! ```
//! # fn main() {
//! use fujisaki_ringsig::{gen_keypair, sign, trace, verify, Tag, Trace};
//! # let mut rng = rand::thread_rng();
//!
//! let msg1 = b"now that the party is jumping";
//! let msg2 = b"magnetized by the mic while I kick my juice";
//! let issue = b"testcase 12345".to_vec();
//!
//! // Make some keypairs for our ring. Pretend we only have the private key of the first keypair
//! let (my_privkey, pubkey1) = gen_keypair(&mut rng);
//! let (_, pubkey2) = gen_keypair(&mut rng);
//! let (_, pubkey3) = gen_keypair(&mut rng);
//! let pubkeys = vec![pubkey1.clone(), pubkey2, pubkey3];
//!
//! // Make the tag corresponding to this issue and ring
//! let tag = Tag {
//!     issue,
//!     pubkeys,
//! };
//!
//! // Make two signatures. Sign different messages with the same key and the same tag. This is
//! // a no-no. We will get caught.
//! let sig1 = sign(&mut rng, &*msg1, &tag, &my_privkey);
//! let sig2 = sign(&mut rng, &*msg2, &tag, &my_privkey);
//!
//! // The signatures are all valid
//! assert!(verify(&*msg1, &tag, &sig1));
//! assert!(verify(&*msg2, &tag, &sig2));
//!
//! // Can't mix signatures
//! assert!(!verify(&*msg1, &tag, &sig2));
//!
//! // But we have been caught double-signing!
//! assert_eq!(trace(&*msg1, &sig1, &*msg2, &sig2, &tag), Trace::Revealed(&pubkey1));
//! # }

//-------- no_std stuff --------//

#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

//-------- Testing stuff --------//

#[cfg(test)]
mod test_utils;

//-------- Modules and exports--------//

pub mod key;
mod prelude;
pub mod sig;
pub mod trace;

pub use key::*;
pub use sig::*;
pub use trace::*;
