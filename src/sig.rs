use crate::{
    key::{PrivateKey, PublicKey},
    prelude::*,
};

use core::convert::TryFrom;

use blake2::{digest::Update, Blake2b};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use rand_core::{CryptoRng, RngCore};

static DOMAIN_STR0: &'static [u8] = b"rust-ringsig-0";
static DOMAIN_STR1: &'static [u8] = b"rust-ringsig-1";
static DOMAIN_STR2: &'static [u8] = b"rust-ringsig-2";

/// A Fujisaki signature. The size of `Signature` scales proportionally with the number of public
/// keys in the ring.
#[derive(Debug, Eq, PartialEq)]
pub struct Signature {
    aa1: RistrettoPoint,
    cs: Vec<Scalar>,
    zs: Vec<Scalar>,
}

/// Denotes the ring of public keys which are being used for the ring signature, as well as the
/// "issue", corresponding to what issue the signature corresponds to (e.g `b"auction number 15"`)
///
/// NOTE: The number of pubkeys MUST be less than 2^64
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tag {
    pub pubkeys: Vec<PublicKey>,
    pub issue: Vec<u8>,
}

impl Tag {
    // Given an initialized hash function, input the pubkeys and issue number
    fn hash_self<T: Update>(&self, mut h: T) -> T {
        for pubkey in &self.pubkeys {
            let pubkey_c = pubkey.0.compress();
            h.update(pubkey_c.as_bytes());
        }
        h.update(&*self.issue);

        h
    }

    // 3 independent hash functions

    fn hash0(&self) -> Blake2b {
        let h = Blake2b::with_params(b"", b"", DOMAIN_STR0);
        self.hash_self(h)
    }

    fn hash1(&self) -> Blake2b {
        let h = Blake2b::with_params(b"", b"", DOMAIN_STR1);
        self.hash_self(h)
    }

    fn hash2(&self) -> Blake2b {
        let h = Blake2b::with_params(b"", b"", DOMAIN_STR2);
        self.hash_self(h)
    }
}

// This routine is common to the verification and trace functions. It returns A₀ and the sigma
// values
pub(crate) fn compute_sigma(
    msg: &[u8],
    tag: &Tag,
    sig: &Signature,
) -> (RistrettoPoint, Vec<RistrettoPoint>) {
    // Make sure the ring size isn't bigger than a u64
    let ring_size = tag.pubkeys.len();
    if u64::try_from(ring_size).is_err() {
        panic!("number of pubkeys must be less than 2^64");
    }

    let aa1 = sig.aa1;

    // A₀ := H'(L, m)
    let aa0 = {
        let mut d = tag.hash1();
        d.update(msg);
        RistrettoPoint::from_hash(d)
    };

    // σᵢ := A₀ * A₁ⁱ. See note in the sign function about the i+1 here
    let sigma: Vec<RistrettoPoint> = {
        let mut vals = Vec::new();
        for i in 0..ring_size {
            let s = Scalar::from((i + 1) as u64);
            let aa1i = &s * &aa1;
            vals.push(&aa0 + &aa1i);
        }

        vals
    };

    (aa0, sigma)
}

/// Sign a message under the given tag with the given private key.
///
/// Example:
///
/// ```
/// # fn main() {
/// use fujisaki_ringsig::{gen_keypair, sign, verify, Tag};
/// # let mut rng = rand::thread_rng();
///
/// let msg = b"ready for the chumps on the wall";
/// let issue = b"testcase 12346".to_vec();
///
/// let (my_privkey, pubkey1) = gen_keypair(&mut rng);
/// let (_, pubkey2) = gen_keypair(&mut rng);
/// let (_, pubkey3) = gen_keypair(&mut rng);
///
/// let pubkeys = vec![pubkey1, pubkey2, pubkey3];
/// let tag = Tag {
///     issue,
///     pubkeys,
/// };
///
/// let sig = sign(&mut rng, &*msg, &tag, &my_privkey);
/// assert!(verify(&*msg, &tag, &sig));
/// # }
pub fn sign<R: RngCore + CryptoRng>(
    rng: &mut R,
    msg: &[u8],
    tag: &Tag,
    privkey: &PrivateKey,
) -> Signature {
    // Make sure the ring size isn't bigger than a u64
    let ring_size = tag.pubkeys.len();
    if u64::try_from(ring_size).is_err() {
        panic!("number of pubkeys must be less than 2^64");
    }

    // TODO: This is not constant time
    let mut privkey_idx: Option<usize> = None;
    for (i, pubkey) in tag.pubkeys.iter().enumerate() {
        if pubkey.0 == privkey.1 {
            privkey_idx = Some(i);
        }
    }
    let privkey_idx = privkey_idx.expect("Could not find private key position in ring");

    // h := H(L)
    let h = RistrettoPoint::from_hash(tag.hash0());
    let mut sigma: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); ring_size];
    sigma[privkey_idx] = &privkey.0 * &h;

    // A₀ := H'(L, m)
    let aa0 = {
        let mut d = tag.hash1();
        d.update(msg);
        RistrettoPoint::from_hash(d)
    };

    // A₁ := (j+1)^{-1} * (σⱼ - A₀)
    let aa1 = {
        let t = &sigma[privkey_idx] - &aa0;
        // sigma is indexed by zero but the paper assumes it is indexed at 1. We can keep it
        // indexed at zero, but we have to calculate 1/(i+1) instead of 1/i, otherwise we might
        // divide by 0
        let s = Scalar::from((privkey_idx + 1) as u64);
        let sinv = s.invert();
        &sinv * &t
    };

    // σᵢ := A₀ * A₁^{i+1}. Same reasoning for the +1 applies here.
    for i in (0..ring_size).filter(|&j| j != privkey_idx) {
        let s = Scalar::from((i + 1) as u64);
        let aa1i = &s * &aa1;
        sigma[i] = &aa0 + &aa1i;
    }

    // Signature values
    let mut c: Vec<Scalar> = vec![Scalar::zero(); ring_size];
    let mut z: Vec<Scalar> = vec![Scalar::zero(); ring_size];

    // Temp values
    let mut a: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); ring_size];
    let mut b: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); ring_size];

    let w = Scalar::random(rng);

    // aⱼ := wⱼG,  bⱼ := wⱼh
    a[privkey_idx] = &w * &RISTRETTO_BASEPOINT_POINT;
    b[privkey_idx] = &w * &h;

    for i in (0..ring_size).filter(|&j| j != privkey_idx) {
        c[i] = Scalar::random(rng);
        z[i] = Scalar::random(rng);

        // aᵢ := zᵢG * cᵢyᵢ,  bᵢ := zᵢh + cᵢσᵢ
        a[i] = {
            let gzi = &z[i] * &RISTRETTO_BASEPOINT_POINT;
            let yici = &c[i] * &tag.pubkeys[i].0;
            &gzi + &yici
        };
        b[i] = {
            let hzi = &z[i] * &h;
            let sici = &c[i] * &sigma[i];
            &hzi + &sici
        };
    }

    // c := H''(L, A₀, A₁, {aᵢ}, {bᵢ})
    let cc = {
        let mut d = tag.hash2();
        let aa0c = aa0.compress();
        let aa1c = aa1.compress();
        d.update(aa0c.as_bytes());
        d.update(aa1c.as_bytes());

        for ai in a.iter() {
            let aic = ai.compress();
            d.update(aic.as_bytes());
        }
        for bi in b.iter() {
            let bic = bi.compress();
            d.update(bic.as_bytes());
        }

        Scalar::from_hash(d)
    };

    // cⱼ := c - Σ_{i ≠ j} cᵢ
    c[privkey_idx] = {
        let sum = c
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != privkey_idx)
            .fold(Scalar::zero(), |acc, (_, v)| &acc + v);
        &cc - &sum
    };

    // zⱼ := wⱼ - cⱼxⱼ
    z[privkey_idx] = {
        let cixi = &c[privkey_idx] * &privkey.0;
        &w - &cixi
    };

    Signature {
        aa1: aa1,
        cs: c,
        zs: z,
    }
}

/// Verify a message against a given signature under a given tag. See `sign` for example usage.
pub fn verify(msg: &[u8], tag: &Tag, sig: &Signature) -> bool {
    let c = &sig.cs;
    let z = &sig.zs;
    let aa1 = sig.aa1; // A₁

    // h := H(L)
    let h = RistrettoPoint::from_hash(tag.hash0());

    let (aa0, sigma) = compute_sigma(msg, tag, sig);

    // aᵢ := zᵢG * cᵢyᵢ
    let a: Vec<RistrettoPoint> = {
        let mut vals = Vec::new();
        for (zi, (pubi, ci)) in z.iter().zip(tag.pubkeys.iter().zip(c.iter())) {
            let gzi = zi * &RISTRETTO_BASEPOINT_POINT;
            let yici = ci * &pubi.0;
            vals.push(&gzi + &yici);
        }

        vals
    };

    // bᵢ := zᵢh + cᵢσᵢ
    let b: Vec<RistrettoPoint> = {
        let mut vals = Vec::new();
        for (zi, (sigmai, ci)) in z.iter().zip(sigma.iter().zip(c.iter())) {
            let hzi = zi * &h;
            let sici = ci * sigmai;
            vals.push(&hzi + &sici)
        }

        vals
    };

    // c := H''(L, A₀, A₁, {aᵢ}, {bᵢ})
    let cc = {
        let mut d = tag.hash2();
        let aa0c = aa0.compress();
        let aa1c = aa1.compress();
        d.update(aa0c.as_bytes());
        d.update(aa1c.as_bytes());

        for ai in a.iter() {
            let aic = ai.compress();
            d.update(aic.as_bytes());
        }
        for bi in b.iter() {
            let bic = bi.compress();
            d.update(bic.as_bytes());
        }

        Scalar::from_hash(d)
    };

    let sum = c.iter().fold(Scalar::zero(), |acc, v| &acc + v);

    // c == Σcᵢ
    sum == cc
}

#[cfg(test)]
mod test {
    use super::{sign, verify};
    use crate::{
        key::gen_keypair,
        test_utils::{rand_ctx, remove_rand_privkey, Context},
    };

    use rand::{self, Rng};

    // Make sure that every signature verifies
    #[test]
    fn test_sig_correctness() {
        let mut rng = rand::thread_rng();

        let Context {
            msg,
            tag,
            mut keypairs,
        } = rand_ctx(&mut rng, 1);
        let privkey = remove_rand_privkey(&mut rng, &mut keypairs);

        let sig = sign(&mut rng, &msg, &tag, &privkey);
        assert!(verify(&msg, &tag, &sig));
    }

    // Make sure doing the same signature twice doesn't result in the same output
    #[test]
    fn test_sig_nondeterminism() {
        let mut rng = rand::thread_rng();

        let Context {
            msg,
            tag,
            mut keypairs,
        } = rand_ctx(&mut rng, 1);
        let privkey = remove_rand_privkey(&mut rng, &mut keypairs);

        let sig1 = sign(&mut rng, &msg, &tag, &privkey);
        let sig2 = sign(&mut rng, &msg, &tag, &privkey);

        assert!(sig1 != sig2);
    }

    // Make sure that changing the message results in an invalid sig
    #[test]
    fn test_sig_msg_linkage() {
        let mut rng = rand::thread_rng();

        let Context {
            msg,
            tag,
            mut keypairs,
        } = rand_ctx(&mut rng, 1);
        let privkey = remove_rand_privkey(&mut rng, &mut keypairs);
        let sig = sign(&mut rng, &msg, &tag, &privkey);

        // Check that changing a byte of the message invalidates the signature
        let mut bad_msg = msg.clone();
        let byte_idx = rng.gen_range(0, msg.len());
        // Flip the bits of one byte of the message;
        bad_msg[byte_idx] = !bad_msg[byte_idx];
        assert!(!verify(&*bad_msg, &tag, &sig));
    }

    // Make sure that changing the tag results in an invalid sig
    #[test]
    fn test_sig_tag_linkage() {
        let mut rng = rand::thread_rng();

        let Context {
            msg,
            tag,
            mut keypairs,
        } = rand_ctx(&mut rng, 1);
        let privkey = remove_rand_privkey(&mut rng, &mut keypairs);
        let sig = sign(&mut rng, &msg, &tag, &privkey);

        // Check that changing a pubkey in the tag invalidates the signature
        let mut bad_tag = tag.clone();
        let (_, new_pubkey) = gen_keypair(&mut rng);
        let pubkey_idx = rng.gen_range(0, tag.pubkeys.len());
        bad_tag.pubkeys[pubkey_idx] = new_pubkey;
        assert!(!verify(&msg, &bad_tag, &sig));

        // Check that changing the issue invalidates the signature
        let mut bad_tag = tag.clone();
        let byte_idx = rng.gen_range(0, tag.issue.len());
        // Flip the bits of one byte of the issue string
        bad_tag.issue[byte_idx] = !bad_tag.issue[byte_idx];
        assert!(!verify(&msg, &bad_tag, &sig));
    }
}
