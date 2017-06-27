use key::{PrivateKey, PublicKey};

use blake2::{Blake2b, Blake2s};
use curve25519_dalek::curve::Identity;
use curve25519_dalek::constants::DECAF_ED25519_BASEPOINT;
use curve25519_dalek::decaf::DecafPoint;
use curve25519_dalek::scalar::Scalar;
use digest::Digest;
use rand::OsRng;

static KEY0: &'static [u8] = b"rustfujisakisuzukihash0";
static KEY1: &'static [u8] = b"rustfujisakisuzukihash1";
static KEY2: &'static [u8] = b"rustfujisakisuzukihash2";

/// A Fujisaki signature. The size of `Signature` scales proportionally with the number of public
/// keys in the ring.
#[derive(Debug, Eq, PartialEq)]
pub struct Signature {
    aa1: DecafPoint,
    cs: Vec<Scalar>,
    zs: Vec<Scalar>,
}

/// Denotes the ring of public keys which are being used for the ring signature, as well as the
/// "issue" number, corresponding to what issue the signature corresponds to (e.g election ID)
#[derive(Debug, Eq, PartialEq)]
pub struct Tag {
    pub pubkeys: Vec<PublicKey>,
    pub issue: u64,
}

impl Tag {
    // Independent elements from a family of hashes. The first two are for hashing onto the curve.
    // The last one is for hashing to a scalar. Accordingly, the first two use digests with 256-bit
    // output and the last uses a digest with 512-bit output.
    fn hash0(&self) -> Blake2s {
        Blake2s::new_keyed(KEY0)
    }

    fn hash1(&self) -> Blake2s {
        Blake2s::new_keyed(KEY1)
    }

    fn hash2(&self) -> Blake2b {
        Blake2b::new_keyed(KEY2)
    }
}

// This routine is common to the verification and trace functions. It returns A₀ and the sigma
// values
pub(crate) fn compute_sigma(msg: &[u8], tag: &Tag, sig: &Signature)
        -> (DecafPoint, Vec<DecafPoint>) {
    let ring_size = tag.pubkeys.len();
    let aa1 = sig.aa1;

    // A₀ := H'(L, m)
    let aa0 = {
        let mut d = tag.hash1();
        d.input(msg);
        DecafPoint::from_hash(d)
    };

    // σᵢ := A₀ * A₁ⁱ. See note in the sign function about the i+1 here
    let sigma: Vec<DecafPoint> = {
        let mut vals = Vec::new();
        for i in 0..ring_size {
            let s = Scalar::from_u64((i+1) as u64);
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
/// use fujisaki_ringsig::{sign, verify, KeyPair, Tag};
///
/// let msg = b"ready for the chumps on the wall";
/// let issue_number: u64 = 12345;
///
/// let kp1 = KeyPair::generate();
/// let kp2 = KeyPair::generate();
/// let kp3 = KeyPair::generate();
///
/// let my_privkey = kp1.privkey;
/// let pubkeys = vec![kp1.pubkey, kp2.pubkey, kp3.pubkey];
/// let tag = Tag {
///     issue: issue_number,
///     pubkeys: pubkeys,
/// };
///
/// let sig = sign(&*msg, &tag, &my_privkey);
/// assert!(verify(&*msg, &tag, &sig));
/// # }
pub fn sign(msg: &[u8], tag: &Tag, privkey: &PrivateKey) -> Signature {
    let ring_size = tag.pubkeys.len();

    // TODO: This is not constant time
    let mut privkey_idx: Option<usize> = None;
    for (i, pubkey) in tag.pubkeys.iter().enumerate() {
        if pubkey.0 == privkey.1 {
            privkey_idx = Some(i);
        }
    }
    let privkey_idx = privkey_idx.expect("Could not find private key position in ring");

    // h := H(L)
    let h = DecafPoint::from_hash(tag.hash0());
    let mut sigma: Vec<DecafPoint> = vec![DecafPoint::identity(); ring_size];
    sigma[privkey_idx] = &privkey.0 * &h;

    // A₀ := H'(L, m)
    let aa0 = {
        let mut d = tag.hash1();
        d.input(msg);
        DecafPoint::from_hash(d)
    };

    // A₁ := i^(-1) * (σⱼ - A₀)
    let aa1 = {
        let t = &sigma[privkey_idx] - &aa0;
        // sigma is indexed by zero but the paper assumes it is indexed at 1. We can keep it
        // indexed at zero, but we have to calculate 1/(i+1) instead of 1/i, otherwise we might
        // divide by 0
        let s = Scalar::from_u64((privkey_idx+1) as u64);
        let sinv = s.invert();
        &sinv * &t
    };

    // σᵢ := A₀ * A₁^{i+1}. Same reasoning for the +1 applies here.
    for i in (0..ring_size).filter(|&j| j != privkey_idx) {
        let s = Scalar::from_u64((i+1) as u64);
        let aa1i = &s * &aa1;
        sigma[i] = &aa0 + &aa1i;
    }

    // Signature values
    let mut c: Vec<Scalar> = vec![Scalar::zero(); ring_size];
    let mut z: Vec<Scalar> = vec![Scalar::zero(); ring_size];

    // Temp values
    let mut a: Vec<DecafPoint> = vec![DecafPoint::identity(); ring_size];
    let mut b: Vec<DecafPoint> = vec![DecafPoint::identity(); ring_size];

    let mut csprng = OsRng::new().expect("Could not instantiate CSPRNG");
    let w = Scalar::random(&mut csprng);

    // aⱼ := wⱼG,  bⱼ := wⱼh
    a[privkey_idx] = &w * &DECAF_ED25519_BASEPOINT;
    b[privkey_idx] = &w * &h;

    for i in (0..ring_size).filter(|&j| j != privkey_idx) {
        c[i] = Scalar::random(&mut csprng);
        z[i] = Scalar::random(&mut csprng);

        // aᵢ := zᵢG * cᵢyᵢ,  bᵢ := zᵢh + cᵢσᵢ
        a[i] = {
            let gzi = &z[i] * &DECAF_ED25519_BASEPOINT;
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
        d.input(aa0c.as_bytes());
        d.input(aa1c.as_bytes());

        for ai in a.iter() {
            let aic = ai.compress();
            d.input(aic.as_bytes());
        }
        for bi in b.iter() {
            let bic = bi.compress();
            d.input(bic.as_bytes());
        }

        Scalar::from_hash(d)
    };

    // cⱼ := c - \sum_{i ‡ j} cᵢ
    c[privkey_idx] = {
        let sum = c.iter()
                   .enumerate()
                   .filter(|&(i, _)| i != privkey_idx)
                   .fold(Scalar::zero(), |acc, (_, v)| &acc + &v);
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
    let h = DecafPoint::from_hash(tag.hash0());

    let (aa0, sigma) = compute_sigma(msg, tag, sig);

    // aᵢ := zᵢG * cᵢyᵢ
    let a: Vec<DecafPoint> = {
        let mut vals = Vec::new();
        for (zi, (pubi, ci)) in z.iter().zip(tag.pubkeys.iter().zip(c.iter())) {
            let gzi = zi * &DECAF_ED25519_BASEPOINT;
            let yici = ci * &pubi.0;
            vals.push(&gzi + &yici);
        }

        vals
    };

    // bᵢ := zᵢh + cᵢσᵢ
    let b: Vec<DecafPoint> = {
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
        d.input(aa0c.as_bytes());
        d.input(aa1c.as_bytes());

        for ai in a.iter() {
            let aic = ai.compress();
            d.input(aic.as_bytes());
        }
        for bi in b.iter() {
            let bic = bi.compress();
            d.input(bic.as_bytes());
        }

        Scalar::from_hash(d)
    };

    let sum = c.iter().fold(Scalar::zero(), |acc, v| &acc + &v);

    // c == Σcᵢ
    sum == cc
}

#[cfg(test)]
mod test {
    use super::{sign, verify};
    use test::{setup, Context};
    use rand::{self, Rng};

    // Make sure that every signature verifies, and changing the msg makes verification fail
    #[test]
    fn test_sig_correctness() {
        let Context { msg, tag, mut keypairs } = setup(1);
        // Pick one privkey to sign with
        let privkey = {
            let mut rng = rand::thread_rng();
            let privkey_idx = rng.gen_range(0, keypairs.len());
            keypairs.remove(privkey_idx).privkey
        };

        let sig = sign(&msg, &tag, &privkey);
        assert!(verify(&msg, &tag, &sig));

        let bad_msg = b"yellow submarine";
        assert!(!verify(&*bad_msg, &tag, &sig));
    }

    // Make sure doing the same signature twice doesn't result in the same output
    #[test]
    fn test_sig_nondeterminism() {
        let Context { msg, tag, mut keypairs } = setup(1);

        // Pick just one privkey to sign with
        let privkey = {
            let mut rng = rand::thread_rng();
            let privkey_idx = rng.gen_range(0, keypairs.len());
            keypairs.remove(privkey_idx).privkey
        };

        let sig1 = sign(&msg, &tag, &privkey);
        let sig2 = sign(&msg, &tag, &privkey);

        assert!(sig1 != sig2);
    }
}
