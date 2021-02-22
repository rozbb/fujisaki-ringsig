use crate::{
    key::PublicKey,
    prelude::*,
    sig::{compute_sigma, Signature, Tag},
};

/// Encodes the relationship of two signatures
#[derive(Debug, Eq, PartialEq)]
pub enum Trace<'a> {
    /// `Indep` indicates that the two given signatures were constructed with different private
    /// keys.
    Indep,

    /// `Linked` indicates that the same private key was used to sign the same message under the
    /// same tag. This does not reveal which key performed the double-signature.
    Linked,

    /// The same key was used to sign distinct messages under the same tag. `Revealed(p)` reveals
    /// that pubkey.
    Revealed(&'a PublicKey),
}

/// Get a `Trace` object representing the relationship between the two provided signatures and
/// messages.
///
/// Example:
///
/// ```
/// # fn main() {
/// use fujisaki_ringsig::{gen_keypair, sign, trace, Tag, Trace};
/// # let mut rng = rand::thread_rng();
///
/// let msg1 = b"cooking MCs like a pound of bacon";
/// let msg2 = msg1;
/// let issue = b"testcase 54321".to_vec();
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
/// let sig1 = sign(&mut rng, &*msg1, &tag, &my_privkey);
/// let sig2 = sign(&mut rng, &*msg2, &tag, &my_privkey);
///
/// assert_eq!(trace(&*msg1, &sig1, &*msg2, &sig2, &tag), Trace::Linked);
/// # }
pub fn trace<'a>(
    msg1: &[u8],
    sig1: &Signature,
    msg2: &[u8],
    sig2: &Signature,
    tag: &'a Tag,
) -> Trace<'a> {
    let (_, sigma1) = compute_sigma(msg1, tag, sig1);
    let (_, sigma2) = compute_sigma(msg2, tag, sig2);

    let intersecting_points = (0..(tag.pubkeys.len()))
        .filter(|&i| sigma1[i] == sigma2[i])
        .collect::<Vec<usize>>();
    match intersecting_points.len() {
        // The lines do not intersect. They are independent.
        0 => Trace::Indep,
        // The lines intersect at exactly one point. This is the pubkey of the double-signer.
        1 => Trace::Revealed(&tag.pubkeys[intersecting_points[0]]),
        // The lines intersect at more than one point. So they must intersect everywhere.
        _ => Trace::Linked,
    }
}

#[cfg(test)]
mod test {
    use super::{trace, Trace};

    use crate::sig::sign;
    use crate::test_utils::{rand_ctx, Context};

    use rand::{self, Rng};

    #[test]
    fn test_trace_indep() {
        let mut rng = rand::thread_rng();

        // Need a context with at least 2 keypairs in it
        let Context {
            msg,
            tag,
            mut keypairs,
        } = rand_ctx(&mut rng, 2);

        // Pick two distinct privkeys to sign with
        let (privkey1, _) = {
            let privkey_idx = rng.gen_range(0, keypairs.len());
            keypairs.remove(privkey_idx)
        };
        let (privkey2, _) = {
            let privkey_idx = rng.gen_range(0, keypairs.len());
            keypairs.remove(privkey_idx)
        };

        // Sign the same message with distinct privkeys
        let sig1 = sign(&mut rng, &msg, &tag, &privkey1);
        let sig2 = sign(&mut rng, &msg, &tag, &privkey2);
        assert_eq!(trace(&msg, &sig1, &msg, &sig2, &tag), Trace::Indep);
    }

    #[test]
    fn test_trace_linked() {
        let mut rng = rand::thread_rng();

        // Need a context with at least 2 keypairs in it, otherwise there is only one possible
        // signer, and the result of a trace is Revealed instead of Linked
        let Context {
            msg,
            tag,
            mut keypairs,
        } = rand_ctx(&mut rng, 2);

        // Pick just one privkey to sign with
        let (privkey, _) = {
            let privkey_idx = rng.gen_range(0, keypairs.len());
            keypairs.remove(privkey_idx)
        };

        // Sign the same message with the same privkey
        let sig1 = sign(&mut rng, &msg, &tag, &privkey);
        let sig2 = sign(&mut rng, &msg, &tag, &privkey);

        assert_eq!(trace(&msg, &sig1, &msg, &sig2, &tag), Trace::Linked);
    }

    #[test]
    fn test_trace_revealed() {
        let mut rng = rand::thread_rng();

        // Get two messages to sign
        let Context {
            msg: msg1,
            tag,
            mut keypairs,
        } = rand_ctx(&mut rng, 1);
        let Context { msg: msg2, .. } = rand_ctx(&mut rng, 1);

        // Pick just one privkey to sign with
        let (my_privkey, my_pubkey) = {
            let privkey_idx = rng.gen_range(0, keypairs.len());
            keypairs.remove(privkey_idx)
        };

        // Sign distinct messages with the same privkey
        let sig1 = sign(&mut rng, &msg1, &tag, &my_privkey);
        let sig2 = sign(&mut rng, &msg2, &tag, &my_privkey);

        assert_eq!(
            trace(&msg1, &sig1, &msg2, &sig2, &tag),
            Trace::Revealed(&my_pubkey)
        );
    }
}
