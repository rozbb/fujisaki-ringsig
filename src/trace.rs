use key::PublicKey;
use sig::{compute_sigma, Signature, Tag};

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
/// use fujisaki_ringsig::{sign, trace, KeyPair, Tag, Trace};
///
/// let msg1 = b"cooking MCs like a pound of bacon";
/// let msg2 = b"rollin' in my 5.0";
/// let issue_number: usize = 54321;
///
/// let kp1 = KeyPair::generate();
/// let kp2 = KeyPair::generate();
/// let kp3 = KeyPair::generate();
///
/// let my_kp = kp1;
/// let pubkeys = vec![my_kp.pubkey.clone(), kp2.pubkey, kp3.pubkey];
/// let tag = Tag {
///     issue: issue_number,
///     pubkeys: pubkeys,
/// };
///
/// let sig1 = sign(&*msg1, &tag, &my_kp.privkey);
/// let sig2 = sign(&*msg2, &tag, &my_kp.privkey);
///
/// assert_eq!(trace(&*msg1, &sig1, &*msg2, &sig2, &tag), Trace::Revealed(&my_kp.pubkey));
/// # }
pub fn trace<'a>(msg1: &[u8], sig1: &Signature, msg2: &[u8], sig2: &Signature, tag: &'a Tag)
        -> Trace<'a> {
    let (_, sigma1) = compute_sigma(msg1, tag, sig1);
    let (_, sigma2) = compute_sigma(msg2, tag, sig2);

    let intersecting_points = (0..(tag.pubkeys.len())).filter(|&i| sigma1[i] == sigma2[i])
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
    use test::{setup, Context};
    use sig::sign;
    use rand::{self, Rng};

    #[test]
    fn test_trace_indep() {
        let mut rng = rand::thread_rng();
        let Context { msg, tag, mut keypairs } = setup();

        // Pick two distinct privkeys to sign with
        let privkey1 = {
            let privkey_idx = rng.gen_range(0, keypairs.len());
            keypairs.remove(privkey_idx).privkey
        };
        let privkey2 = {
            let privkey_idx = rng.gen_range(0, keypairs.len());
            keypairs.remove(privkey_idx).privkey
        };

        // Sign the same message with distinct privkeys
        let sig1 = sign(&msg, &tag, &privkey1);
        let sig2 = sign(&msg, &tag, &privkey2);
        assert_eq!(trace(&msg, &sig1, &msg, &sig2, &tag), Trace::Indep);
    }

    #[test]
    fn test_trace_linked() {
        let Context { msg, tag, mut keypairs } = setup();

        // Pick just one privkey to sign with
        let privkey = {
            let mut rng = rand::thread_rng();
            let privkey_idx = rng.gen_range(0, keypairs.len());
            keypairs.remove(privkey_idx).privkey
        };

        // Sign the same message with the same privkey
        let sig1 = sign(&msg, &tag, &privkey);
        let sig2 = sign(&msg, &tag, &privkey);

        assert_eq!(trace(&msg, &sig1, &msg, &sig2, &tag), Trace::Linked);
    }

    #[test]
    fn test_trace_revealed() {
        // Get two messages to sign
        let (msg1, tag, mut keypairs) = {
            let ctx = setup();
            (ctx.msg, ctx.tag, ctx.keypairs)
        };
        let msg2 = {
            let ctx = setup();
            ctx.msg
        };

        // Pick just one privkey to sign with
        let kp = {
            let mut rng = rand::thread_rng();
            let privkey_idx = rng.gen_range(0, keypairs.len());
            keypairs.remove(privkey_idx)
        };

        // Sign distinct messages with the same privkey
        let sig1 = sign(&msg1, &tag, &kp.privkey);
        let sig2 = sign(&msg2, &tag, &kp.privkey);

        assert_eq!(trace(&msg1, &sig1, &msg2, &sig2, &tag), Trace::Revealed(&kp.pubkey));
    }
}
