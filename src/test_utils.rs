use sig::{Tag};
use key::{KeyPair, PrivateKey, PublicKey};
use rand::{self, Rng, RngCore};

// Testing context for convenience
pub(crate) struct Context {
    pub msg: Vec<u8>,
    pub tag: Tag,
    pub keypairs: Vec<KeyPair>,
}

// Construct a context for testing
pub(crate) fn setup(min_ring_size: usize) -> Context {
    // Make a random issue number, random ring size, and random message to sign
    let mut rng = rand::thread_rng();
    let msg_len = rng.gen_range(1..50);
    let issue_len = rng.gen_range(1..50);
    let mut msg = vec![0u8; msg_len];
    let mut issue = vec![0u8; issue_len];

    rng.fill_bytes(&mut msg);
    rng.fill_bytes(&mut issue);

    let ring_size: usize = rng.gen_range(min_ring_size..50);

    // Make a bunch of keypairs
    let mut keypairs = Vec::new();
    for _ in 0..ring_size {
        let kp = KeyPair::generate();
        keypairs.push(kp);
    }

    // Clone out just the pubkeys
    let pubkeys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.pubkey.clone()).collect();

    let tag = Tag {
        pubkeys,
        issue,
    };

    Context {
        msg,
        tag,
        keypairs,
    }
}

pub(crate) fn remove_privkey(keypairs: &mut Vec<KeyPair>) -> PrivateKey {
    let mut rng = rand::thread_rng();
    let privkey_idx = rng.gen_range(0..keypairs.len());
    keypairs.remove(privkey_idx).privkey
}
