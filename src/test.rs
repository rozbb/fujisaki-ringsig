use sig::{Tag};
use key::{KeyPair, PublicKey};
use rand::{self, Rng};

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
    let msg_len = rng.gen_range(0, 50);
    let mut msg = vec![0u8; msg_len];
    rng.fill_bytes(&mut msg);
    let issue: u64 = rng.gen();
    let ring_size: usize = rng.gen_range(min_ring_size, 50);
    //let ring_size = 1;

    //println!("ring_size == {}", ring_size);
    //println!("issue == {}", issue);

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
