use rand::{thread_rng, RngCore};

pub(crate) fn randbytes<const BYTES: usize>() -> Vec<u8> {
    let mut bytes = vec![0u8; BYTES];

    thread_rng().fill_bytes(&mut bytes);

    bytes
}
