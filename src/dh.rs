use crypto_bigint::{rand_core::OsRng, Encoding, NonZero, Random, Wrapping, U2048, U256};
use pyo3::prelude::*;

use std::borrow::Cow;

const PRIME: Wrapping<U2048> = Wrapping(U2048::from_le_hex(
    "\
        FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
        29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
        EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
        E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
        EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
        C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
        83655D23DCA3AD961C62F356208552BB9ED529077096966D\
        670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
        E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
        DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
        15728E5A8AACAA68FFFFFFFFFFFFFFFF\
    ",
));

fn modpow(mut b: Wrapping<U2048>, mut e: U256, mut m: Wrapping<U2048>) -> Wrapping<U2048> {
    let mut r = Wrapping(U2048::ONE);

    let m2 = NonZero::new(m.0.clone()).unwrap();

    b %= &m2;

    while e > U256::ZERO {
        if e & U256::ONE == U256::ONE {
            r *= &b;
        }

        b *= &m;
        b %= &m2;
        e >>= 1;
    }

    r
}

#[pyclass]
pub struct DiffieHellman {
    public_key: Wrapping<U2048>,
    private_key: U256,
}

#[pymethods]
impl DiffieHellman {
    #[new]
    fn new() -> DiffieHellman {
        let private_key = U256::random(&mut OsRng);
        let generator = Wrapping(U2048::from(2u8));

        let public_key = modpow(generator, private_key, PRIME);

        DiffieHellman {
            public_key,
            private_key,
        }
    }

    #[getter]
    fn get_public_key(&self) -> Cow<[u8]> {
        self.public_key.0.to_le_bytes().to_vec().into()
    }

    fn shared_key(&self, other: Vec<u8>) -> Cow<[u8]> {
        let public_key = Wrapping(U2048::from_le_slice(&other));
        modpow(public_key, self.private_key.clone(), PRIME)
            .0
            .to_le_bytes()
            .to_vec()
            .into()
    }
}

#[pymodule]
pub fn dh(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<DiffieHellman>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh() {
        let alice = DiffieHellman::new();
        let bob = DiffieHellman::new();

        assert_eq!(
            alice.shared_key(bob.get_public_key().to_vec()),
            bob.shared_key(alice.get_public_key().to_vec())
        );
    }
}
