// code and tests adapted from http://cr.yp.to/highspeed/naclcrypto-20090310.pdf

use crate::util::randbytes;
use pyo3::prelude::*;
use rug::ops::Pow;
use rug::Integer;
use std::sync::LazyLock;

static P: LazyLock<Integer> = LazyLock::new(|| Integer::from(2).pow(255) - Integer::from(19));

fn add(n: (Integer, Integer), m: (Integer, Integer), d: (Integer, Integer)) -> (Integer, Integer) {
    let (xn, zn) = n;
    let (xm, zm) = m;
    let (xd, zd) = d;

    let x = (zd << 2) * (Integer::from(&xm * &xn) - Integer::from(&zm * &zn)).pow(2);
    let z = (xd << 2) * (xm * zn - &zm * &xn).pow(2);

    (Integer::from(x % &*P), Integer::from(z % &*P))
}

fn double(n: (Integer, Integer)) -> (Integer, Integer) {
    let (xn, zn) = n;

    let xn2 = xn.clone().pow(2);
    let zn2 = zn.clone().pow(2);

    let x = (xn2.clone() - zn2.clone()).pow(2);
    let z = (Integer::from(4) * Integer::from(&xn * &zn)) * (xn2 + 486662 * (xn * zn) + zn2);
    (Integer::from(x % &*P), Integer::from(z % &*P))
}

fn f(
    m: Integer,
    one: (Integer, Integer),
    two: (Integer, Integer),
) -> ((Integer, Integer), (Integer, Integer)) {
    if m.clone() == 1 {
        return (one, two);
    }

    let (pm, pm1) = f(m.clone() / 2, one.clone(), two);

    if Integer::from(&m & 1) != 0 {
        return (add(pm, pm1.clone(), one), double(pm1));
    }

    (double(pm.clone()), add(pm, pm1, one))
}

fn inv(x: Integer) -> Integer {
    x.secure_pow_mod(&Integer::from(&*P - 2), &*P)
}

fn curve25519(base: Integer, n: Integer) -> Integer {
    let one = (base, Integer::from(1));
    let two = double(one.clone());
    let ((x, z), _) = f(n, one, two);

    (x * inv(z)) % &*P
}

fn clamp(mut n: Integer) -> Integer {
    n &= -8;
    let m: Integer = Integer::from(128u8) << 8u32 * 31u32;
    n &= !m;
    n |= Integer::from(64u8) << 8 * 31;

    n
}

fn unpack(s: &[u8]) -> Integer {
    let mut n = Integer::from(0);
    for i in 0..32 {
        n += Integer::from(s[i]) << (8 * i);
    }
    n
}

fn pack(n: Integer) -> [u8; 32] {
    let mut s = [0u8; 32];
    for i in 0..32 {
        s[i] = (n.clone() >> (8 * i)).to_u8_wrapping();
    }
    s
}

fn crypto_scalarmult_curve25519_base(n: &[u8]) -> Vec<u8> {
    let n = clamp(unpack(n));
    pack(curve25519(Integer::from(9), n)).to_vec()
}

fn crypto_scalarmult_curve25519(n: &[u8], p: &[u8]) -> Vec<u8> {
    let n = clamp(unpack(n));
    let p = unpack(p);
    pack(curve25519(p, n)).to_vec()
}

#[pyfunction]
fn keygen() -> Vec<u8> {
    let mut bytes = randbytes::<4>();
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;

    bytes.to_vec()
}

#[pyclass]
struct X25519 {
    key: Vec<u8>,
}

#[pymethods]
impl X25519 {
    #[new]
    pub fn new(key: Vec<u8>) -> Self {
        X25519 { key }
    }

    #[getter]
    pub fn get_public_key(&self) -> Vec<u8> {
        crypto_scalarmult_curve25519_base(&self.key)
    }

    pub fn shared(&self, other: &[u8]) -> Vec<u8> {
        crypto_scalarmult_curve25519(&self.key, other)
    }
}

#[pymodule]
pub fn dh(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<X25519>()?;
    m.add_wrapped(wrap_pyfunction!(keygen))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_1() {
        let sk = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];

        let pk: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];

        assert_eq!(pk.as_slice(), crypto_scalarmult_curve25519_base(&sk));
    }

    #[test]
    fn test_public_2() {
        let sk = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];

        let pk = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];

        assert_eq!(pk.as_slice(), crypto_scalarmult_curve25519_base(&sk),);
    }

    #[test]
    fn test_key_exchange() {
        let alicesk = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];

        let bobpk = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];

        let shared = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];

        assert_eq!(
            shared.as_slice(),
            crypto_scalarmult_curve25519(&alicesk, &bobpk),
        );
    }
}
