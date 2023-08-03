use num_bigint::BigUint;

fn pad16(x: usize) -> Vec<u8> {
    vec![0; 16 - (x % 16)]
}

pub struct Poly1305 {
    r: BigUint,
    s: BigUint,
    p: BigUint,
    acc: BigUint,
    items: Vec<u8>,
}

impl Poly1305 {
    pub fn new(key: Vec<u8>) -> Self {
        let mut r = BigUint::from_bytes_le(&key[..16]);
        let s = BigUint::from_bytes_le(&key[16..]);

        r &= BigUint::parse_bytes(b"0ffffffc0ffffffc0ffffffc0fffffff", 16).unwrap();

        Poly1305 {
            r,
            s,
            p: BigUint::parse_bytes(b"3fffffffffffffffffffffffffffffffb", 16).unwrap(),
            acc: 0u8.into(),
            items: Vec::new(),
        }
    }

    pub fn block(&mut self, msg: &[u8]) {
        let mut n = BigUint::from_bytes_le(msg);
        n.set_bit((msg.len() * 8) as u64, true);
        self.acc += n;
        self.acc *= &self.r;
        self.acc %= &self.p;
    }

    pub fn update(&mut self, msg: &[u8], pad: bool) {
        self.items.extend_from_slice(msg);

        if pad {
            self.items.append(&mut pad16(msg.len()));
        }
    }

    pub fn process(&mut self) {
        for chunk in self.items.clone().chunks(16) {
            self.block(chunk);
        }
    }

    pub fn tag(&mut self) -> Vec<u8> {
        self.process();

        let result = &self.acc + &self.s;
        let mut bytes = result.to_bytes_le();
        bytes.resize(16, 0);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poly1305_test() {
        let key: Vec<u8> = vec![
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];

        let expected_output: [u8; 16] = [
            168, 6, 29, 193, 48, 81, 54, 198, 194, 43, 139, 175, 12, 1, 39, 169,
        ];
        let mut mac = Poly1305::new(key);

        mac.update(b"Cryptographic Forum Research Group", false);

        let result = mac.tag();
        assert_eq!(result.as_slice(), expected_output);
    }

    #[test]
    fn poly1305_block() {
        let key: Vec<u8> = vec![
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];

        let expected_output: [u8; 16] = [
            168, 6, 29, 193, 48, 81, 54, 198, 194, 43, 139, 175, 12, 1, 39, 169,
        ];
        let mut mac = Poly1305::new(key);

        mac.block(b"Cryptographic Fo");
        mac.block(b"rum Research Gro");
        mac.block(b"up");

        let result = mac.tag();
        assert_eq!(result.as_slice(), expected_output);
    }
}
