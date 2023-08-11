extern "C" {
    fn poly1305_auth(mac: *mut u8, m: *mut u8, bytes: isize, key: *mut u8);
    fn poly1305_verify(mac1: *const u8, mac2: *const u8) -> u32;
}

fn pad16(length: usize) -> Vec<u8> {
    vec![0u8; 16 - (length % 16)]
}

pub struct Poly1305 {
    key: Vec<u8>,
    items: Vec<u8>,
}

impl Poly1305 {
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key,
            items: Vec::new(),
        }
    }

    pub fn update(&mut self, items: &[u8], pad: bool) {
        self.items.extend_from_slice(items);

        if pad {
            self.items.append(&mut pad16(items.len()));
        }
    }

    pub fn tag(&self) -> Vec<u8> {
        let mut mac: [u8; 16] = [0; 16];
        unsafe {
            poly1305_auth(
                mac.as_mut_ptr(),
                self.items.clone().as_mut_ptr(),
                self.items.len() as isize,
                self.key.clone().as_mut_ptr(),
            );
        }
        mac.to_vec()
    }

    pub fn verify(&self, other: &[u8]) -> bool {
        unsafe { poly1305_verify(self.tag().as_ptr(), other.as_ptr()) == 1 }
    }
}
