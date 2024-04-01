use core::mem::MaybeUninit;

use log::info;
use rsa::{
    rand_core::{CryptoRng, RngCore},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};

use crate::cyhal_trng::{cyhal_trng_free, cyhal_trng_generate, cyhal_trng_init, cyhal_trng_t};

struct Rng {
    trng: cyhal_trng_t,
}

impl Rng {
    pub fn new() -> Self {
        let mut rng = Self {
            trng: unsafe { MaybeUninit::zeroed().assume_init() },
        };
        assert!(unsafe { cyhal_trng_init(&mut rng.trng) } == 0);
        rng
    }
}

impl Drop for Rng {
    fn drop(&mut self) {
        unsafe { cyhal_trng_free(&mut self.trng) };
    }
}

impl CryptoRng for Rng {}

impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        unsafe { cyhal_trng_generate(&mut self.trng) }
    }

    fn next_u64(&mut self) -> u64 {
        (self.next_u32() as u64) << 32 | self.next_u32() as u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = self.next_u32() as u8;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

pub struct Crypto {}

impl Crypto {
    pub fn new() -> Self {
        Self {}
    }

    pub fn rsa_keygen(&mut self) {
        let mut rng = Rng::new();
        let privkey =
            RsaPrivateKey::new(&mut rng, 512).expect("Failed to generate RSA private key.");
        info!("RSA private key: {:x?}", privkey);
        let pubkey = RsaPublicKey::from(&privkey);

        let result = pubkey
            .encrypt(&mut rng, Pkcs1v15Encrypt, b"Hello, World!")
            .unwrap();
        info!("RSA encrypted: {:x?}", result);

        let result = privkey.decrypt(Pkcs1v15Encrypt, &result).unwrap();
        info!("RSA decrypted: {:x?}", result);
    }
}
