#[cfg(target_os = "none")]
use core::mem::MaybeUninit;

use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes128,
};
use ctr::Ctr128BE;
use log::{debug, info};
#[cfg(target_os = "none")]
use rsa::rand_core::CryptoRng;
use rsa::{
    rand_core::RngCore, traits::PublicKeyParts, BigUint, Pkcs1v15Encrypt, RsaPrivateKey,
    RsaPublicKey,
};

#[cfg(not(target_os = "none"))]
use rand;

#[cfg(target_os = "none")]
use crate::{
    cyhal_trng::{cyhal_trng_free, cyhal_trng_generate, cyhal_trng_init, cyhal_trng_t},
    http::{WifiConnectionError, WifiConnectionManager},
};

#[cfg(not(target_os = "none"))]
type Error = reqwest::Error;
#[cfg(target_os = "none")]
type Error = WifiConnectionError;

#[cfg(target_os = "none")]
pub(crate) static mut BUFFER: [u8; 4096] = [0; 4096];

#[cfg(target_os = "none")]
struct Rng {
    trng: cyhal_trng_t,
}

#[cfg(target_os = "none")]
impl Rng {
    pub fn new() -> Self {
        let mut rng = Self {
            trng: unsafe { MaybeUninit::zeroed().assume_init() },
        };
        assert!(unsafe { cyhal_trng_init(&mut rng.trng) } == 0);
        rng
    }
}

#[cfg(target_os = "none")]
impl Drop for Rng {
    fn drop(&mut self) {
        unsafe { cyhal_trng_free(&mut self.trng) };
    }
}

#[cfg(target_os = "none")]
impl CryptoRng for Rng {}

#[cfg(target_os = "none")]
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

#[derive(Default)]
pub struct Crypto {
    rsa_private_key: Option<RsaPrivateKey>,
    rsa_server_public_key: Option<RsaPublicKey>,
    pub(crate) ctr_instance: Option<Ctr128BE<Aes128>>,
}

impl Crypto {
    #[cfg(target_os = "none")]
    pub fn establish_crypto(
        &mut self,
        server: &mut WifiConnectionManager,
    ) -> Result<(), WifiConnectionError> {
        self.rsa_keygen();
        self.send_public_key(server)?;
        self.get_server_public_key(server)?;
        self.exchange_aes_key(server)?;
        Ok(())
    }
    #[cfg(not(target_os = "none"))]
    pub fn establish_crypto(&mut self) -> Result<(), Error> {
        self.rsa_keygen();
        self.send_public_key()?;
        self.get_server_public_key()?;
        self.exchange_aes_key()?;
        Ok(())
    }

    pub fn rsa_keygen(&mut self) {
        debug!("Crypto::rsa_keygen");

        let private_key = if cfg!(feature = "rsa_keygen") {
            #[cfg(target_os = "none")]
            let mut rng = Rng::new();
            #[cfg(not(target_os = "none"))]
            let mut rng = rand::thread_rng();
            RsaPrivateKey::new(&mut rng, 2048).unwrap()
        } else {
            RsaPrivateKey::from_p_q(
                BigUint::from_slice(&[
                    1424269889, 2787240996, 3159910469, 587006868, 1678786330, 2707170067,
                    3695130652, 1186774184, 3016514461, 1278963338, 583502715, 4138407494,
                    2798313311, 250178598, 4280451139, 196311780, 3526243793, 386251617,
                    3007636879, 351905548, 1600135654, 1644131029, 2963924868, 3945827008,
                    3173893926, 1916033844, 1282349844, 2707474342, 258126534, 2523168899,
                    3776025140, 3883201587,
                ]),
                BigUint::from_slice(&[
                    3879442921, 2820239366, 3157087420, 3507524794, 225218248, 129115924,
                    3066121741, 278452355, 2881299167, 2753403987, 1400998090, 3436476445,
                    139063583, 402340706, 1853993481, 545627023, 665165599, 1447865582, 3083291136,
                    2204183672, 223633613, 1400902721, 3575498304, 2677304750, 1655372974,
                    310263134, 1363830125, 4115261234, 372556404, 1098012183, 1971852395,
                    3289575676,
                ]),
                BigUint::from_slice(&[0x10001]),
            )
            .unwrap()
        };
        self.rsa_private_key = Some(private_key);

        info!(
            "Crypto::rsa_keygen: private_key: {:?}",
            self.rsa_private_key
        );
    }

    #[cfg(target_os = "none")]
    pub fn send_public_key(
        &self,
        server: &mut WifiConnectionManager,
    ) -> Result<(), WifiConnectionError> {
        debug!("Crypto::send_public_key");
        assert!(self.rsa_private_key.is_some());
        let (status_code, ciphertext) = server.http_client_send(
            "/crypto/rsa/client_modulus",
            Some(&self.rsa_private_key.as_ref().unwrap().n().to_bytes_be()),
        )?;
        if status_code != 200 {
            return Err(WifiConnectionError::CyRsltHttpClientErrorInvalidResponse);
        }
        let plaintext = self
            .rsa_private_key
            .as_ref()
            .unwrap()
            .decrypt(Pkcs1v15Encrypt, ciphertext)
            .or(Err(
                WifiConnectionError::CyRsltHttpClientErrorInvalidResponse,
            ))?;
        if plaintext.as_slice() != b"hello" {
            return Err(WifiConnectionError::CyRsltHttpClientErrorInvalidResponse);
        }
        Ok(())
    }

    #[cfg(not(target_os = "none"))]
    pub fn send_public_key(&self) -> Result<(), Error> {
        debug!("Crypto::send_public_key");
        assert!(self.rsa_private_key.is_some());

        let response = reqwest::blocking::Client::new()
            .get("http://smi-server.stefan-hackenberg.de/crypto/rsa/client_modulus")
            .body(self.rsa_private_key.as_ref().unwrap().n().to_bytes_be())
            .send()?;
        assert!(response.status() == 200);

        let plaintext = self
            .rsa_private_key
            .as_ref()
            .unwrap()
            .decrypt(Pkcs1v15Encrypt, &response.bytes().unwrap())
            .unwrap();
        assert!(plaintext == b"hello");
        Ok(())
    }

    #[cfg(target_os = "none")]
    pub fn get_server_public_key(
        &mut self,
        server: &mut WifiConnectionManager,
    ) -> Result<(), WifiConnectionError> {
        debug!("Crypto::get_server_public_key");
        let (status_code, server_modulus) = server.http_client_send(
            "/crypto/rsa/server_modulus",
            Some(&self.rsa_private_key.as_ref().unwrap().n().to_bytes_be()),
        )?;
        if status_code != 200 {
            return Err(WifiConnectionError::CyRsltHttpClientErrorInvalidResponse);
        }
        self.rsa_server_public_key = Some(
            RsaPublicKey::new(
                BigUint::from_bytes_be(server_modulus),
                BigUint::from_slice(&[0x10001]),
            )
            .or(Err(
                WifiConnectionError::CyRsltHttpClientErrorInvalidResponse,
            ))?,
        );
        Ok(())
    }

    #[cfg(not(target_os = "none"))]
    pub fn get_server_public_key(&mut self) -> Result<(), Error> {
        debug!("Crypto::get_server_public_key");
        let response = reqwest::blocking::Client::new()
            .get("http://smi-server.stefan-hackenberg.de/crypto/rsa/server_modulus")
            .send()?;
        assert!(response.status() == 200);
        self.rsa_server_public_key = Some(
            RsaPublicKey::new(
                BigUint::from_bytes_be(&response.bytes().unwrap()),
                BigUint::from_slice(&[0x10001]),
            )
            .unwrap(),
        );
        Ok(())
    }

    pub fn exchange_aes_key(
        &mut self,
        #[cfg(target_os = "none")] server: &mut WifiConnectionManager,
    ) -> Result<(), Error> {
        debug!("Crypto::exchange_aes_key");

        // Create client AES key half
        let mut aes_key = [0u8; 16];
        {
            #[cfg(target_os = "none")]
            let mut rng = Rng::new();
            #[cfg(not(target_os = "none"))]
            let mut rng = rand::thread_rng();
            rng.fill_bytes(&mut aes_key);
        }

        // Encrypt with server_public and send
        let response = {
            #[cfg(target_os = "none")]
            let mut rng = Rng::new();
            #[cfg(not(target_os = "none"))]
            let mut rng = rand::thread_rng();
            let ciphertext = self
                .rsa_server_public_key
                .as_ref()
                .unwrap()
                .encrypt(&mut rng, Pkcs1v15Encrypt, &aes_key)
                .unwrap();

            #[cfg(not(target_os = "none"))]
            {
                let response = reqwest::blocking::Client::new()
                    .get("http://smi-server.stefan-hackenberg.de/crypto/rsa/client_aes")
                    .body(ciphertext)
                    .send()?;
                assert!(response.status() == 200);
                response.bytes().unwrap()
            }
            #[cfg(target_os = "none")]
            {
                let (status_code, response) =
                    server.http_client_send("/crypto/rsa/client_aes", Some(&ciphertext))?;
                assert!(status_code == 200);
                response
            }
        };

        // Decrypt response and XOR
        {
            let plaintext = self
                .rsa_private_key
                .as_ref()
                .unwrap()
                .decrypt(Pkcs1v15Encrypt, &response)
                .unwrap();
            assert!(plaintext.len() == 16);
            for (i, byte) in aes_key.iter_mut().enumerate() {
                *byte ^= plaintext[i];
            }
        }

        // Create AES CTR session
        self.ctr_instance = Some(Ctr128BE::<Aes128>::new(&aes_key.into(), &[0u8; 16].into()));

        // Test exchanged key
        {
            let ctr = self.ctr_instance.as_mut().unwrap();
            let mut data = [0u8; 6];
            data.copy_from_slice(b"Hello!");
            ctr.apply_keystream(&mut data);
            #[cfg(not(target_os = "none"))]
            let response = {
                let response = reqwest::blocking::Client::new()
                    .get("http://smi-server.stefan-hackenberg.de/crypto/aes_ctr/echo")
                    .body(data.to_vec())
                    .send()?;
                assert!(response.status() == 200);
                response.bytes().unwrap()
            };
            #[cfg(target_os = "none")]
            let response = {
                let (status_code, response) =
                    server.http_client_send("/crypto/aes_ctr/echo", Some(&data))?;
                assert!(status_code == 200);
                response
            };
            ctr.apply_keystream_b2b(&response, &mut data).unwrap();
            assert!(&data == b"Hello!");
        }
        Ok(())
    }
}
