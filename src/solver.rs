#[cfg(feature = "crypto")]
use aes::cipher::StreamCipher;
use log::{debug, info};
use sha2::{Digest, Sha256};

#[cfg(not(target_os = "none"))]
use reqwest::Error;

#[cfg(target_os = "none")]
use crate::{
    http::{WifiConnectionError, WifiConnectionManager},
    mfrc522,
    nfc::{self, Nfc, NfcPins},
    WIFI_PASSWORD, WIFI_SSID,
};

#[cfg(feature = "crypto")]
use crate::crypto::{self, Crypto};
#[cfg(not(target_os = "none"))]
use crate::nfc::Nfc;

type ShortHashEntry = [u8; 11];

#[derive(Debug)]
pub struct NfcHashTable {
    nfc: Nfc,
    nfc_uid: [u8; 7],
    hashes: [ShortHashEntry; 64],
}

impl NfcHashTable {
    #[cfg(target_os = "none")]
    pub fn new(pins: NfcPins) -> Self {
        Self {
            nfc: Nfc::new(pins),
            nfc_uid: [0; 7],
            hashes: [Default::default(); 64],
        }
    }
    #[cfg(not(target_os = "none"))]
    pub fn new() -> Self {
        Self {
            nfc: Nfc::new(),
            nfc_uid: [0; 7],
            hashes: [Default::default(); 64],
        }
    }

    fn read_hash(&mut self, index: usize) -> (u8, ShortHashEntry) {
        let index = index as u8;
        let mut digest: ShortHashEntry = Default::default();
        // Read first block
        let data = self.nfc.mifare_read(4 + 3 * index).unwrap();
        let hash_index = data[0];
        let _ = &mut digest[0..3].copy_from_slice(&data[1..4]);
        // Read second block
        let data = self.nfc.mifare_read(4 + 3 * index + 1).unwrap();
        let _ = &mut digest[3..7].copy_from_slice(&data[0..4]);
        // Read third block
        let data = self.nfc.mifare_read(4 + 3 * index + 2).unwrap();
        let _ = &mut digest[7..11].copy_from_slice(&data[0..4]);

        (hash_index, digest)
    }

    pub fn read_table_from_tag(&mut self) {
        loop {
            if self.nfc.is_new_card_present() {
                break;
            }
        }
        loop {
            if let Ok(uid) = self.nfc.read_card_serial() {
                debug!("NfcHashTable::read_from_tag: uid: {:02x?}", uid);
                self.nfc_uid.copy_from_slice(&uid[..7]);
                break;
            }
        }

        for i in 0..64 {
            let (index, hash) = self.read_hash(i);
            self.hashes[index as usize] = hash;
            debug!(
                "NfcHashTable::read_table_from_tag: {:02x?}",
                self.hashes[index as usize]
            );
        }
    }
}

pub struct ServerHashTable {
    hashes: [ShortHashEntry; 64],
    #[cfg(target_os = "none")]
    pub(crate) wcm: WifiConnectionManager,
    #[cfg(feature = "crypto")]
    pub(crate) crypto: Crypto,
    #[cfg(not(target_os = "none"))]
    buffer: [u8; 8092],
}

#[cfg(target_os = "none")]
impl ServerHashTable {
    pub fn new() -> Self {
        #[allow(unused_mut)]
        let mut result = Self {
            hashes: [Default::default(); 64],
            wcm: WifiConnectionManager::new(),
            #[cfg(feature = "crypto")]
            crypto: Default::default(),
        };
        #[cfg(feature = "crypto")]
        result.crypto.rsa_keygen();
        result
    }

    pub fn connect(&mut self, ssid: &str, password: &str) -> Result<(), WifiConnectionError> {
        self.wcm.init()?;
        loop {
            let status = self.wcm.connect(ssid, password);
            if status.is_ok() {
                break;
            }
        }
        self.wcm.http_client_init()?;
        self.wcm
            .http_client_connect("smi-server.stefan-hackenberg.de", 80)?;

        #[cfg(feature = "crypto")]
        self.crypto.establish_crypto(&mut self.wcm)?;
        Ok(())
    }

    fn read_snippet_from_server(
        &mut self,
        index: usize,
        uid: &[u8],
    ) -> Result<&[u8], WifiConnectionError> {
        let mut buffer = [0u8; 8];
        let _ = &mut buffer[..7].copy_from_slice(uid);
        buffer[7] = index as u8;

        #[cfg(feature = "crypto")]
        {
            self.crypto
                .ctr_instance
                .as_mut()
                .unwrap()
                .apply_keystream(&mut buffer);
        }

        let (status_code, snippet) = self.wcm.http_client_send(
            if cfg!(feature = "crypto") {
                "/crypto/aes_ctr/getsnippet"
            } else {
                "/getsnippet"
            },
            Some(&buffer),
        )?;
        assert!(status_code == 200);

        #[cfg(feature = "crypto")]
        {
            self.crypto
                .ctr_instance
                .as_mut()
                .unwrap()
                .apply_keystream_b2b(snippet, unsafe { &mut crypto::BUFFER[..snippet.len()] })
                .unwrap();
            Ok(unsafe { &crypto::BUFFER[..snippet.len()] })
        }
        #[cfg(not(feature = "crypto"))]
        Ok(snippet)
    }

    pub fn read_snippets_from_server(&mut self, uid: &[u8]) -> Result<(), WifiConnectionError> {
        for index in 0..64 {
            let digest: [u8; 32] =
                Sha256::digest(self.read_snippet_from_server(index, uid)?).into();
            self.hashes[index].copy_from_slice(&digest[..11]);
            info!(
                "ServerHashTable::read_snippets_from_server: index: {index}, hash: {:02x?}",
                self.hashes[index]
            );
        }
        Ok(())
    }
}

#[cfg(not(target_os = "none"))]
impl ServerHashTable {
    pub fn new() -> Self {
        #[allow(unused_mut)]
        let mut result = Self {
            hashes: [Default::default(); 64],
            #[cfg(feature = "crypto")]
            crypto: Default::default(),
            buffer: [0; 8092],
        };
        #[cfg(feature = "crypto")]
        result.crypto.rsa_keygen();
        result
    }

    pub fn connect(&mut self) -> Result<(), Error> {
        #[cfg(feature = "crypto")]
        {
            self.crypto.establish_crypto()?;
        }
        Ok(())
    }

    fn read_snippet_from_server(&mut self, index: usize, uid: &[u8]) -> Result<&[u8], Error> {
        assert!(uid.len() == 7);
        let mut buffer = Vec::new();
        buffer.extend_from_slice(uid);
        buffer.push(index as u8);
        #[cfg(feature = "crypto")]
        {
            self.crypto
                .ctr_instance
                .as_mut()
                .unwrap()
                .apply_keystream(&mut buffer);
        }

        let response = reqwest::blocking::Client::new()
            .get(format!(
                "http://smi-server.stefan-hackenberg.de/{}getsnippet",
                if cfg!(feature = "crypto") {
                    "/crypto/aes_ctr/"
                } else {
                    ""
                }
            ))
            .body(buffer)
            .send()?;
        assert!(response.status() == 200);
        let response_body = response.bytes()?;
        self.buffer[..response_body.len()].copy_from_slice(&response_body);

        #[cfg(feature = "crypto")]
        self.crypto
            .ctr_instance
            .as_mut()
            .unwrap()
            .apply_keystream(&mut self.buffer[..response_body.len()]);

        Ok(&self.buffer[..response_body.len()])
    }

    pub fn read_snippets_from_server(&mut self, uid: &[u8]) -> Result<(), Error> {
        for index in 0..64 {
            let digest: [u8; 32] =
                Sha256::digest(self.read_snippet_from_server(index, uid)?).into();
            self.hashes[index].copy_from_slice(&digest[..11]);
            info!(
                "ServerHashTable::read_snippets_from_server: index: {index}, hash: {:02x?}",
                self.hashes[index]
            );
        }
        Ok(())
    }
}

pub struct Solver {
    pub(crate) nfc_hash_table: NfcHashTable,
    pub(crate) server_hash_table: ServerHashTable,
    pub(crate) solution: [u8; 64],
}

impl Solver {
    pub fn new() -> Self {
        Self {
            nfc_hash_table: NfcHashTable::new(
                #[cfg(target_os = "none")]
                nfc::NfcPins {
                    mosi: mfrc522::cyhal_gpio_psoc6_02_124_bga_t_P9_0,
                    miso: mfrc522::cyhal_gpio_psoc6_02_124_bga_t_P9_1,
                    sclk: mfrc522::cyhal_gpio_psoc6_02_124_bga_t_P9_2,
                    cs: mfrc522::cyhal_gpio_psoc6_02_124_bga_t_P9_3,
                    reset: mfrc522::cyhal_gpio_psoc6_02_124_bga_t_P9_4,
                },
            ),
            server_hash_table: ServerHashTable::new(),
            solution: [0; 64],
        }
    }
    pub fn do_nfc(&mut self) {
        self.nfc_hash_table.read_table_from_tag();
        info!(
            "Solver::do_nfc: nfc_hash_table: {:02x?}",
            self.nfc_hash_table.hashes
        );
    }

    pub fn do_wifi(&mut self) {
        #[cfg(target_os = "none")]
        self.server_hash_table
            .connect(&WIFI_SSID, &WIFI_PASSWORD)
            .unwrap();
        #[cfg(not(target_os = "none"))]
        self.server_hash_table.connect().unwrap();
        self.server_hash_table
            .read_snippets_from_server(&self.nfc_hash_table.nfc_uid)
            .unwrap();
    }

    pub fn solve(&mut self) {
        self.solution.fill(65);
        for i in 0..64 {
            let j = self
                .nfc_hash_table
                .hashes
                .iter()
                .position(|el| el == &self.server_hash_table.hashes[i])
                .unwrap();
            assert!(self.solution[j] == 65);
            self.solution[j] = i as u8;
            info!("Solver::solve: solution[{}]: {}", i, j);
        }
    }

    #[cfg(target_os = "none")]
    pub fn send_solution(&mut self) {
        let mut buffer = [0u8; 7 + 64];
        buffer[..7].copy_from_slice(&self.nfc_hash_table.nfc_uid);
        buffer[7..].copy_from_slice(&self.solution);

        #[cfg(feature = "crypto")]
        {
            self.server_hash_table
                .crypto
                .ctr_instance
                .as_mut()
                .unwrap()
                .apply_keystream(&mut buffer);
        }

        let (result_status, _) = self
            .server_hash_table
            .wcm
            .http_client_send(
                if cfg!(feature = "crypto") {
                    "/crypto/aes_ctr/solve"
                } else {
                    "/solve"
                },
                Some(&buffer),
            )
            .unwrap();
        info!("Solver::send_solution result_status: {result_status}");
        assert!(result_status == 200);
    }

    #[cfg(not(target_os = "none"))]
    pub fn send_solution(&mut self) {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.nfc_hash_table.nfc_uid);
        buffer.extend_from_slice(&self.solution);

        #[cfg(feature = "crypto")]
        {
            self.server_hash_table
                .crypto
                .ctr_instance
                .as_mut()
                .unwrap()
                .apply_keystream(&mut buffer);
        }

        let response = reqwest::blocking::Client::new()
            .get(format!(
                "http://smi-server.stefan-hackenberg.de/{}solve",
                if cfg!(feature = "crypto") {
                    "/crypto/aes_ctr/"
                } else {
                    ""
                }
            ))
            .body(buffer)
            .send()
            .unwrap()
            .status();
        info!("Solver::send_solution result_status: {response}");
        assert!(response == 200);
    }
}
