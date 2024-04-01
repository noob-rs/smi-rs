use log::{debug, info};
use sha2::{Digest, Sha256};

use crate::{
    http::{WifiConnectionError, WifiConnectionManager},
    mfrc522,
    nfc::{self, Nfc, NfcPins},
    WIFI_PASSWORD, WIFI_SSID,
};

type ShortHashEntry = [u8; 11];

#[derive(Debug)]
pub struct NfcHashTable {
    nfc: Nfc,
    nfc_uid: [u8; 7],
    hashes: [ShortHashEntry; 64],
}

impl NfcHashTable {
    pub fn new(pins: NfcPins) -> Self {
        Self {
            nfc: Nfc::new(pins),
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
    wcm: WifiConnectionManager,
}

impl ServerHashTable {
    pub fn new() -> Self {
        Self {
            hashes: [Default::default(); 64],
            wcm: WifiConnectionManager::new(),
        }
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
            .http_client_connect("smi-server.stefan-hackenberg.de", 80)
    }

    fn read_snippet_from_server(
        &mut self,
        index: usize,
        uid: &[u8],
    ) -> Result<&[u8], WifiConnectionError> {
        let mut buffer = [0u8; 8];
        let _ = &mut buffer[..7].copy_from_slice(uid);
        buffer[7] = index as u8;
        let (status_code, snippet) = self.wcm.http_client_send("/getsnippet", Some(&buffer))?;
        assert!(status_code == 200);
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

pub struct Solver {
    nfc_hash_table: NfcHashTable,
    server_hash_table: ServerHashTable,
    solution: [u8; 64],
}

impl Solver {
    pub fn new() -> Self {
        Self {
            nfc_hash_table: NfcHashTable::new(nfc::NfcPins {
                mosi: mfrc522::cyhal_gpio_psoc6_02_124_bga_t_P9_0,
                miso: mfrc522::cyhal_gpio_psoc6_02_124_bga_t_P9_1,
                sclk: mfrc522::cyhal_gpio_psoc6_02_124_bga_t_P9_2,
                cs: mfrc522::cyhal_gpio_psoc6_02_124_bga_t_P9_3,
                reset: mfrc522::cyhal_gpio_psoc6_02_124_bga_t_P9_4,
            }),
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
        self.server_hash_table
            .connect(&WIFI_SSID, &WIFI_PASSWORD)
            .unwrap();
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

    pub fn send_solution(&mut self) {
        let mut buffer = [0u8; 7 + 64];
        buffer[..7].copy_from_slice(&self.nfc_hash_table.nfc_uid);
        buffer[7..].copy_from_slice(&self.solution);
        let (result_status, _) = self
            .server_hash_table
            .wcm
            .http_client_send("/solve", Some(&buffer))
            .unwrap();
        info!("Solver::send_solution result_status: {result_status}");
        assert!(result_status == 200);
    }
}
