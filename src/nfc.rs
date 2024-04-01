use core::{mem::MaybeUninit, ptr::addr_of_mut};

use log::{info, trace};

use crate::mfrc522::{
    cyhal_gpio_t, mfrc522_t, MFRC522_Init, MIFARE_Read, PCD_Init, PCD_ReadRegister,
    PCD_Register_VersionReg, PICC_IsNewCardPresent, PICC_ReadCardSerial, StatusCode,
    StatusCode_STATUS_OK,
};

#[derive(Debug)]
pub struct Nfc {}

pub struct NfcPins {
    pub mosi: cyhal_gpio_t,
    pub miso: cyhal_gpio_t,
    pub sclk: cyhal_gpio_t,
    pub cs: cyhal_gpio_t,
    pub reset: cyhal_gpio_t,
}

static mut MRFC: mfrc522_t = unsafe { MaybeUninit::zeroed().assume_init() };

impl Nfc {
    pub fn new(nfc_pins: NfcPins) -> Self {
        unsafe {
            MFRC522_Init(
                addr_of_mut!(MRFC),
                nfc_pins.mosi,
                nfc_pins.miso,
                nfc_pins.sclk,
                nfc_pins.cs,
                nfc_pins.reset,
            );
            PCD_Init(addr_of_mut!(MRFC));
            info!(
                "Nfc::new: pcd_version: {}",
                PCD_ReadRegister(addr_of_mut!(MRFC), PCD_Register_VersionReg as u8)
            );
        }
        Self {}
    }

    pub fn is_new_card_present(&mut self) -> bool {
        unsafe { PICC_IsNewCardPresent(addr_of_mut!(MRFC)) }
    }

    pub fn read_card_serial(&mut self) -> Result<&[u8], ()> {
        let status = unsafe { PICC_ReadCardSerial(addr_of_mut!(MRFC)) };
        if status {
            Ok(unsafe { &MRFC.uid.uidByte[..MRFC.uid.size as usize] })
        } else {
            Err(())
        }
    }

    pub fn mifare_read(&mut self, block: u8) -> Result<[u8; 18], StatusCode> {
        trace!("Nfc::mifare_read(block: {block})");
        let mut buffer = [0u8; 18];
        let mut buffer_size = buffer.len() as u8;
        let status = unsafe {
            MIFARE_Read(
                addr_of_mut!(MRFC),
                block,
                buffer.as_mut_ptr(),
                &mut buffer_size,
            )
        };
        trace!("Nfc::mifare_read status: {status:02x} buffer: {buffer:02x?}");
        if status == StatusCode_STATUS_OK as u8 {
            Ok(buffer)
        } else {
            Err(status.into())
        }
    }
}
