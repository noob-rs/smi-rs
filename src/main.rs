#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
use log::{info, LevelFilter};

#[cfg(target_os = "none")]
#[macro_use]
extern crate num_derive;

#[cfg(feature = "crypto")]
mod crypto;
mod nfc;
mod solver;

#[cfg(target_os = "none")]
mod cy_http_client_api;
#[cfg(target_os = "none")]
mod cy_wcm;
#[cfg(target_os = "none")]
mod cyhal_trng;
#[cfg(target_os = "none")]
mod http;
#[cfg(target_os = "none")]
mod main_no_std;
#[cfg(target_os = "none")]
mod mfrc522;
#[cfg(target_os = "none")]
mod retargetio;

#[cfg(target_os = "none")]
include!("../.credentials.rs");

#[cfg(not(target_os = "none"))]
use simple_logger::SimpleLogger;

#[cfg(not(target_os = "none"))]
pub fn main() {
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .unwrap();
    info!("Hello from smi_main");

    let mut solver = solver::Solver::new();
    solver.do_nfc();
    solver.do_wifi();
    solver.solve();
    solver.send_solution();
}
