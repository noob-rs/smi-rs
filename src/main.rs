#![no_std]
#![no_main]

#[macro_use]
extern crate num_derive;

mod cy_http_client_api;
mod cy_wcm;
mod http;
mod mfrc522;
mod nfc;
mod retargetio;
mod solver;

use core::panic::PanicInfo;

use log::debug;

use crate::{retargetio::LOGGER, solver::Solver};

extern "C" {
    // fn http_task_init();
    // fn http_task_connect();
    // fn _http_task();
    // fn cy_rtos_delay_milliseconds(ms: u32);
}

include!("../.credentials.rs");

#[no_mangle]
pub extern "C" fn smi_main() {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(log::LevelFilter::Info))
        .unwrap();

    debug!("Hello from smi_main");

    let mut solver = Solver::new();
    solver.do_nfc();
    solver.do_wifi();
    solver.solve();
    solver.send_solution();
}

#[inline(never)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    uart_writeln!("panic! {:?}", info);

    loop {}
}
