use core::panic::PanicInfo;
use log::info;

use crate::{retargetio::LOGGER, solver::Solver, uart_writeln};

extern "C" {
    // fn http_task_init();
    // fn http_task_connect();
    // fn _http_task();
    // fn cy_rtos_delay_milliseconds(ms: u32);
}

#[no_mangle]
pub extern "C" fn smi_main() {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(log::LevelFilter::Info))
        .unwrap();

    info!("Hello from smi_main");

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

extern crate alloc;
use alloc::alloc::*;

/// The global allocator type.
#[derive(Default)]
pub struct Allocator;

extern "C" {
    fn malloc(size: u32) -> *mut core::ffi::c_void;
    fn free(ptr: *mut core::ffi::c_void);
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        malloc(layout.size() as u32) as *mut u8
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        free(ptr as *mut core::ffi::c_void);
    }
}

/// If there is an out of memory error, just panic.
// #[alloc_error_handler]
// fn my_allocator_error(_layout: Layout) -> ! {
//     panic!("out of memory");
// }

/// The static global allocator.
#[global_allocator]
static GLOBAL_ALLOCATOR: Allocator = Allocator;
