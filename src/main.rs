#![no_std]
#![no_main]

#[macro_use]
extern crate num_derive;

mod cy_wcm;
mod http;
mod retargetio;

use core::panic::PanicInfo;

use crate::http::WifiConnectionManager;

extern "C" {
    fn http_task_init();
    fn http_task_connect();
    fn _http_task();
    fn cy_rtos_delay_milliseconds(ms: u32);
}

#[no_mangle]
pub extern "C" fn http_task() {
    // unsafe { _http_task() };
    uart_writeln!("Hello {:} from foo_task!", 42);

    let wcm = WifiConnectionManager::new();
    let status = wcm.init();
    uart_writeln!("wcm.init: {:?}", status);

    loop {
        let status = wcm.connect("", "");
        uart_writeln!("Connected with ip: {:?}", status);
        if status.is_ok() {
            break;
        }
        // unsafe { cy_rtos_delay_milliseconds(500) };
    }

    uart_writeln!("Connected !");
}

#[inline(never)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    uart_writeln!("panic! {:?}", info);

    loop {}
}
