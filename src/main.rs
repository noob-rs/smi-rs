#![no_std]
#![no_main]

#[macro_use]
extern crate num_derive;

mod cy_http_client_api;
mod cy_wcm;
mod http;
mod retargetio;

use core::panic::PanicInfo;

use crate::http::WifiConnectionManager;

extern "C" {
    // fn http_task_init();
    // fn http_task_connect();
    // fn _http_task();
    fn cy_rtos_delay_milliseconds(ms: u32);
}

#[no_mangle]
pub extern "C" fn smi_main() {
    // unsafe { _http_task() };
    uart_writeln!("Hello {:} from foo_task!", 42);

    let mut wcm = WifiConnectionManager::new();
    let status = wcm.init();
    uart_writeln!("wcm.init: {:?}", status);

    loop {
        let status = wcm.connect("", "");
        uart_writeln!("Connected with ip: {:?}", status);
        if status.is_ok() {
            break;
        }
        unsafe { cy_rtos_delay_milliseconds(1000) };
    }

    uart_writeln!("Connected !");

    let status = wcm.http_client_init();
    uart_writeln!("http_client_init: {:?}", status);

    let status = wcm.http_client_connect("smi-server.stefan-hackenberg.de", 80);
    uart_writeln!("http_client_connect: {:?}", status);

    let status = wcm.http_client_send("/hello", None);
    uart_writeln!("http_client_send: {:?}", status);
    if let Ok(data) = status {
        uart_writeln!(
            "http_client_send response: {:?}",
            core::str::from_utf8(data).unwrap()
        );
    }
}

#[inline(never)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    uart_writeln!("panic! {:?}", info);

    loop {}
}
