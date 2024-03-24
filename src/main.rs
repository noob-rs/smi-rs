#![no_std]
#![no_main]

mod retargetio;

use panic_halt as _;

#[no_mangle]
pub extern "C" fn foo_task() {
    uart_writeln!("Hello {:} from foo_task!", 42);

    loop {}
}
