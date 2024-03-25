use core::ptr::addr_of;

pub(crate) struct Io;

impl core::fmt::Write for Io {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        do_write(s.as_bytes());
        Ok(())
    }
}

fn do_write(data: &[u8]) {
    for byte in data {
        unsafe {
            cyhal_uart_putc(addr_of!(cy_retarget_io_uart_obj), *byte as u32);
        }
    }
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct cyhal_uart_t {
    _unused: [u8; 0],
}

extern "C" {
    static mut cy_retarget_io_uart_obj: cyhal_uart_t;
    fn cyhal_uart_putc(uart: *const cyhal_uart_t, value: u32);
}

#[macro_export]
macro_rules! uart_writeln {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut io = $crate::retargetio::Io;
        writeln!(io, $($arg)*).unwrap();
    }};
}
