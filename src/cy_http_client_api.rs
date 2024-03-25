#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, unused)]

/* automatically generated by rust-bindgen 0.69.4 */

pub const CY_RSLT_MODULE_HTTP_CLIENT_ERR_CODE_START: u32 = 0;
#[doc = " @brief Provides the result of an operation as a structured bitfield.\n\n @note A newer version @ref cy_rslt_decode_t is also available for improved\n debugging experience.\n\n See the \\ref anchor_general_description \"General Description\"\n for more details on structure and usage."]
pub type cy_rslt_t = u32;
#[doc = " Represents the server information."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cy_awsport_server_info {
    #[doc = "< Server host name. Must be NULL-terminated."]
    pub host_name: *const ::core::ffi::c_char,
    #[doc = "< Server port in host-order."]
    pub port: u16,
}
#[test]
fn bindgen_test_layout_cy_awsport_server_info() {
    const UNINIT: ::core::mem::MaybeUninit<cy_awsport_server_info> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<cy_awsport_server_info>(),
        16usize,
        concat!("Size of: ", stringify!(cy_awsport_server_info))
    );
    assert_eq!(
        ::core::mem::align_of::<cy_awsport_server_info>(),
        8usize,
        concat!("Alignment of ", stringify!(cy_awsport_server_info))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).host_name) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_server_info),
            "::",
            stringify!(host_name)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).port) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_server_info),
            "::",
            stringify!(port)
        )
    );
}
#[doc = " Represents the server information."]
pub type cy_awsport_server_info_t = cy_awsport_server_info;
#[doc = "< Peer RootCA verification to be done during TLS handshake. Handshake is aborted if verification fails. This mode is a default verify mode for client sockets."]
pub const cy_awsport_rootca_verify_mode_CY_AWS_ROOTCA_VERIFY_REQUIRED:
    cy_awsport_rootca_verify_mode = 0;
#[doc = "< Skip Peer RootCA verification during TLS handshake."]
pub const cy_awsport_rootca_verify_mode_CY_AWS_ROOTCA_VERIFY_NONE: cy_awsport_rootca_verify_mode =
    1;
#[doc = "< Peer RootCA verification to be done during TLS handshake. Even if the RootCA verification fails, continue with the TLS handshake."]
pub const cy_awsport_rootca_verify_mode_CY_AWS_ROOTCA_VERIFY_OPTIONAL:
    cy_awsport_rootca_verify_mode = 2;
#[doc = " Represents the RootCA verification mode for MQTT/HTTP client socket connection."]
pub type cy_awsport_rootca_verify_mode = u32;
#[doc = " Represents the RootCA verification mode for MQTT/HTTP client socket connection."]
pub use self::cy_awsport_rootca_verify_mode as cy_awsport_rootca_verify_mode_t;
#[doc = "< Read certificates and key from the given buffer (default location for Non PKCS flow)."]
pub const cy_awsport_cert_key_location_CY_AWS_CERT_KEY_LOCATION_RAM: cy_awsport_cert_key_location =
    0;
#[doc = " Represents the memory location for reading certificates and key during TLS connection."]
pub type cy_awsport_cert_key_location = u32;
#[doc = " Represents the memory location for reading certificates and key during TLS connection."]
pub use self::cy_awsport_cert_key_location as cy_awsport_cert_key_location_t;
#[doc = " Contains the credentials to establish a TLS connection."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cy_awsport_ssl_credentials {
    #[doc = "< An array of ALPN protocols. Set to NULL to disable ALPN."]
    pub alpnprotos: *const ::core::ffi::c_char,
    #[doc = "< Length of the ALPN protocols array."]
    pub alpnprotoslen: usize,
    #[doc = "< Set a host name to enable SNI. Set to NULL to disable SNI."]
    pub sni_host_name: *const ::core::ffi::c_char,
    #[doc = "< Size of the SNI host name."]
    pub sni_host_name_size: usize,
    #[doc = "< String representing a trusted server root certificate."]
    pub root_ca: *const ::core::ffi::c_char,
    #[doc = "< Size of the Root CA certificate."]
    pub root_ca_size: usize,
    #[doc = "< RootCA verification mode for client sockets."]
    pub root_ca_verify_mode: cy_awsport_rootca_verify_mode_t,
    #[doc = "< RootCA location for TLS connection."]
    pub root_ca_location: cy_awsport_cert_key_location_t,
    #[doc = "< String representing the client certificate."]
    pub client_cert: *const ::core::ffi::c_char,
    #[doc = "< Size of the client certificate."]
    pub client_cert_size: usize,
    #[doc = "< String representing the client certificate's private key."]
    pub private_key: *const ::core::ffi::c_char,
    #[doc = "< Size of the private Key."]
    pub private_key_size: usize,
    #[doc = "< Client key and Client certificate location for TLS connection."]
    pub cert_key_location: cy_awsport_cert_key_location_t,
    #[doc = "< String representing the username for the HTTP/MQTT client."]
    pub username: *const ::core::ffi::c_char,
    #[doc = "< Size of the user name."]
    pub username_size: usize,
    #[doc = "< String representing the password for the HTTP/MQTT client."]
    pub password: *const ::core::ffi::c_char,
    #[doc = "< Size of the password."]
    pub password_size: usize,
}
#[test]
fn bindgen_test_layout_cy_awsport_ssl_credentials() {
    const UNINIT: ::core::mem::MaybeUninit<cy_awsport_ssl_credentials> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<cy_awsport_ssl_credentials>(),
        128usize,
        concat!("Size of: ", stringify!(cy_awsport_ssl_credentials))
    );
    assert_eq!(
        ::core::mem::align_of::<cy_awsport_ssl_credentials>(),
        8usize,
        concat!("Alignment of ", stringify!(cy_awsport_ssl_credentials))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).alpnprotos) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(alpnprotos)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).alpnprotoslen) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(alpnprotoslen)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).sni_host_name) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(sni_host_name)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).sni_host_name_size) as usize - ptr as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(sni_host_name_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).root_ca) as usize - ptr as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(root_ca)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).root_ca_size) as usize - ptr as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(root_ca_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).root_ca_verify_mode) as usize - ptr as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(root_ca_verify_mode)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).root_ca_location) as usize - ptr as usize },
        52usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(root_ca_location)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).client_cert) as usize - ptr as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(client_cert)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).client_cert_size) as usize - ptr as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(client_cert_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).private_key) as usize - ptr as usize },
        72usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(private_key)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).private_key_size) as usize - ptr as usize },
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(private_key_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).cert_key_location) as usize - ptr as usize },
        88usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(cert_key_location)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).username) as usize - ptr as usize },
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(username)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).username_size) as usize - ptr as usize },
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(username_size)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).password) as usize - ptr as usize },
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(password)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).password_size) as usize - ptr as usize },
        120usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_awsport_ssl_credentials),
            "::",
            stringify!(password_size)
        )
    );
}
#[doc = " Contains the credentials to establish a TLS connection."]
pub type cy_awsport_ssl_credentials_t = cy_awsport_ssl_credentials;
#[doc = "< HTTP GET Method"]
pub const cy_http_client_method_CY_HTTP_CLIENT_METHOD_GET: cy_http_client_method = 0;
#[doc = "< HTTP PUT Method"]
pub const cy_http_client_method_CY_HTTP_CLIENT_METHOD_PUT: cy_http_client_method = 1;
#[doc = "< HTTP POST Method"]
pub const cy_http_client_method_CY_HTTP_CLIENT_METHOD_POST: cy_http_client_method = 2;
#[doc = "< HTTP HEAD Method"]
pub const cy_http_client_method_CY_HTTP_CLIENT_METHOD_HEAD: cy_http_client_method = 3;
#[doc = "< HTTP DELETE Method"]
pub const cy_http_client_method_CY_HTTP_CLIENT_METHOD_DELETE: cy_http_client_method = 4;
#[doc = "< HTTP PATCH Method"]
pub const cy_http_client_method_CY_HTTP_CLIENT_METHOD_PATCH: cy_http_client_method = 5;
#[doc = "< HTTP CONNECT Method"]
pub const cy_http_client_method_CY_HTTP_CLIENT_METHOD_CONNECT: cy_http_client_method = 6;
#[doc = "< HTTP OPTIONS Method"]
pub const cy_http_client_method_CY_HTTP_CLIENT_METHOD_OPTIONS: cy_http_client_method = 7;
#[doc = "< HTTP TRACE Method"]
pub const cy_http_client_method_CY_HTTP_CLIENT_METHOD_TRACE: cy_http_client_method = 8;
#[doc = " @addtogroup http_client_struct\n\n HTTP Client library data structures and type definitions\n\n @{\n/\n/******************************************************\n                   Enumerations\n/\n/**\n HTTP Client supported methods"]
pub type cy_http_client_method = u32;
#[doc = " @addtogroup http_client_struct\n\n HTTP Client library data structures and type definitions\n\n @{\n/\n/******************************************************\n                   Enumerations\n/\n/**\n HTTP Client supported methods"]
pub use self::cy_http_client_method as cy_http_client_method_t;
#[doc = "< Server initiated disconnect"]
pub const cy_http_client_disconn_type_CY_HTTP_CLIENT_DISCONN_TYPE_SERVER_INITIATED:
    cy_http_client_disconn_type = 0;
#[doc = "< Network is disconnected"]
pub const cy_http_client_disconn_type_CY_HTTP_CLIENT_DISCONN_TYPE_NETWORK_DOWN:
    cy_http_client_disconn_type = 1;
#[doc = " HTTP Client disconnect type"]
pub type cy_http_client_disconn_type = u32;
#[doc = " HTTP Client disconnect type"]
pub use self::cy_http_client_disconn_type as cy_http_client_disconn_type_t;
#[doc = "                 Type Definitions\n/\n/**\n HTTP Client handle"]
pub type cy_http_client_t = *mut ::core::ffi::c_void;
#[doc = " Disconnect notification callback function which was registered while invoking /ref cy_http_client_create.\n On disconnect event, the application needs to call cy_http_client_disconnect() to disconnect.\n\n @param handle [in]       : Handle for which disconnection has occurred.\n @param type [in]         : Disconnect type.\n @param user_data [in]    : User data provided by the caller while invoking /ref cy_http_client_create.\n\n @return                  : void"]
pub type cy_http_disconnect_callback_t = ::core::option::Option<
    unsafe extern "C" fn(
        handle: cy_http_client_t,
        type_: cy_http_client_disconn_type_t,
        user_data: *mut ::core::ffi::c_void,
    ),
>;
#[doc = "                    Structures\n/\n/**\n HTTP structure containing the HTTP header fields"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cy_http_client_header_t {
    #[doc = "< HTTP header field such as host, date, content_length, etc."]
    pub field: *mut ::core::ffi::c_char,
    #[doc = "< HTTP field length."]
    pub field_len: usize,
    #[doc = "< HTTP header value corresponding to the field."]
    pub value: *mut ::core::ffi::c_char,
    #[doc = "< HTTP header value length."]
    pub value_len: usize,
}
#[test]
fn bindgen_test_layout_cy_http_client_header_t() {
    const UNINIT: ::core::mem::MaybeUninit<cy_http_client_header_t> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<cy_http_client_header_t>(),
        32usize,
        concat!("Size of: ", stringify!(cy_http_client_header_t))
    );
    assert_eq!(
        ::core::mem::align_of::<cy_http_client_header_t>(),
        8usize,
        concat!("Alignment of ", stringify!(cy_http_client_header_t))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).field) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_header_t),
            "::",
            stringify!(field)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).field_len) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_header_t),
            "::",
            stringify!(field_len)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).value) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_header_t),
            "::",
            stringify!(value)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).value_len) as usize - ptr as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_header_t),
            "::",
            stringify!(value_len)
        )
    );
}
#[doc = " HTTP structure containing the fields required for the request header"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cy_http_client_request_header_t {
    #[doc = "< Method for which the HTTP Client request has to be sent."]
    pub method: cy_http_client_method_t,
    #[doc = "< Path to which HTTP Client request has to be sent; NULL terminated."]
    pub resource_path: *const ::core::ffi::c_char,
    #[doc = "< Pointer to the buffer to store HTTP request and the HTTP response received from the server.\nThis buffer needs to be allocated by the caller and should not be freed before \\ref cy_http_client_send returns."]
    pub buffer: *mut u8,
    #[doc = "< Length of the buffer in bytes."]
    pub buffer_len: usize,
    #[doc = "< Length of the request header updated in \\ref cy_http_client_write_header, or\nthe user has to update this field if the header is generated by the application and passed to cy_http_client_send."]
    pub headers_len: usize,
    #[doc = "< Indicates the Start Range from where the server should return. If the range header is not required, set this value to -1."]
    pub range_start: i32,
    #[doc = "< Indicates the End Range until where the data is expected.\nSet this to -1 if requested range is all bytes from the starting range byte to the end of file or\nthe requested range is for the last N bytes of the file."]
    pub range_end: i32,
}
#[test]
fn bindgen_test_layout_cy_http_client_request_header_t() {
    const UNINIT: ::core::mem::MaybeUninit<cy_http_client_request_header_t> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<cy_http_client_request_header_t>(),
        48usize,
        concat!("Size of: ", stringify!(cy_http_client_request_header_t))
    );
    assert_eq!(
        ::core::mem::align_of::<cy_http_client_request_header_t>(),
        8usize,
        concat!("Alignment of ", stringify!(cy_http_client_request_header_t))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).method) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_request_header_t),
            "::",
            stringify!(method)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).resource_path) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_request_header_t),
            "::",
            stringify!(resource_path)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).buffer) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_request_header_t),
            "::",
            stringify!(buffer)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).buffer_len) as usize - ptr as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_request_header_t),
            "::",
            stringify!(buffer_len)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).headers_len) as usize - ptr as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_request_header_t),
            "::",
            stringify!(headers_len)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).range_start) as usize - ptr as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_request_header_t),
            "::",
            stringify!(range_start)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).range_end) as usize - ptr as usize },
        44usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_request_header_t),
            "::",
            stringify!(range_end)
        )
    );
}
#[doc = " HTTP structure containing the fields required for response header and body"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cy_http_client_response_t {
    #[doc = "< Standard HTTP response status code."]
    pub status_code: u16,
    #[doc = "< Pointer to the buffer containing the HTTP response. This buffer is the same as the buffer provided in cy_http_client_request_header_t."]
    pub buffer: *mut u8,
    #[doc = "< Length of the buffer in bytes."]
    pub buffer_len: usize,
    #[doc = "< The starting location of the response headers in the buffer."]
    pub header: *const u8,
    #[doc = "< Byte length of the response headers in the buffer."]
    pub headers_len: usize,
    #[doc = "< Count of the headers sent by the server."]
    pub header_count: usize,
    #[doc = "< The starting location of the response body in the buffer."]
    pub body: *const u8,
    #[doc = "< Byte length of the body in the buffer."]
    pub body_len: usize,
    #[doc = "< The value in the \"Content-Length\" header is updated here."]
    pub content_len: usize,
}
#[test]
fn bindgen_test_layout_cy_http_client_response_t() {
    const UNINIT: ::core::mem::MaybeUninit<cy_http_client_response_t> =
        ::core::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::core::mem::size_of::<cy_http_client_response_t>(),
        72usize,
        concat!("Size of: ", stringify!(cy_http_client_response_t))
    );
    assert_eq!(
        ::core::mem::align_of::<cy_http_client_response_t>(),
        8usize,
        concat!("Alignment of ", stringify!(cy_http_client_response_t))
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).status_code) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_response_t),
            "::",
            stringify!(status_code)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).buffer) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_response_t),
            "::",
            stringify!(buffer)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).buffer_len) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_response_t),
            "::",
            stringify!(buffer_len)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).header) as usize - ptr as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_response_t),
            "::",
            stringify!(header)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).headers_len) as usize - ptr as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_response_t),
            "::",
            stringify!(headers_len)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).header_count) as usize - ptr as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_response_t),
            "::",
            stringify!(header_count)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).body) as usize - ptr as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_response_t),
            "::",
            stringify!(body)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).body_len) as usize - ptr as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_response_t),
            "::",
            stringify!(body_len)
        )
    );
    assert_eq!(
        unsafe { ::core::ptr::addr_of!((*ptr).content_len) as usize - ptr as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(cy_http_client_response_t),
            "::",
            stringify!(content_len)
        )
    );
}
extern "C" {
    #[doc = " Initializes the Http Client library and its components.\n This function must be called before using any other HTTP Client library functions.\n\n @note \\ref cy_http_client_init and \\ref cy_http_client_deinit API functions are not thread-safe. The caller\n       must ensure that these two API functions are not invoked simultaneously from different threads.\n\n @return cy_rslt_t        : CY_RSLT_SUCCESS on success; error codes in @ref http_client_defines otherwise."]
    pub fn cy_http_client_init() -> cy_rslt_t;
}
extern "C" {
    #[doc = " Creates a HTTP Client instance and initializes its members based on the input arguments.\n The handle to the HTTP Client instance is returned via the handle pointer supplied by the user on success.\n This handle is used for connect, disconnect, and sending HTTP Client requests.\n This function must be called after calling \\ref cy_http_client_init.\n\n @param security [in]              : Credentials for TLS secure connection. For non-secure connection, set it to NULL.\n                                     The application must allocate memory for keys and should not be freed until the HTTP Client object is deleted.\n @param server_info [in]           : Pointer for the HTTP Client Server information required during connect and send.\n @param disconn_cb [in]            : Pointer to the callback function to be invoked on disconnect.\n @param user_data [in]             : User data to be sent while invoking the disconnect callback.\n @param handle [out]               : Pointer to store the HTTP Client handle allocated by this function on a successful return.\n                                     Caller should not free the handle directly. User needs to invoke \\ref cy_http_client_delete to free the handle.\n\n @return cy_rslt_t                 : CY_RSLT_SUCCESS on success; error codes in @ref http_client_defines otherwise."]
    pub fn cy_http_client_create(
        security: *mut cy_awsport_ssl_credentials_t,
        server_info: *mut cy_awsport_server_info_t,
        disconn_cb: cy_http_disconnect_callback_t,
        user_data: *mut ::core::ffi::c_void,
        handle: *mut cy_http_client_t,
    ) -> cy_rslt_t;
}
extern "C" {
    #[doc = " Connects to the given HTTP server and establishes a connection.\n This function must be called after calling \\ref cy_http_client_create.\n\n Note: send_timeout_ms & receive_timeout_ms timeout is used by underlying network stack to receive/send the complete data asked by application or return when timeout happens. Since application/HTTP client library\n       is not aware about the amount of data to read from network stack it will ask for some number of bytes. If network stack has those many number of bytes available it will return immediately with number of bytes.\n       In case when number of bytes are not available, network stack waits for data till receive_timeout_ms expires. When receive_timeout_ms value is set to higher value, network stack will wait till timeout even\n       though the data is received. This will lead to delay in processing the HTTP response. To avoid such issues, recommendation is to configure send_timeout_ms & receive_timeout_ms in range of 100~500ms.\n\n       Now when HTTP response is larger which cannot be read/sent in timeout configured, HTTP client library provides another set of timeout which will be used by HTTP client library to keep sending/receiving remaining\n       number of bytes till timeout occurs. HTTP client library provides HTTP_SEND_RETRY_TIMEOUT_MS & HTTP_RECV_RETRY_TIMEOUT_MS configuration which value can be set in application makefile.\n\n @param handle [in]                : HTTP Client handle created using \\ref cy_http_client_create.\n @param send_timeout_ms [in]       : Socket send timeout in milliseconds.\n @param receive_timeout_ms [in]    : Socket receive timeout in milliseconds.\n @return cy_rslt_t                 : CY_RSLT_SUCCESS on success; error codes in @ref http_client_defines otherwise."]
    pub fn cy_http_client_connect(
        handle: cy_http_client_t,
        send_timeout_ms: u32,
        receive_timeout_ms: u32,
    ) -> cy_rslt_t;
}
extern "C" {
    #[doc = " Generates the request Header used as HTTP Client request header during \\ref cy_http_client_send.\n This function must be called after calling \\ref cy_http_client_create.\n\n Note: This function will automatically add the host header to request buffer. Additional headers are added to the buffer based on the header and num_header arguments.\n       If additional headers are not required, pass header as NULL and num_header as 0.\n\n @param handle [in]                : HTTP Client handle created using \\ref cy_http_client_create.\n @param request [in/out]           : Pointer to the HTTP request structure. The list of HTTP request headers are stored in the HTTP protocol header format.\n @param header [in]                : Pointer to the list of headers to be updated in the request buffer.\n @param num_header [in]            : Indicates the number of headers in the header list.\n\n @return cy_rslt_t                 : CY_RSLT_SUCCESS on success; error codes in @ref http_client_defines otherwise."]
    pub fn cy_http_client_write_header(
        handle: cy_http_client_t,
        request: *mut cy_http_client_request_header_t,
        header: *mut cy_http_client_header_t,
        num_header: u32,
    ) -> cy_rslt_t;
}
extern "C" {
    #[doc = " Sends the HTTP request to the server and returns the received HTTP response from the server.\n This function must be called after calling \\ref cy_http_client_connect.\n This API will return if the data is not sent or the response is not received within the timeout configured in \\ref cy_http_client_connect.\n This is a synchronous API. For a given HTTP Client instance, the caller has to wait till this API returns to initiate a new \\ref cy_http_client_send.\n\n @param handle [in]                : HTTP Client handle created using \\ref cy_http_client_create.\n @param request [in]               : Pointer containing the HTTP request header updated at \\ref cy_http_client_write_header.\n @param payload [in]               : Pointer to the payload which must be sent with the HTTP request.\n @param payload_len [in]           : Length of the payload.\n @param response [out]             : Pointer updated with the response of the request with the header and body on success.\n\n @return cy_rslt_t                 : CY_RSLT_SUCCESS on success; error codes in @ref http_client_defines otherwise."]
    pub fn cy_http_client_send(
        handle: cy_http_client_t,
        request: *mut cy_http_client_request_header_t,
        payload: *mut u8,
        payload_len: u32,
        response: *mut cy_http_client_response_t,
    ) -> cy_rslt_t;
}
extern "C" {
    #[doc = " Parses the headers received in the HTTP response.\n This function must be called after calling \\ref cy_http_client_send.\n While parsing the headers from the response, if any error occurs, the particular\n header/value entries in the output array will have the value and length fields set to NULL and 0 respectively.\n\n @param handle [in]                : HTTP Client handle created using \\ref cy_http_client_create.\n @param response [in]              : Pointer to the HTTP response updated during \\ref cy_http_client_send.\n @param header [out]               : Pointer to the header list to store the header fields parsed from the response.\n @param num_header [in]            : Indicates the number of headers to be parsed.\n\n @return cy_rslt_t                 : CY_RSLT_SUCCESS on success; error codes in @ref http_client_defines otherwise."]
    pub fn cy_http_client_read_header(
        handle: cy_http_client_t,
        response: *mut cy_http_client_response_t,
        header: *mut cy_http_client_header_t,
        num_header: u32,
    ) -> cy_rslt_t;
}
extern "C" {
    #[doc = " Disconnects the HTTP Client network connection.\n This function must be called after calling \\ref cy_http_client_connect.\n\n @param handle [in]                : HTTP Client handle created using \\ref cy_http_client_create.\n\n @return cy_rslt_t                 : CY_RSLT_SUCCESS on success; error codes in @ref http_client_defines otherwise."]
    pub fn cy_http_client_disconnect(handle: cy_http_client_t) -> cy_rslt_t;
}
extern "C" {
    #[doc = " Deletes the HTTP Client library Object.\n  Frees the resources assigned during object creation.\n This function must be called after calling \\ref cy_http_client_create.\n\n @param handle [in]                : HTTP Client handle created using \\ref cy_http_client_create.\n\n @return cy_rslt_t                 : CY_RSLT_SUCCESS on success; error codes in @ref http_client_defines otherwise."]
    pub fn cy_http_client_delete(handle: cy_http_client_t) -> cy_rslt_t;
}
extern "C" {
    #[doc = " De-initializes the global resources used by the HTTP Client library.\n  Removes the resources assigned for the library during initialization.\n\n @note \\ref cy_http_client_init and \\ref cy_http_client_deinit API functions are not thread-safe. The caller\n       must ensure that these two API functions are not invoked simultaneously from different threads.\n\n @return cy_rslt_t        : CY_RSLT_SUCCESS on success; error codes in @ref http_client_defines otherwise."]
    pub fn cy_http_client_deinit() -> cy_rslt_t;
}
