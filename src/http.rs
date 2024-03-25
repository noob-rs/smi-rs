use core::mem::MaybeUninit;

use num_traits::FromPrimitive;

use crate::{
    cy_wcm::{
        cy_wcm_config_t, cy_wcm_connect_ap, cy_wcm_connect_params_t, cy_wcm_init,
        cy_wcm_interface_t_CY_WCM_INTERFACE_TYPE_STA, cy_wcm_ip_address_t,
        cy_wcm_security_t_CY_WCM_SECURITY_WPA2_AES_PSK,
    },
    uart_writeln,
};

const CY_RSLT_WCM_ERR_BASE: u32 = 0x82e0000;

#[allow(non_snake_case)]
const fn WHD_RESULT_CREATE(x: u32) -> u32 {
    0x02000000 | x
}

#[repr(u32)]
#[derive(FromPrimitive, Debug)]
pub enum WifiConnectionError {
    CyRsltWcmWaitTimeout = (CY_RSLT_WCM_ERR_BASE + 1), // Wait timeout.
    CyRsltWcmBadNetworkParam = (CY_RSLT_WCM_ERR_BASE + 2), // Bad network parameters.
    CyRsltWcmBadSsidLen = (CY_RSLT_WCM_ERR_BASE + 3),  // Bad SSID length.
    CyRsltWcmSecurityNotSupported = (CY_RSLT_WCM_ERR_BASE + 4), // Security not supported.
    CyRsltWcmBadPassphraseLen = (CY_RSLT_WCM_ERR_BASE + 5), // Bad passphrase length.
    CyRsltWcmBadArg = (CY_RSLT_WCM_ERR_BASE + 6),      // Bad argument.
    CyRsltWcmInterfaceNotSupported = (CY_RSLT_WCM_ERR_BASE + 7), // Interface type not supported.
    CyRsltWcmMutexError = (CY_RSLT_WCM_ERR_BASE + 8),  // Mutex error.
    CyRsltWcmStaDisconnectError = (CY_RSLT_WCM_ERR_BASE + 9), // STA disconnect error.
    CyRsltWcmStaNetworkDown = (CY_RSLT_WCM_ERR_BASE + 10), // STA network is down.
    CyRsltWcmBspInitError = (CY_RSLT_WCM_ERR_BASE + 11), // CY BSP initialization error.
    CyRsltWcmBspDeinitError = (CY_RSLT_WCM_ERR_BASE + 12), // CY BSP error while de-initialization.
    CyRsltWcmNoActiveScan = (CY_RSLT_WCM_ERR_BASE + 13), // No active scan running currently.
    CyRsltWcmScanInProgress = (CY_RSLT_WCM_ERR_BASE + 14), // Scan in progress.
    CyRsltWcmScanError = (CY_RSLT_WCM_ERR_BASE + 15),  // Scan error.
    CyRsltWcmStopScanError = (CY_RSLT_WCM_ERR_BASE + 16), // Stop scan error.
    CyRsltWcmBandNotSupported = (CY_RSLT_WCM_ERR_BASE + 17), // BAND not supported.
    CyRsltWcmOutOfMemory = (CY_RSLT_WCM_ERR_BASE + 18), // WCM out of memory error.
    CyRsltWcmChannelError = (CY_RSLT_WCM_ERR_BASE + 19), // Error in retrieving the Wi-Fi channel.
    CyRsltWcmNetifDoesNotExist = (CY_RSLT_WCM_ERR_BASE + 20), // Network interface does not exist.
    CyRsltWcmArpRequestFailure = (CY_RSLT_WCM_ERR_BASE + 21), // Error returned for ARP request failure.
    CyRsltWcmIpv6GlobalAddressNotSupported = (CY_RSLT_WCM_ERR_BASE + 22), // IPv6 global IP not supported.
    CyRsltWcmIpv6InterfaceNotReady = (CY_RSLT_WCM_ERR_BASE + 23), // IPv6 interface not ready.
    CyRsltWcmPingFailure = (CY_RSLT_WCM_ERR_BASE + 24),           // Failure in executing ping.
    CyRsltWcmPingRequestTimeout = (CY_RSLT_WCM_ERR_BASE + 25),    // Ping request timed out.
    CyRsltWcmStaticIpNotSupported = (CY_RSLT_WCM_ERR_BASE + 26), // Static IP address not supported for IPv6.
    CyRsltWcmBadStaticIp = (CY_RSLT_WCM_ERR_BASE + 27),          // Bad Static IP address.
    CyRsltWcmSecondaryInterfaceError = (CY_RSLT_WCM_ERR_BASE + 28), // Error in bringing up the secondary interface.
    CyRsltWcmApNetworkBringupError = (CY_RSLT_WCM_ERR_BASE + 29),   // AP network bring up error.
    CyRsltWcmApBadChannel = (CY_RSLT_WCM_ERR_BASE + 30),            // Bad AP channel number.
    CyRsltWcmApIeRemovalError = (CY_RSLT_WCM_ERR_BASE + 31),        // AP IE removal error.
    CyRsltWcmInvalidIe = (CY_RSLT_WCM_ERR_BASE + 32),               // Invalid IE.
    CyRsltWcmApNotUp = (CY_RSLT_WCM_ERR_BASE + 33),                 // SoftAP is not started.
    CyRsltWcmApAlreadyUp = (CY_RSLT_WCM_ERR_BASE + 34),             // SoftAP is already started
    CyRsltWcmInterfaceNotUp = (CY_RSLT_WCM_ERR_BASE + 35),          // Interface is not initialized.
    CyRsltWcmNotInitialized = (CY_RSLT_WCM_ERR_BASE + 36),          // WCM not initialized.
    CyRsltWcmSemaphoreError = (CY_RSLT_WCM_ERR_BASE + 37),          // Semaphore error.
    CyRsltWcmSecurityNotFound = (CY_RSLT_WCM_ERR_BASE + 38), // Security type could not be determined.
    CyRsltWcmConnectInProgress = (CY_RSLT_WCM_ERR_BASE + 39), // Connect to AP is in progress.
    CyRsltWcmGatewayAddrError = (CY_RSLT_WCM_ERR_BASE + 40), // Failed to get the Gateway address.
    CyRsltWcmNetmaskAddrError = (CY_RSLT_WCM_ERR_BASE + 41), // Failed to get the netmask address.
    CyRsltWcmIpAddrError = (CY_RSLT_WCM_ERR_BASE + 42),      // Failed to get the IP address.
    CyRsltWcmGatewayMacAddrError = (CY_RSLT_WCM_ERR_BASE + 43), // Failed to get the Gateway MAC address.
    CyRsltWcmNwInitError = (CY_RSLT_WCM_ERR_BASE + 44), // Failed to initialize the network stack.
    CyRsltWcmWpsPbcOverlap = (CY_RSLT_WCM_ERR_BASE + 45), // WPS PBC overlap.
    CyRsltWcmWpsErrorReceivedWepCredentials = (CY_RSLT_WCM_ERR_BASE + 46), // WPS received incorrect credentials.
    CyRsltWcmWpsFailed = (CY_RSLT_WCM_ERR_BASE + 47), // WPS PBC/PIN mode failed.
    CyRsltWcmDhcpTimeout = (CY_RSLT_WCM_ERR_BASE + 48), // DHCP timeout.
    CyRsltWcmWpa3SupplicantError = (CY_RSLT_WCM_ERR_BASE + 49), // WPA3 supplicant error.
    CyRsltWcmUnsupportedApi = (CY_RSLT_WCM_ERR_BASE + 50), // Unsupported WCM API.
    CyRsltWcmVcmError = (CY_RSLT_WCM_ERR_BASE + 51),  // Failed to execute virtual API using VCM.
    CyRsltWcmPowersaveModeNotSupported = (CY_RSLT_WCM_ERR_BASE + 52), // Powersave mode not supported on this device.
    WhdPending = WHD_RESULT_CREATE(1),                                //< Pending
    WhdTimeout = WHD_RESULT_CREATE(2),                                //< Timeout
    WhdBadarg = WHD_RESULT_CREATE(5),                                 //< Bad Arguments
    WhdUnfinished = WHD_RESULT_CREATE(10), //< Operation not finished yet WHD_RESULT_CREATE(maybe aborted)
    WhdPartialResults = WHD_RESULT_CREATE(1003), //< Partial results
    WhdInvalidKey = WHD_RESULT_CREATE(1004), //< Invalid key
    WhdDoesNotExist = WHD_RESULT_CREATE(1005), //< Does not exist
    WhdNotAuthenticated = WHD_RESULT_CREATE(1006), //< Not authenticated
    WhdNotKeyed = WHD_RESULT_CREATE(1007), //< Not keyed
    WhdIoctlFail = WHD_RESULT_CREATE(1008), //< IOCTL fail
    WhdBufferUnavailableTemporary = WHD_RESULT_CREATE(1009), //< Buffer unavailable temporarily
    WhdBufferUnavailablePermanent = WHD_RESULT_CREATE(1010), //< Buffer unavailable permanently
    WhdConnectionLost = WHD_RESULT_CREATE(1012), //< Connection lost
    WhdOutOfEventHandlerSpace = WHD_RESULT_CREATE(1013), //< Cannot add extra event handler
    WhdSemaphoreError = WHD_RESULT_CREATE(1014), //< Error manipulating a semaphore
    WhdFlowControlled = WHD_RESULT_CREATE(1015), //< Packet retrieval cancelled due to flow control
    WhdNoCredits = WHD_RESULT_CREATE(1016), //< Packet retrieval cancelled due to lack of bus credits
    WhdNoPacketToSend = WHD_RESULT_CREATE(1017), //< Packet retrieval cancelled due to no pending packets
    WhdCoreClockNotEnabled = WHD_RESULT_CREATE(1018), //< Core disabled due to no clock
    WhdCoreInReset = WHD_RESULT_CREATE(1019),    //< Core disabled - in reset
    WhdUnsupported = WHD_RESULT_CREATE(1020),    //< Unsupported function
    WhdBusWriteRegisterError = WHD_RESULT_CREATE(1021), //< Error writing to WLAN register
    WhdSdioBusUpFail = WHD_RESULT_CREATE(1022),  //< SDIO bus failed to come up
    WhdJoinInProgress = WHD_RESULT_CREATE(1023), //< Join not finished yet
    WhdNetworkNotFound = WHD_RESULT_CREATE(1024), //< Specified network was not found
    WhdInvalidJoinStatus = WHD_RESULT_CREATE(1025), //< Join status error
    WhdUnknownInterface = WHD_RESULT_CREATE(1026), //< Unknown interface specified
    WhdSdioRxFail = WHD_RESULT_CREATE(1027),     //< Error during SDIO receive
    WhdHwtagMismatch = WHD_RESULT_CREATE(1028),  //< Hardware tag header corrupt
    WhdRxBufferAllocFail = WHD_RESULT_CREATE(1029), //< Failed to allocate a buffer to receive into
    WhdBusReadRegisterError = WHD_RESULT_CREATE(1030), //< Error reading a bus hardware register
    WhdThreadCreateFailed = WHD_RESULT_CREATE(1031), //< Failed to create a new thread
    WhdQueueError = WHD_RESULT_CREATE(1032),     //< Error manipulating a queue
    WhdBufferPointerMoveError = WHD_RESULT_CREATE(1033), //< Error moving the current pointer of a packet buffer
    WhdBufferSizeSetError = WHD_RESULT_CREATE(1034),     //< Error setting size of packet buffer
    WhdThreadStackNull = WHD_RESULT_CREATE(1035), //< Null stack pointer passed when non null was reqired
    WhdThreadDeleteFail = WHD_RESULT_CREATE(1036), //< Error deleting a thread
    WhdSleepError = WHD_RESULT_CREATE(1037),      //< Error sleeping a thread
    WhdBufferAllocFail = WHD_RESULT_CREATE(1038), //< Failed to allocate a packet buffer
    WhdNoPacketToReceive = WHD_RESULT_CREATE(1039), //< No Packets waiting to be received
    WhdInterfaceNotUp = WHD_RESULT_CREATE(1040),  //< Requested interface is not active
    WhdDelayTooLong = WHD_RESULT_CREATE(1041),    //< Requested delay is too long
    WhdInvalidDutyCycle = WHD_RESULT_CREATE(1042), //< Duty cycle is outside limit 0 to 100
    WhdPmkWrongLength = WHD_RESULT_CREATE(1043),  //< Returned pmk was the wrong length
    WhdUnknownSecurityType = WHD_RESULT_CREATE(1044), //< AP security type was unknown
    WhdWepNotAllowed = WHD_RESULT_CREATE(1045), //< AP not allowed to use WEP - it is not secure - use Open instead
    WhdWpaKeylenBad = WHD_RESULT_CREATE(1046), //< WPA / WPA2 key length must be between 8 & 64 bytes
    WhdFilterNotFound = WHD_RESULT_CREATE(1047), //< Specified filter id not found
    WhdSpiIdReadFail = WHD_RESULT_CREATE(1048), //< Failed to read 0xfeedbead SPI id from chip
    WhdSpiSizeMismatch = WHD_RESULT_CREATE(1049), //< Mismatch in sizes between SPI header and SDPCM header
    WhdAddressAlreadyRegistered = WHD_RESULT_CREATE(1050), //< Attempt to register a multicast address twice
    WhdSdioRetriesExceeded = WHD_RESULT_CREATE(1051),      //< SDIO transfer failed too many times.
    WhdNullPtrArg = WHD_RESULT_CREATE(1052), //< Null Pointer argument passed to function.
    WhdThreadFinishFail = WHD_RESULT_CREATE(1053), //< Error deleting a thread
    WhdWaitAborted = WHD_RESULT_CREATE(1054), //< Semaphore/mutex wait has been aborted
    WhdSetBlockAckWindowFail = WHD_RESULT_CREATE(1055), //< Failed to set block ack window
    WhdDelayTooShort = WHD_RESULT_CREATE(1056), //< Requested delay is too short
    WhdInvalidInterface = WHD_RESULT_CREATE(1057), //< Invalid interface provided
    WhdWepKeylenBad = WHD_RESULT_CREATE(1058), //< WEP / WEP_SHARED key length must be 5 or 13 bytes
    WhdHandlerAlreadyRegistered = WHD_RESULT_CREATE(1059), //< EAPOL handler already registered
    WhdApAlreadyUp = WHD_RESULT_CREATE(1060), //< Soft AP or P2P group owner already up
    WhdEapolKeyPacketM1Timeout = WHD_RESULT_CREATE(1061), //< Timeout occurred while waiting for EAPOL packet M1 from AP
    WhdEapolKeyPacketM3Timeout = WHD_RESULT_CREATE(1062), //< Timeout occurred while waiting for EAPOL packet M3 from APwhich may indicate incorrect WPA2/WPA passphrase
    WhdEapolKeyPacketG1Timeout = WHD_RESULT_CREATE(1063), //< Timeout occurred while waiting for EAPOL packet G1 from AP
    WhdEapolKeyFailure = WHD_RESULT_CREATE(1064), //< Unknown failure occurred during the EAPOL key handshake
    WhdMallocFailure = WHD_RESULT_CREATE(1065),   //< Memory allocation failure
    WhdAccessPointNotFound = WHD_RESULT_CREATE(1066), //< Access point not found
    WhdRtosError = WHD_RESULT_CREATE(1067),       //< RTOS operation failed
    WhdClmBlobDloadError = WHD_RESULT_CREATE(1068), //< CLM blob download failed
    WhdHalError = WHD_RESULT_CREATE(1069),        //< WHD HAL Error
    WhdRtosStaticMemLimit = WHD_RESULT_CREATE(1070), //< Exceeding the RTOS static objects memory
    WhdNoRegisterFunctionPointer = WHD_RESULT_CREATE(1071), //< No register function pointer
    WhdBlhsValidateFailed = WHD_RESULT_CREATE(1072), //< Bootloader handshake validation failed
    WhdBusUpFail = WHD_RESULT_CREATE(1073),       //< bus failed to come up
    WhdBusMemReserveFail = WHD_RESULT_CREATE(1074), //< commonring reserve for write failed
    WhdNoPktIdAvailable = WHD_RESULT_CREATE(1075), //< commonring reserve for write failed
    WhdWlanError = WHD_RESULT_CREATE(2001),       //< Generic Error
    WhdWlanBadarg = WHD_RESULT_CREATE(2002),      //< Bad Argument
    WhdWlanBadoption = WHD_RESULT_CREATE(2003),   //< Bad option
    WhdWlanNotup = WHD_RESULT_CREATE(2004),       //< Not up
    WhdWlanNotdown = WHD_RESULT_CREATE(2005),     //< Not down
    WhdWlanNotap = WHD_RESULT_CREATE(2006),       //< Not AP
    WhdWlanNotsta = WHD_RESULT_CREATE(2007),      //< Not STA
    WhdWlanBadkeyidx = WHD_RESULT_CREATE(2008),   //< BAD Key Index
    WhdWlanRadiooff = WHD_RESULT_CREATE(2009),    //< Radio Off
    WhdWlanNotbandlocked = WHD_RESULT_CREATE(2010), //< Not  band locked
    WhdWlanNoclk = WHD_RESULT_CREATE(2011),       //< No Clock
    WhdWlanBadrateset = WHD_RESULT_CREATE(2012),  //< BAD Rate valueset
    WhdWlanBadband = WHD_RESULT_CREATE(2013),     //< BAD Band
    WhdWlanBuftooshort = WHD_RESULT_CREATE(2014), //< Buffer too short
    WhdWlanBuftoolong = WHD_RESULT_CREATE(2015),  //< Buffer too long
    WhdWlanBusy = WHD_RESULT_CREATE(2016),        //< Busy
    WhdWlanNotassociated = WHD_RESULT_CREATE(2017), //< Not Associated
    WhdWlanBadssidlen = WHD_RESULT_CREATE(2018),  //< Bad SSID len
    WhdWlanOutofrangechan = WHD_RESULT_CREATE(2019), //< Out of Range Channel
    WhdWlanBadchan = WHD_RESULT_CREATE(2020),     //< Bad Channel
    WhdWlanBadaddr = WHD_RESULT_CREATE(2021),     //< Bad Address
    WhdWlanNoresource = WHD_RESULT_CREATE(2022),  //< Not Enough Resources
    WhdWlanUnsupported = WHD_RESULT_CREATE(2023), //< Unsupported
    WhdWlanBadlen = WHD_RESULT_CREATE(2024),      //< Bad length
    WhdWlanNotready = WHD_RESULT_CREATE(2025),    //< Not Ready
    WhdWlanEperm = WHD_RESULT_CREATE(2026),       //< Not Permitted
    WhdWlanNomem = WHD_RESULT_CREATE(2027),       //< No Memory
    WhdWlanAssociated = WHD_RESULT_CREATE(2028),  //< Associated
    WhdWlanRange = WHD_RESULT_CREATE(2029),       //< Not In Range
    WhdWlanNotfound = WHD_RESULT_CREATE(2030),    //< Not Found
    WhdWlanWmeNotEnabled = WHD_RESULT_CREATE(2031), //< WME Not Enabled
    WhdWlanTspecNotfound = WHD_RESULT_CREATE(2032), //< TSPEC Not Found
    WhdWlanAcmNotsupported = WHD_RESULT_CREATE(2033), //< ACM Not Supported
    WhdWlanNotWmeAssociation = WHD_RESULT_CREATE(2034), //< Not WME Association
    WhdWlanSdioError = WHD_RESULT_CREATE(2035),   //< SDIO Bus Error
    WhdWlanWlanDown = WHD_RESULT_CREATE(2036),    //< WLAN Not Accessible
    WhdWlanBadVersion = WHD_RESULT_CREATE(2037),  //< Incorrect version
    WhdWlanTxfail = WHD_RESULT_CREATE(2038),      //< TX failure
    WhdWlanRxfail = WHD_RESULT_CREATE(2039),      //< RX failure
    WhdWlanNodevice = WHD_RESULT_CREATE(2040),    //< Device not present
    WhdWlanUnfinished = WHD_RESULT_CREATE(2041),  //< To be finished
    WhdWlanNonresident = WHD_RESULT_CREATE(2042), //< access to nonresident overlay
    WhdWlanDisabled = WHD_RESULT_CREATE(2043),    //< Disabled in this build
    WhdWlanNofunction = WHD_RESULT_CREATE(2044),  //< Function pointer not provided
    WhdWlanInvalid = WHD_RESULT_CREATE(2045),     //< Not valid
    WhdWlanNoband = WHD_RESULT_CREATE(2046),      //< No Band
}

#[derive(Debug)]
pub struct WifiConnectionManager;

impl WifiConnectionManager {
    pub fn new() -> Self {
        WifiConnectionManager
    }

    pub fn init(&self) -> Result<(), WifiConnectionError> {
        let mut config = cy_wcm_config_t {
            interface: cy_wcm_interface_t_CY_WCM_INTERFACE_TYPE_STA,
        };
        match unsafe { cy_wcm_init(&mut config) } {
            0 => Ok(()),
            x => Err(FromPrimitive::from_u32(x).unwrap()),
        }
    }

    pub fn connect(&self, ssid: &str, password: &str) -> Result<[u8; 4], WifiConnectionError> {
        let mut params: cy_wcm_connect_params_t = unsafe { MaybeUninit::zeroed().assume_init() };
        if ssid.len() > params.ap_credentials.SSID.len()
            || password.len() > params.ap_credentials.password.len()
        {
            return Err(WifiConnectionError::CyRsltWcmBadArg);
        }

        params.ap_credentials.SSID[..ssid.len()].copy_from_slice(ssid.as_bytes());
        params.ap_credentials.password[..password.len()].copy_from_slice(password.as_bytes());
        params.ap_credentials.security = cy_wcm_security_t_CY_WCM_SECURITY_WPA2_AES_PSK;

        let mut ip_addr: cy_wcm_ip_address_t = unsafe { MaybeUninit::zeroed().assume_init() };

        let status = unsafe { cy_wcm_connect_ap(&mut params, &mut ip_addr) };
        match status {
            0 => Ok(unsafe { ip_addr.ip.v4 }.to_le_bytes()),
            x => Err(FromPrimitive::from_u32(x).unwrap()),
        }
    }
}
