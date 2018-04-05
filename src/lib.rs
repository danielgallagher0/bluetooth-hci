#![no_std]
#![feature(const_fn)]

extern crate nb;

pub mod hci;

/// List of possible error codes, Bluetooth Spec 5.0, Table 1.1
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum Status {
    Ok = 0x00,
    UnknownCommand = 0x01,
    UnknownConnectionId = 0x02,
    HardwareFailure = 0x03,
    PageTimeout = 0x04,
    AuthFailure = 0x05,
    PinOrKeyMissing = 0x06,
    OutOfMemory = 0x07,
    ConnectionTimeout = 0x08,
    ConnectionLimitExceeeded = 0x09,
    SyncConnectionLimitExceeded = 0x0A,
    ConnectionAlreadyExists = 0x0B,
    CommandDisallowed = 0x0C,
    LimitedResources = 0x0D,
    ConnectionRejectedSecurity = 0x0E,
    UnacceptableBdAddr = 0x0F,
    AcceptTimeoutExceeded = 0x10,
    UnsupportedFeature = 0x11,
    InvalidParameters = 0x12,
    RemoteTerminationByUser = 0x13,
    RemoteTerminationLowResources = 0x14,
    RemoteTerminationPowerOff = 0x15,
    ConnectionTerminatedByHost = 0x16,
    RepeatedAttempts = 0x17,
    PairingNotAllowed = 0x18,
    /*
0x19 Unknown LMP PDU
0x1A Unsupported Remote Feature / Unsupported LMP Feature
0x1B SCO Offset Rejected
0x1C SCO Interval Rejected
0x1D SCO Air Mode Rejected
0x1E Invalid LMP Parameters / Invalid LL Parameters
0x1F Unspecified Error
0x20 Unsupported LMP Parameter Value / Unsupported LL Parameter Value
        0x21 Role Change Not Allowed
0x22 LMP Response Timeout / LL Response Timeout
0x23 LMP Error Transaction Collision / LL Procedure Collision
0x24 LMP PDU Not Allowed
0x25 Encryption Mode Not Acceptable
0x26 Link Key cannot be Changed
0x27 Requested QoS Not Supported
0x28 Instant Passed
0x29 Pairing With Unit Key Not Supported
0x2A Different Transaction Collision
0x2B Reserved for Future Use
0x2C QoS Unacceptable Parameter
0x2D QoS Rejected
0x2E Channel Classification Not Supported
0x2F Insufficient Security
0x30 Parameter Out Of Mandatory Range
0x31 Reserved for Future Use
0x32 Role Switch Pending
0x33 Reserved for Future Use
0x34 Reserved Slot Violation
0x35 Role Switch Failed
0x36 Extended Inquiry Response Too Large
0x37 Secure Simple Pairing Not Supported By Host
0x38 Host Busy - Pairing
0x39 Connection Rejected due to No Suitable Channel Found
0x3A Controller Busy
0x3B Unacceptable Connection Parameters
0x3C Advertising Timeout
0x3D Connection Terminated due to MIC Failure
0x3E Connection Failed to be Established
0x3F MAC Connection Failed
0x40 Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock Dragging
0x41 Type0 Submap Not Defined
0x42 Unknown Advertising Identifier
0x43 Limit Reached
0x44 Operation Cancelled by Host
*/
}

/// Values returned by local version information query. Bluetooth Specification 5.0, Vol 2 Part E,
/// 7.4.1: Read Local Version Information Command
pub struct LocalVersionInfo {
    pub hci_version: u8,
    pub hci_revision: u16,
    pub lmp_version: u8,
    pub manufacturer_name: u16,
    pub lmp_subversion: u16,
}

pub enum ReturnParameters {
    None,
    ReadLocalVersion(LocalVersionInfo),
}

pub struct CommandComplete {
    pub num_hci_command_packets: u8,
    pub return_params: ReturnParameters,
}

pub enum Event {
    CommandComplete(CommandComplete),
}

pub trait Controller {
    type Error;

    fn write(&mut self, header: &[u8], payload: &[u8]) -> nb::Result<(), Self::Error>;
    fn read(&mut self) -> nb::Result<Event, Self::Error>;
}
