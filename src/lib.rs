#![no_std]
#![feature(const_fn)]

extern crate byteorder;
extern crate nb;

pub mod event;
pub mod host;
mod opcode;

pub use event::Event;

pub trait Controller {
    type Error;

    fn write(&mut self, header: &[u8], payload: &[u8]) -> nb::Result<(), Self::Error>;
    fn read_into(&mut self, buffer: &mut [u8]) -> nb::Result<(), Self::Error>;
    fn peek(&mut self, n: usize) -> nb::Result<u8, Self::Error>;
}

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
    UnknownLmpPdu = 0x19,
    UnsupportedRemoteFeature = 0x1A,
    ScoOffsetRejected = 0x1B,
    ScoIntervalRejected = 0x1C,
    ScoAirModeRejected = 0x1D,
    InvalidLmpParameters = 0x1E,
    UnspecifiedError = 0x1F,
    UnsupportedLmpParameterValue = 0x20,
    RoleChangeNotAllowed = 0x21,
    LmpResponseTimeout = 0x22,
    LmpTransactionCollision = 0x23,
    LmpPduNotAllowed = 0x24,
    EncryptionModeNotAcceptable = 0x25,
    LinkKeyCannotBeChanged = 0x26,
    RequestedQosNotSupported = 0x27,
    InstantPassed = 0x28,
    PairingWithUnitKeyNotSupported = 0x29,
    DifferentTransactionCollision = 0x2A,
    ReservedforFutureUse = 0x2B,
    QosUnacceptableParameter = 0x2C,
    QosRejected = 0x2D,
    ChannelClassificationNotSupported = 0x2E,
    InsufficientSecurity = 0x2F,
    ParameterOutOfMandatoryRange = 0x30,
    ReservedForFutureUse49 = 0x31,
    RoleSwitchPending = 0x32,
    ReservedForFutureUse51 = 0x33,
    ReservedSlotViolation = 0x34,
    RoleSwitchFailed = 0x35,
    ExtendedInquiryResponseTooLarge = 0x36,
    SecureSimplePairingNotSupportedByHost = 0x37,
    HostBusyPairing = 0x38,
    ConnectionRejectedNoSuitableChannel = 0x39,
    ControllerBusy = 0x3A,
    UnacceptableConnectionParameters = 0x3B,
    AdvertisingTimeout = 0x3C,
    ConnectionTerminatedMicFailure = 0x3D,
    ConnectionFailedToEstablish = 0x3E,
    MacConnectionFailed = 0x3F,
    CoarseClockAdjustmentRejectedDraggingAttempted = 0x40,
    Type0SubmapNotDefined = 0x41,
    UnknownAdvertisingId = 0x42,
    LimitReached = 0x43,
    OperationCancelledByHost = 0x44,
}

pub enum StatusFromU8Error {
    BadValue(u8),
}

impl core::convert::TryFrom<u8> for Status {
    type Error = StatusFromU8Error;

    fn try_from(value: u8) -> Result<Status, Self::Error> {
        match value {
            0x00 => Ok(Status::Ok),
            0x01 => Ok(Status::UnknownCommand),
            0x02 => Ok(Status::UnknownConnectionId),
            0x03 => Ok(Status::HardwareFailure),
            0x04 => Ok(Status::PageTimeout),
            0x05 => Ok(Status::AuthFailure),
            0x06 => Ok(Status::PinOrKeyMissing),
            0x07 => Ok(Status::OutOfMemory),
            0x08 => Ok(Status::ConnectionTimeout),
            0x09 => Ok(Status::ConnectionLimitExceeeded),
            0x0A => Ok(Status::SyncConnectionLimitExceeded),
            0x0B => Ok(Status::ConnectionAlreadyExists),
            0x0C => Ok(Status::CommandDisallowed),
            0x0D => Ok(Status::LimitedResources),
            0x0E => Ok(Status::ConnectionRejectedSecurity),
            0x0F => Ok(Status::UnacceptableBdAddr),
            0x10 => Ok(Status::AcceptTimeoutExceeded),
            0x11 => Ok(Status::UnsupportedFeature),
            0x12 => Ok(Status::InvalidParameters),
            0x13 => Ok(Status::RemoteTerminationByUser),
            0x14 => Ok(Status::RemoteTerminationLowResources),
            0x15 => Ok(Status::RemoteTerminationPowerOff),
            0x16 => Ok(Status::ConnectionTerminatedByHost),
            0x17 => Ok(Status::RepeatedAttempts),
            0x18 => Ok(Status::PairingNotAllowed),
            0x19 => Ok(Status::UnknownLmpPdu),
            0x1A => Ok(Status::UnsupportedRemoteFeature),
            0x1B => Ok(Status::ScoOffsetRejected),
            0x1C => Ok(Status::ScoIntervalRejected),
            0x1D => Ok(Status::ScoAirModeRejected),
            0x1E => Ok(Status::InvalidLmpParameters),
            0x1F => Ok(Status::UnspecifiedError),
            0x20 => Ok(Status::UnsupportedLmpParameterValue),
            0x21 => Ok(Status::RoleChangeNotAllowed),
            0x22 => Ok(Status::LmpResponseTimeout),
            0x23 => Ok(Status::LmpTransactionCollision),
            0x24 => Ok(Status::LmpPduNotAllowed),
            0x25 => Ok(Status::EncryptionModeNotAcceptable),
            0x26 => Ok(Status::LinkKeyCannotBeChanged),
            0x27 => Ok(Status::RequestedQosNotSupported),
            0x28 => Ok(Status::InstantPassed),
            0x29 => Ok(Status::PairingWithUnitKeyNotSupported),
            0x2A => Ok(Status::DifferentTransactionCollision),
            0x2B => Ok(Status::ReservedforFutureUse),
            0x2C => Ok(Status::QosUnacceptableParameter),
            0x2D => Ok(Status::QosRejected),
            0x2E => Ok(Status::ChannelClassificationNotSupported),
            0x2F => Ok(Status::InsufficientSecurity),
            0x30 => Ok(Status::ParameterOutOfMandatoryRange),
            0x31 => Ok(Status::ReservedForFutureUse49),
            0x32 => Ok(Status::RoleSwitchPending),
            0x33 => Ok(Status::ReservedForFutureUse51),
            0x34 => Ok(Status::ReservedSlotViolation),
            0x35 => Ok(Status::RoleSwitchFailed),
            0x36 => Ok(Status::ExtendedInquiryResponseTooLarge),
            0x37 => Ok(Status::SecureSimplePairingNotSupportedByHost),
            0x38 => Ok(Status::HostBusyPairing),
            0x39 => Ok(Status::ConnectionRejectedNoSuitableChannel),
            0x3A => Ok(Status::ControllerBusy),
            0x3B => Ok(Status::UnacceptableConnectionParameters),
            0x3C => Ok(Status::AdvertisingTimeout),
            0x3D => Ok(Status::ConnectionTerminatedMicFailure),
            0x3E => Ok(Status::ConnectionFailedToEstablish),
            0x3F => Ok(Status::MacConnectionFailed),
            0x40 => Ok(Status::CoarseClockAdjustmentRejectedDraggingAttempted),
            0x41 => Ok(Status::Type0SubmapNotDefined),
            0x42 => Ok(Status::UnknownAdvertisingId),
            0x43 => Ok(Status::LimitReached),
            0x44 => Ok(Status::OperationCancelledByHost),
            _ => Err(StatusFromU8Error::BadValue(value)),
        }
    }
}
