#![no_std]
#![feature(const_fn)]

extern crate nb;

pub mod event;
pub mod hci;
mod opcode;

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

pub use event::Event;

pub trait Controller {
    type Error;

    fn write(&mut self, header: &[u8], payload: &[u8]) -> nb::Result<(), Self::Error>;
    fn read(&mut self) -> nb::Result<Event, Self::Error>;
}
