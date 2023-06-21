//! Common Data Types

/// Enumeration of "Common Data Types" from the [Bluetooth Assigned Numbers][0]
/// registry.
///
/// [0]: https://www.bluetooth.com/specifications/assigned-numbers/
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, defmt::Format)]
pub enum CommonDataType {
    /// Ref: Core Specification Supplement, Part A, Section 1.3
    Flags = 0x01,
    /// Ref: Core Specification Supplement, Part A, Section 1.1
    IncompleteListOf16BitServiceClassUuids = 0x02,
    /// Ref: Core Specification Supplement, Part A, Section 1.1
    CompleteListOf16BitServiceClassUuids = 0x03,
    /// Ref: Core Specification Supplement, Part A, Section 1.1
    IncompleteListOf32BitServiceClassUuids = 0x04,
    /// Ref: Core Specification Supplement, Part A, Section 1.1
    CompleteListOf32BitServiceClassUuids = 0x05,
    /// Ref: Core Specification Supplement, Part A, Section 1.1
    IncompleteListOf128BitServiceClassUuids = 0x06,
    /// Ref: Core Specification Supplement, Part A, Section 1.1
    CompleteListOf128BitServiceClassUuids = 0x07,
    /// Ref: Core Specification Supplement, Part A, Section 1.2
    ShortenedLocalName = 0x08,
    /// Ref: Core Specification Supplement, Part A, Section 1.2
    CompleteLocalName = 0x09,
    /// Ref: Core Specification Supplement, Part A, Section 1.5
    TxPowerLevel = 0x0a,
    /// Ref: Core Specification Supplement, Part A, Section 1.6
    ClassOfDevice = 0x0d,
    /// Ref: Core Specification Supplement, Part A, Section 1.6
    SimplePairingHashC192 = 0x0e,
    /// Ref: Core Specification Supplement, Part A, Section 1.6
    SimplePairingRandomizerR192 = 0x0f,
    /// Ref: Device ID Profile
    DeviceId = 0x10, // (also SecurityManagerTkValue)
    /// Ref: Core Specification Supplement, Part A, Section 1.7
    SecurityManagerTkValue = 0x11,
    /// Ref: Core Specification Supplement, Part A, Section 1.9
    PeripheralConnectionIntervalRange = 0x12,
    /// Ref: Core Specification Supplement, Part A, Section 1.10
    ListOf16BitServiceSolicitationUuids = 0x14,
    /// Ref: Core Specification Supplement, Part A, Section 1.10
    ListOf128BitServiceSolicitationUuids = 0x15,
    /// Ref: Core Specification Supplement, Part A, Section 1.11
    ServiceData16BitUuid = 0x16,
    /// Ref: Core Specification Supplement, Part A, Section 1.13
    PublicTargetAddress = 0x17,
    /// Ref: Core Specification Supplement, Part A, Section 1.14
    RandomTargetAddress = 0x18,
    /// Ref: Core Specification Supplement, Part A, Section 1.12
    Appearance = 0x19,
    /// Ref: Core Specification Supplement, Part A, Section 1.15
    AdvertisingInterval = 0x1a,
    /// Ref: Core Specification Supplement, Part A, Section 1.16
    LeBluetoothDeviceAddress = 0x1b,
    /// Ref: Core Specification Supplement, Part A, Section 1.17
    LeRole = 0x1c,
    /// Ref: Core Specification Supplement, Part A, Section 1.6
    SimplePairingHashC256 = 0x1d,
    /// Ref: Core Specification Supplement, Part A, Section 1.6
    SimplePairingRandomizerR256 = 0x1e,
    /// Ref: Core Specification Supplement, Part A, Section 1.10
    ListOf32BitServiceSolicitationUuids = 0x1f,
    /// Ref: Core Specification Supplement, Part A, Section 1.11
    ServiceData32BitUuid = 0x20,
    /// Ref: Core Specification Supplement, Part A, Section 1.11
    ServiceData128BitUuid = 0x21,
    /// Ref: Core Specification Supplement, Part A, Section 1.6
    LeSecureConnectionsConfirmationValue = 0x22,
    /// Ref: Core Specification Supplement, Part A, Section 1.6
    LeSecureConnectionsRandomValue = 0x23,
    /// Ref: Core Specification Supplement, Part A, Section 1.18
    Uri = 0x24,
    /// Ref: Indoor Positioning Service
    IndoorPositioning = 0x25,
    /// Ref: Transport Discovery Service
    TransportDiscoveryData = 0x26,
    /// Ref: Core Specification Supplement, Part A, Section 1.19
    LeSupportedFeatures = 0x27,
    /// Ref: Core Specification Supplement, Part A, Section 1.20
    ChannelMapUpdateIndication = 0x28,
    /// Ref: Mesh Profile Specification, Section 5.2.1
    PbAdv = 0x29,
    /// Ref: Mesh Profile Specification, Section 3.3.1
    MeshMessage = 0x2a,
    /// Ref: Mesh Profile Specification, Section 3.9
    MeshBeacon = 0x2b,
    /// Ref: Core Specification Supplement, Part A, Section 1.21
    BigInfo = 0x2c,
    /// Ref: Core Specification Supplement, Part A, Section 1.22
    BroadcastCode = 0x2d,
    /// Ref: Coordinated Set Identification Profile
    ResolvableSetIdentifier = 0x2e,
    /// Ref: Core Specification Supplement, Part A, Section 1.15
    AdvertisingIntervalLong = 0x2f,
    /// Ref: Public Broadcast Profile
    BroadcastName = 0x30,
    /// Ref: 3D Synchronization Profile
    ThreeDInformationData = 0x3d,
    /// Ref: Core Specification Supplement, Part A, Section 1.4
    ManufacturerSpecificData = 0xff,
}
