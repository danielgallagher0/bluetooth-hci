//! Return parameters for vendor-specific commands.
//!
//! This module defines the parameters returned in the Command Complete event for vendor-specific
//! commands.  These commands are defined for the BlueNRG controller, but are not standard HCI
//! commands.

use crate::{require_len, require_len_at_least};
use byteorder::{ByteOrder, LittleEndian};
use core::convert::{TryFrom, TryInto};
use core::fmt::{Debug, Formatter, Result as FmtResult};
use core::time::Duration;

use super::AttributeHandle;

/// Vendor-specific commands that may generate the [Command
/// Complete](crate::event::command::ReturnParameters::Vendor) event. If the commands have defined
/// return parameters, they are included in the enum.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, defmt::Format)]
pub enum ReturnParameters {
    /// Parameters returned by the [HAL Get Firmware
    /// Revision](crate::hal::Commands::get_firmware_revision) command.
    HalGetFirmwareRevision(HalFirmwareRevision),

    /// Status returned by the [HAL Write Config Data](crate::hal::Commands::write_config_data)
    /// command.
    HalWriteConfigData(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [HAL Read Config Data](crate::hal::Commands::read_config_data)
    /// command.
    HalReadConfigData(HalConfigData),

    /// Status returned by the [HAL Set Tx Power Level](crate::hal::Commands::set_tx_power_level)
    /// command.
    HalSetTxPowerLevel(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Status returned by the [HAL Device Standby](crate::hal::Commands::device_standby) command.
    HalDeviceStandby(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [HAL Get Tx Test Packet
    /// Count](crate::hal::Commands::get_tx_test_packet_count) command.
    HalGetTxTestPacketCount(HalTxTestPacketCount),

    /// Status returned by the [HAL Start Tone](crate::hal::Commands::start_tone) command.
    HalStartTone(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Status returned by the [HAL Stop Tone](crate::hal::Commands::stop_tone) command.
    HalStopTone(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Status returned by the [HAL Get Link Status](crate::hal::Commands::get_link_status) command.
    HalGetLinkStatus(HalLinkStatus),

    /// Parameters returned by the [HAL Get Anchor Period](crate::hal::Commands::get_anchor_period)
    /// command.
    HalGetAnchorPeriod(HalAnchorPeriod),

    /// Status returned by the [GAP Set Non-Discoverable](crate::gap::Commands::set_nondiscoverable)
    /// command.
    GapSetNonDiscoverable(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Status returned by the [GAP Set Discoverable](crate::gap::Commands::set_discoverable)
    /// command.
    GapSetDiscoverable(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Status returned by the [GAP Set Direct
    /// Connectable](crate::gap::Commands::set_direct_connectable) command.
    GapSetDirectConnectable(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Status returned by the [GAP Set IO Capability](crate::gap::Commands::set_io_capability)
    /// command.
    GapSetIoCapability(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Status returned by the [GAP Set Authentication
    /// Requirement](crate::gap::Commands::set_authentication_requirement) command.
    GapSetAuthenticationRequirement(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Status returned by the [GAP Set Authorization
    /// Requirement](crate::gap::Commands::set_authorization_requirement) command.
    GapSetAuthorizationRequirement(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Status returned by the [GAP Pass Key Response](crate::gap::Commands::pass_key_response)
    /// command.
    GapPassKeyResponse(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Status returned by the [GAP Authorization
    /// Response](crate::gap::Commands::authorization_response) command.
    GapAuthorizationResponse(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GAP Init](crate::gap::Commands::init) command.
    GapInit(GapInit),

    /// Parameters returned by the [GAP Set
    /// Non-Connectable](crate::gap::Commands::set_nonconnectable) command.
    GapSetNonConnectable(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GAP Set
    /// Undirected Connectable](crate::gap::Commands::set_undirected_connectable) command.
    GapSetUndirectedConnectable(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GAP Update Advertising
    /// Data](crate::gap::Commands::update_advertising_data) command.
    GapUpdateAdvertisingData(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GAP Delete AD Type](crate::gap::Commands::delete_ad_type)
    /// command.
    GapDeleteAdType(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GAP Get Security
    /// Level](crate::gap::Commands::get_security_level) command.
    GapGetSecurityLevel(GapSecurityLevel),

    /// Parameters returned by the [GAP Set Event Mask](crate::gap::Commands::set_event_mask)
    /// command.
    GapSetEventMask(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GAP Configure
    /// White List](crate::gap::Commands::configure_white_list) command.
    GapConfigureWhiteList(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GAP Clear Security
    /// Database](crate::gap::Commands::clear_security_database) command.
    GapClearSecurityDatabase(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GAP Allow Rebond](crate::gap::Commands::allow_rebond) command.
    GapAllowRebond(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GAP Terminate
    /// Procedure](crate::gap::Commands::terminate_procedure) command.
    GapTerminateProcedure(crate::Status<crate::vendor::stm32wb::event::Status>),

    #[cfg(not(feature = "ms"))]
    /// Parameters returned by the [GAP Resolve Private
    /// Address](crate::gap::Commands::resolve_private_address) command.
    GapResolvePrivateAddress(crate::Status<crate::vendor::stm32wb::event::Status>),

    #[cfg(feature = "ms")]
    /// Parameters returned by the [GAP Resolve Private
    /// Address](crate::gap::Commands::resolve_private_address) command.
    GapResolvePrivateAddress(GapResolvePrivateAddress),

    /// Parameters returned by the [GAP Get Bonded
    /// Devices](crate::gap::Commands::get_bonded_devices) command.
    GapGetBondedDevices(GapBondedDevices),

    #[cfg(feature = "ms")]
    /// Parameters returned by the [GAP Set Broadcast
    /// Mode](crate::gap::Commands::set_broadcast_mode) command.
    GapSetBroadcastMode(crate::Status<crate::vendor::stm32wb::event::Status>),

    #[cfg(feature = "ms")]
    /// Parameters returned by the [GAP Start Observation
    /// Procedure](crate::gap::Commands::start_observation_procedure) command.
    GapStartObservationProcedure(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GAP Is Device Bonded](crate::gap::Commands::is_device_bonded)
    /// command.
    GapIsDeviceBonded(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GATT Init](crate::vendor::stm32wb::command::gatt::Commands::init) command.
    GattInit(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GATT Add Service](crate::vendor::stm32wb::command::gatt::Commands::add_service) command.
    GattAddService(GattService),

    /// Parameters returned by the [GATT Include Service](crate::vendor::stm32wb::command::gatt::Commands::include_service)
    /// command.
    GattIncludeService(GattService),

    /// Parameters returned by the [GATT Add
    /// Characteristic](crate::vendor::stm32wb::command::gatt::Commands::add_characteristic) command.
    GattAddCharacteristic(GattCharacteristic),

    /// Parameters returned by the [GATT Add Characteristic
    /// Descriptor](crate::vendor::stm32wb::command::gatt::Commands::add_characteristic_descriptor) command.
    GattAddCharacteristicDescriptor(GattCharacteristicDescriptor),

    /// Parameters returned by the [GATT Update Characteristic
    /// Value](crate::vendor::stm32wb::command::gatt::Commands::update_characteristic_value) command.
    GattUpdateCharacteristicValue(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GATT Delete
    /// Characteristic](crate::vendor::stm32wb::command::gatt::Commands::delete_characteristic) command.
    GattDeleteCharacteristic(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GATT Delete Service](crate::vendor::stm32wb::command::gatt::Commands::delete_service)
    /// command.
    GattDeleteService(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GATT Delete Included
    /// Service](crate::vendor::stm32wb::command::gatt::Commands::delete_included_service) command.
    GattDeleteIncludedService(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GATT Set Event Mask](crate::vendor::stm32wb::command::gatt::Commands::set_event_mask)
    /// command.
    GattSetEventMask(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GATT Write Without
    /// Response](crate::vendor::stm32wb::command::gatt::Commands::write_without_response) command.
    GattWriteWithoutResponse(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GATT Signed Write Without
    /// Response](crate::vendor::stm32wb::command::gatt::Commands::signed_write_without_response) command.
    GattSignedWriteWithoutResponse(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GATT Confirm
    /// Indication](crate::vendor::stm32wb::command::gatt::Commands::confirm_indication) command.
    GattConfirmIndication(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GATT Write Response](crate::vendor::stm32wb::command::gatt::Commands::write_response)
    /// command.
    GattWriteResponse(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GATT Allow Read](crate::vendor::stm32wb::command::gatt::Commands::allow_read) command.
    GattAllowRead(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GATT Set Security
    /// Permission](crate::vendor::stm32wb::command::gatt::Commands::set_security_permission) command.
    GattSetSecurityPermission(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GATT Set Descriptor
    /// Value](crate::vendor::stm32wb::command::gatt::Commands::set_descriptor_value) command.
    GattSetDescriptorValue(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Parameters returned by the [GATT Read Handle
    /// Value](crate::vendor::stm32wb::command::gatt::Commands::read_handle_value) command.
    GattReadHandleValue(GattHandleValue),

    /// Parameters returned by the [GATT Read Handle
    /// Value](crate::vendor::stm32wb::command::gatt::Commands::read_handle_value_offset) command.
    #[cfg(feature = "ms")]
    GattReadHandleValueOffset(GattHandleValue),

    /// Parameters returned by the [GATT Update Long Characteristic
    /// Value](crate::vendor::stm32wb::command::gatt::Commands::update_long_characteristic_value) command.
    #[cfg(feature = "ms")]
    GattUpdateLongCharacteristicValue(crate::Status<crate::vendor::stm32wb::event::Status>),

    /// Status returned by the [L2CAP Connection Parameter Update
    /// Response](crate::l2cap::Commands::connection_parameter_update_response) command.
    L2CapConnectionParameterUpdateResponse(crate::Status<crate::vendor::stm32wb::event::Status>),
}

impl crate::event::VendorReturnParameters for ReturnParameters {
    type Error = super::Stm32Wb5xError;

    fn new(bytes: &[u8]) -> Result<Self, crate::event::Error<Self::Error>> {
        check_len_at_least(bytes, 3)?;

        match crate::Opcode(LittleEndian::read_u16(&bytes[1..])) {
            crate::vendor::stm32wb::opcode::HAL_GET_FIRMWARE_REVISION => Ok(
                ReturnParameters::HalGetFirmwareRevision(to_hal_firmware_revision(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::HAL_WRITE_CONFIG_DATA => Ok(
                ReturnParameters::HalWriteConfigData(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::HAL_READ_CONFIG_DATA => Ok(
                ReturnParameters::HalReadConfigData(to_hal_config_data(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::HAL_SET_TX_POWER_LEVEL => Ok(
                ReturnParameters::HalSetTxPowerLevel(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::HAL_DEVICE_STANDBY => {
                Ok(ReturnParameters::HalDeviceStandby(to_status(&bytes[3..])?))
            }
            crate::vendor::stm32wb::opcode::HAL_TX_TEST_PACKET_COUNT => {
                Ok(ReturnParameters::HalGetTxTestPacketCount(
                    to_hal_tx_test_packet_count(&bytes[3..])?,
                ))
            }
            crate::vendor::stm32wb::opcode::HAL_START_TONE => {
                Ok(ReturnParameters::HalStartTone(to_status(&bytes[3..])?))
            }
            crate::vendor::stm32wb::opcode::HAL_STOP_TONE => {
                Ok(ReturnParameters::HalStopTone(to_status(&bytes[3..])?))
            }
            crate::vendor::stm32wb::opcode::HAL_GET_LINK_STATUS => Ok(
                ReturnParameters::HalGetLinkStatus(to_hal_link_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::HAL_GET_ANCHOR_PERIOD => Ok(
                ReturnParameters::HalGetAnchorPeriod(to_hal_anchor_period(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_SET_NONDISCOVERABLE => Ok(
                ReturnParameters::GapSetNonDiscoverable(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_SET_DISCOVERABLE => Ok(
                ReturnParameters::GapSetDiscoverable(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_SET_DIRECT_CONNECTABLE => Ok(
                ReturnParameters::GapSetDirectConnectable(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_SET_IO_CAPABILITY => Ok(
                ReturnParameters::GapSetIoCapability(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_SET_AUTHENTICATION_REQUIREMENT => Ok(
                ReturnParameters::GapSetAuthenticationRequirement(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_SET_AUTHORIZATION_REQUIREMENT => Ok(
                ReturnParameters::GapSetAuthorizationRequirement(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_PASS_KEY_RESPONSE => Ok(
                ReturnParameters::GapPassKeyResponse(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_AUTHORIZATION_RESPONSE => Ok(
                ReturnParameters::GapAuthorizationResponse(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_INIT => {
                Ok(ReturnParameters::GapInit(to_gap_init(&bytes[3..])?))
            }
            crate::vendor::stm32wb::opcode::GAP_SET_NONCONNECTABLE => Ok(
                ReturnParameters::GapSetNonConnectable(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_SET_UNDIRECTED_CONNECTABLE => Ok(
                ReturnParameters::GapSetUndirectedConnectable(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_UPDATE_ADVERTISING_DATA => Ok(
                ReturnParameters::GapUpdateAdvertisingData(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_DELETE_AD_TYPE => {
                Ok(ReturnParameters::GapDeleteAdType(to_status(&bytes[3..])?))
            }
            crate::vendor::stm32wb::opcode::GAP_GET_SECURITY_LEVEL => Ok(
                ReturnParameters::GapGetSecurityLevel(to_gap_security_level(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_SET_EVENT_MASK => {
                Ok(ReturnParameters::GapSetEventMask(to_status(&bytes[3..])?))
            }
            crate::vendor::stm32wb::opcode::GAP_CONFIGURE_WHITE_LIST => Ok(
                ReturnParameters::GapConfigureWhiteList(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_CLEAR_SECURITY_DATABASE => Ok(
                ReturnParameters::GapClearSecurityDatabase(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_ALLOW_REBOND => {
                Ok(ReturnParameters::GapAllowRebond(to_status(&bytes[3..])?))
            }
            crate::vendor::stm32wb::opcode::GAP_TERMINATE_PROCEDURE => Ok(
                ReturnParameters::GapTerminateProcedure(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_RESOLVE_PRIVATE_ADDRESS => {
                #[cfg(not(feature = "ms"))]
                {
                    Ok(ReturnParameters::GapResolvePrivateAddress(to_status(
                        &bytes[3..],
                    )?))
                }

                #[cfg(feature = "ms")]
                {
                    Ok(ReturnParameters::GapResolvePrivateAddress(
                        to_gap_resolve_private_address(&bytes[3..])?,
                    ))
                }
            }
            crate::vendor::stm32wb::opcode::GAP_GET_BONDED_DEVICES => Ok(
                ReturnParameters::GapGetBondedDevices(to_gap_bonded_devices(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GAP_SET_BROADCAST_MODE => {
                #[cfg(feature = "ms")]
                {
                    Ok(ReturnParameters::GapSetBroadcastMode(to_status(
                        &bytes[3..],
                    )?))
                }

                #[cfg(not(feature = "ms"))]
                {
                    Err(crate::event::Error::UnknownOpcode(
                        crate::vendor::stm32wb::opcode::GAP_SET_BROADCAST_MODE,
                    ))
                }
            }
            crate::vendor::stm32wb::opcode::GAP_START_OBSERVATION_PROCEDURE => {
                #[cfg(feature = "ms")]
                {
                    Ok(ReturnParameters::GapStartObservationProcedure(to_status(
                        &bytes[3..],
                    )?))
                }

                #[cfg(not(feature = "ms"))]
                {
                    Err(crate::event::Error::UnknownOpcode(
                        crate::vendor::stm32wb::opcode::GAP_START_OBSERVATION_PROCEDURE,
                    ))
                }
            }
            crate::vendor::stm32wb::opcode::GAP_IS_DEVICE_BONDED => {
                Ok(ReturnParameters::GapIsDeviceBonded(to_status(&bytes[3..])?))
            }
            crate::vendor::stm32wb::opcode::GATT_INIT => {
                Ok(ReturnParameters::GattInit(to_status(&bytes[3..])?))
            }
            crate::vendor::stm32wb::opcode::GATT_ADD_SERVICE => Ok(
                ReturnParameters::GattAddService(to_gatt_service(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GATT_INCLUDE_SERVICE => Ok(
                ReturnParameters::GattIncludeService(to_gatt_service(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GATT_ADD_CHARACTERISTIC => Ok(
                ReturnParameters::GattAddCharacteristic(to_gatt_characteristic(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GATT_ADD_CHARACTERISTIC_DESCRIPTOR => {
                Ok(ReturnParameters::GattAddCharacteristicDescriptor(
                    to_gatt_characteristic_descriptor(&bytes[3..])?,
                ))
            }
            crate::vendor::stm32wb::opcode::GATT_UPDATE_CHARACTERISTIC_VALUE => Ok(
                ReturnParameters::GattUpdateCharacteristicValue(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GATT_DELETE_CHARACTERISTIC => Ok(
                ReturnParameters::GattDeleteCharacteristic(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GATT_DELETE_SERVICE => {
                Ok(ReturnParameters::GattDeleteService(to_status(&bytes[3..])?))
            }
            crate::vendor::stm32wb::opcode::GATT_DELETE_INCLUDED_SERVICE => Ok(
                ReturnParameters::GattDeleteIncludedService(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GATT_SET_EVENT_MASK => {
                Ok(ReturnParameters::GattSetEventMask(to_status(&bytes[3..])?))
            }
            crate::vendor::stm32wb::opcode::GATT_WRITE_WITHOUT_RESPONSE => Ok(
                ReturnParameters::GattWriteWithoutResponse(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GATT_SIGNED_WRITE_WITHOUT_RESPONSE => Ok(
                ReturnParameters::GattSignedWriteWithoutResponse(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GATT_CONFIRM_INDICATION => Ok(
                ReturnParameters::GattConfirmIndication(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GATT_WRITE_RESPONSE => {
                Ok(ReturnParameters::GattWriteResponse(to_status(&bytes[3..])?))
            }
            crate::vendor::stm32wb::opcode::GATT_ALLOW_READ => {
                Ok(ReturnParameters::GattAllowRead(to_status(&bytes[3..])?))
            }
            crate::vendor::stm32wb::opcode::GATT_SET_SECURITY_PERMISSION => Ok(
                ReturnParameters::GattSetSecurityPermission(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GATT_SET_DESCRIPTOR_VALUE => Ok(
                ReturnParameters::GattSetDescriptorValue(to_status(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GATT_READ_HANDLE_VALUE => Ok(
                ReturnParameters::GattReadHandleValue(to_gatt_handle_value(&bytes[3..])?),
            ),
            crate::vendor::stm32wb::opcode::GATT_READ_HANDLE_VALUE_OFFSET => {
                #[cfg(feature = "ms")]
                {
                    Ok(ReturnParameters::GattReadHandleValueOffset(
                        to_gatt_handle_value(&bytes[3..])?,
                    ))
                }

                #[cfg(not(feature = "ms"))]
                {
                    Err(crate::event::Error::UnknownOpcode(
                        crate::vendor::stm32wb::opcode::GATT_READ_HANDLE_VALUE_OFFSET,
                    ))
                }
            }
            crate::vendor::stm32wb::opcode::GATT_UPDATE_LONG_CHARACTERISTIC_VALUE => {
                #[cfg(feature = "ms")]
                {
                    Ok(ReturnParameters::GattUpdateLongCharacteristicValue(
                        to_status(&bytes[3..])?,
                    ))
                }

                #[cfg(not(feature = "ms"))]
                {
                    Err(crate::event::Error::UnknownOpcode(
                        crate::vendor::stm32wb::opcode::GATT_UPDATE_LONG_CHARACTERISTIC_VALUE,
                    ))
                }
            }
            crate::vendor::stm32wb::opcode::L2CAP_CONN_PARAM_UPDATE_RESP => Ok(
                ReturnParameters::L2CapConnectionParameterUpdateResponse(to_status(&bytes[3..])?),
            ),
            other => Err(crate::event::Error::UnknownOpcode(other)),
        }
    }
}

fn check_len_at_least(
    buffer: &[u8],
    len: usize,
) -> Result<(), crate::event::Error<super::Stm32Wb5xError>> {
    if buffer.len() < len {
        Err(crate::event::Error::BadLength(buffer.len(), len))
    } else {
        Ok(())
    }
}

fn to_status(
    bytes: &[u8],
) -> Result<
    crate::Status<crate::vendor::stm32wb::event::Status>,
    crate::event::Error<super::Stm32Wb5xError>,
> {
    require_len_at_least!(bytes, 1);
    bytes[0].try_into().map_err(crate::event::rewrap_bad_status)
}

/// Parameters returned by the [HAL Get Firmware
/// Revision](crate::hal::Commands::get_firmware_revision) command.
#[derive(Clone, Debug, defmt::Format)]
pub struct HalFirmwareRevision {
    /// Did the command fail, and if so, how?
    pub status: crate::Status<crate::vendor::stm32wb::event::Status>,

    /// The firmware revision number.
    pub revision: u16,
}

fn to_hal_firmware_revision(
    bytes: &[u8],
) -> Result<HalFirmwareRevision, crate::event::Error<super::Stm32Wb5xError>> {
    require_len!(bytes, 3);

    Ok(HalFirmwareRevision {
        status: to_status(bytes)?,
        revision: LittleEndian::read_u16(&bytes[1..]),
    })
}

/// Parameters returned by the [HAL Read Config Data](crate::hal::Commands::read_config_data)
/// command.
#[derive(Clone, Debug, defmt::Format)]
pub struct HalConfigData {
    /// Did the command fail, and if so, how?
    pub status: crate::Status<crate::vendor::stm32wb::event::Status>,

    /// Requested value.
    ///
    /// The value is requested by offset, and distinguished upon return by length only. This means
    /// that this event cannot distinguish between the 16-byte encryption keys
    /// ([EncryptionRoot](crate::hal::ConfigParameter::EncryptionRoot) and
    /// [IdentityRoot](crate::hal::ConfigParameter::IdentityRoot)) or between the single-byte values
    /// ([LinkLayerOnly](crate::hal::ConfigParameter::LinkLayerOnly) or
    /// [Role](crate::hal::ConfigParameter::Role)).
    pub value: HalConfigParameter,
}

/// Potential values that can be fetched by [HAL Read Config
/// Data](crate::hal::Commands::read_config_data).
#[derive(Clone, Debug, PartialEq, defmt::Format)]
pub enum HalConfigParameter {
    /// Bluetooth public address. Corresponds to
    /// [PublicAddress](crate::hal::ConfigParameter::PublicAddress).
    PublicAddress(crate::BdAddr),

    /// Bluetooth random address. Corresponds to
    /// [RandomAddress](crate::hal::ConfigParameter::RandomAddress).
    RandomAddress(crate::BdAddr),

    /// Diversifier used to derive CSRK (connection signature resolving key).  Corresponds to
    /// [Diversifier](crate::hal::ConfigParameter::Diversifier).
    Diversifier(u16),

    /// A requested encryption key. Corresponds to either
    /// [EncryptionRoot](crate::hal::ConfigParameter::EncryptionRoot) or
    /// [IdentityRoot](crate::hal::ConfigParameter::IdentityRoot).
    EncryptionKey(crate::host::EncryptionKey),

    /// A single-byte value. Corresponds to either
    /// [LinkLayerOnly](crate::hal::ConfigParameter::LinkLayerOnly) or
    /// [Role](crate::hal::ConfigParameter::Role).
    Byte(u8),
}

fn to_hal_config_data(
    bytes: &[u8],
) -> Result<HalConfigData, crate::event::Error<super::Stm32Wb5xError>> {
    require_len_at_least!(bytes, 2);
    Ok(HalConfigData {
        status: to_status(bytes)?,
        value: to_hal_config_parameter(&bytes[1..])?,
    })
}

fn to_hal_config_parameter(
    bytes: &[u8],
) -> Result<HalConfigParameter, crate::event::Error<super::Stm32Wb5xError>> {
    match bytes.len() {
        6 => {
            let mut buf = [0; 6];
            buf.copy_from_slice(bytes);

            Ok(HalConfigParameter::PublicAddress(crate::BdAddr(buf)))
        }
        2 => Ok(HalConfigParameter::Diversifier(LittleEndian::read_u16(
            bytes,
        ))),
        16 => {
            let mut buf = [0; 16];
            buf.copy_from_slice(bytes);

            Ok(HalConfigParameter::EncryptionKey(
                crate::host::EncryptionKey(buf),
            ))
        }
        1 => Ok(HalConfigParameter::Byte(bytes[0])),
        other => Err(crate::event::Error::Vendor(
            super::Stm32Wb5xError::BadConfigParameterLength(other),
        )),
    }
}

/// Parameters returned by the [HAL Get Tx Test Packet
/// Count](crate::hal::Commands::get_tx_test_packet_count) command.
#[derive(Clone, Debug, defmt::Format)]
pub struct HalTxTestPacketCount {
    /// Did the command fail, and if so, how?
    pub status: crate::Status<crate::vendor::stm32wb::event::Status>,

    /// Number of packets sent during the last Direct TX test.
    pub packet_count: u32,
}

fn to_hal_tx_test_packet_count(
    bytes: &[u8],
) -> Result<HalTxTestPacketCount, crate::event::Error<super::Stm32Wb5xError>> {
    require_len!(bytes, 5);
    Ok(HalTxTestPacketCount {
        status: to_status(bytes)?,
        packet_count: LittleEndian::read_u32(&bytes[1..]),
    })
}

/// Parameters returned by the [HAL Get Link Status](crate::hal::Commands::get_link_status) command.
#[derive(Clone, Debug, defmt::Format)]
pub struct HalLinkStatus {
    /// Did the command fail, and if so, how?
    pub status: crate::Status<crate::vendor::stm32wb::event::Status>,

    /// State of the client connections.
    pub clients: [ClientStatus; 8],
}

/// State of a client connection.
#[derive(Copy, Clone, Debug, PartialEq, defmt::Format)]
pub struct ClientStatus {
    /// Link state for the client.
    pub state: LinkState,

    /// Connection handle for the client
    pub conn_handle: crate::ConnectionHandle,
}

/// Potential states for a connection.
#[derive(Copy, Clone, Debug, PartialEq, defmt::Format)]
pub enum LinkState {
    /// Idle
    Idle,
    /// Advertising
    Advertising,
    /// Connected in peripheral role
    ConnectedAsPeripheral,
    /// Scanning
    Scanning,
    /// Reserved
    Reserved,
    /// Connected in primary role
    ConnectedAsPrimary,
    /// TX Test
    TxTest,
    /// RX Test
    RxTest,
}

impl TryFrom<u8> for LinkState {
    type Error = super::Stm32Wb5xError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LinkState::Idle),
            1 => Ok(LinkState::Advertising),
            2 => Ok(LinkState::ConnectedAsPeripheral),
            3 => Ok(LinkState::Scanning),
            4 => Ok(LinkState::Reserved),
            5 => Ok(LinkState::ConnectedAsPrimary),
            6 => Ok(LinkState::TxTest),
            7 => Ok(LinkState::RxTest),
            _ => Err(super::Stm32Wb5xError::UnknownLinkState(value)),
        }
    }
}

fn to_hal_link_status(
    bytes: &[u8],
) -> Result<HalLinkStatus, crate::event::Error<super::Stm32Wb5xError>> {
    require_len!(bytes, 25);

    let mut status = HalLinkStatus {
        status: to_status(&bytes[0..])?,
        clients: [ClientStatus {
            state: LinkState::Idle,
            conn_handle: crate::ConnectionHandle(0),
        }; 8],
    };

    for client in 0..8 {
        status.clients[client].state = bytes[1 + client]
            .try_into()
            .map_err(crate::event::Error::Vendor)?;
        status.clients[client].conn_handle = crate::ConnectionHandle(LittleEndian::read_u16(
            &bytes[9 + 2 * client..9 + 2 * (client + 1)],
        ));
    }

    Ok(status)
}

/// Parameters returned by the [HAL Get Anchor Period](crate::hal::Commands::get_anchor_period)
/// command.
#[derive(Clone, Debug, defmt::Format)]
pub struct HalAnchorPeriod {
    /// Did the command fail, and if so, how?
    pub status: crate::Status<crate::vendor::stm32wb::event::Status>,

    /// Duration between the beginnings of sniff anchor points.
    pub anchor_interval: Duration,

    /// Maximum available size that can be allocated to a new connection slot.
    pub max_slot: Duration,
}

fn to_hal_anchor_period(
    bytes: &[u8],
) -> Result<HalAnchorPeriod, crate::event::Error<super::Stm32Wb5xError>> {
    require_len!(bytes, 9);

    Ok(HalAnchorPeriod {
        status: to_status(bytes)?,
        anchor_interval: Duration::from_micros(
            625 * u64::from(LittleEndian::read_u32(&bytes[1..5])),
        ),
        max_slot: Duration::from_micros(625 * u64::from(LittleEndian::read_u32(&bytes[5..9]))),
    })
}

/// Parameters returned by the [GAP Init](crate::gap::Commands::init) command.
#[derive(Copy, Clone, Debug, defmt::Format)]
pub struct GapInit {
    /// Did the command fail, and if so, how?
    ///
    /// Should be one of:
    /// - [Success](crate::Status::Success)
    /// - [InvalidParameters](crate::Status::InvalidParameters)
    pub status: crate::Status<crate::vendor::stm32wb::event::Status>,

    /// Handle for the GAP service
    pub service_handle: AttributeHandle,

    /// Handle for the device name characteristic added to the GAP service.
    pub dev_name_handle: AttributeHandle,

    /// Handle for the appearance characteristic added to the GAP service.
    pub appearance_handle: AttributeHandle,
}

fn to_gap_init(bytes: &[u8]) -> Result<GapInit, crate::event::Error<super::Stm32Wb5xError>> {
    require_len!(bytes, 7);

    Ok(GapInit {
        status: to_status(bytes)?,
        service_handle: AttributeHandle(LittleEndian::read_u16(&bytes[1..])),
        dev_name_handle: AttributeHandle(LittleEndian::read_u16(&bytes[3..])),
        appearance_handle: AttributeHandle(LittleEndian::read_u16(&bytes[5..])),
    })
}

/// Parameters returned by the [GAP Get Security Level](crate::gap::Commands::get_security_level)
/// command.
#[derive(Copy, Clone, Debug, defmt::Format)]
pub struct GapSecurityLevel {
    /// Did the command fail, and if so, how?
    pub status: crate::Status<crate::vendor::stm32wb::event::Status>,

    /// Is MITM (man-in-the-middle) protection required?
    pub mitm_protection_required: bool,

    /// Is bonding required?
    pub bonding_required: bool,

    /// Is out-of-band data present?
    pub out_of_band_data_present: bool,

    /// Is a pass key required, and if so, how is it generated?
    pub pass_key_required: PassKeyRequirement,
}

/// Options for pass key generation.
#[derive(Copy, Clone, Debug, PartialEq, defmt::Format)]
pub enum PassKeyRequirement {
    /// A pass key is not required.
    NotRequired,
    /// A fixed pin is present which is being used.
    FixedPin,
    /// Pass key required for pairing. An event will be generated when required.
    Generated,
}

impl TryFrom<u8> for PassKeyRequirement {
    type Error = super::Stm32Wb5xError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(PassKeyRequirement::NotRequired),
            0x01 => Ok(PassKeyRequirement::FixedPin),
            0x02 => Ok(PassKeyRequirement::Generated),
            _ => Err(super::Stm32Wb5xError::BadPassKeyRequirement(value)),
        }
    }
}

fn to_boolean(value: u8) -> Result<bool, super::Stm32Wb5xError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(super::Stm32Wb5xError::BadBooleanValue(value)),
    }
}

fn to_gap_security_level(
    bytes: &[u8],
) -> Result<GapSecurityLevel, crate::event::Error<super::Stm32Wb5xError>> {
    require_len!(bytes, 5);

    Ok(GapSecurityLevel {
        status: to_status(&bytes[0..])?,
        mitm_protection_required: to_boolean(bytes[1]).map_err(crate::event::Error::Vendor)?,
        bonding_required: to_boolean(bytes[2]).map_err(crate::event::Error::Vendor)?,
        out_of_band_data_present: to_boolean(bytes[3]).map_err(crate::event::Error::Vendor)?,
        pass_key_required: bytes[4].try_into().map_err(crate::event::Error::Vendor)?,
    })
}

#[cfg(feature = "ms")]
/// Parameters returned by the [GAP Resolve Private
/// Address](crate::gap::Commands::resolve_private_address) command.
#[derive(Copy, Clone, Debug, defmt::Format)]
pub struct GapResolvePrivateAddress {
    /// Did the command fail, and if so, how?
    pub status: crate::Status<crate::vendor::stm32wb::event::Status>,

    /// If the address was successfully resolved, the peer address is returned.  This value is
    /// `None` if the address could not be resolved.
    pub bd_addr: Option<crate::BdAddr>,
}

#[cfg(feature = "ms")]
fn to_gap_resolve_private_address(
    bytes: &[u8],
) -> Result<GapResolvePrivateAddress, crate::event::Error<super::Stm32Wb5xError>> {
    let status = to_status(bytes)?;
    if status == crate::Status::Success {
        require_len!(bytes, 7);

        let mut addr = [0; 6];
        addr.copy_from_slice(&bytes[1..7]);

        Ok(GapResolvePrivateAddress {
            status,
            bd_addr: Some(crate::BdAddr(addr)),
        })
    } else {
        Ok(GapResolvePrivateAddress {
            status,
            bd_addr: None,
        })
    }
}

/// Parameters returned by the [GAP Get Bonded Devices](crate::gap::Commands::get_bonded_devices)
/// command.
#[derive(Copy, Clone, defmt::Format)]
pub struct GapBondedDevices {
    /// Did the command fail, and if so, how?
    pub status: crate::Status<crate::vendor::stm32wb::event::Status>,

    // Number of peer addresses in the event, and a buffer that can hold all of the addresses.
    address_count: usize,
    address_buffer: [crate::BdAddrType; MAX_ADDRESSES],
}

// Max packet size (255 bytes) less non-address data (4 bytes) divided by peer address size (7):
const MAX_ADDRESSES: usize = 35;

impl GapBondedDevices {
    /// Return an iterator over the bonded device addresses.
    pub fn bonded_addresses(&self) -> &[crate::BdAddrType] {
        &self.address_buffer[..self.address_count]
    }
}

impl Debug for GapBondedDevices {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{{")?;
        for addr in self.bonded_addresses().iter() {
            write!(f, "{:?}, ", addr)?;
        }
        write!(f, "}}")
    }
}

fn to_gap_bonded_devices(
    bytes: &[u8],
) -> Result<GapBondedDevices, crate::event::Error<super::Stm32Wb5xError>> {
    let status = to_status(bytes)?;
    match status {
        crate::Status::Success => {
            const HEADER_LEN: usize = 2;
            const ADDR_LEN: usize = 7;

            require_len_at_least!(bytes, HEADER_LEN);
            let address_count = bytes[1] as usize;
            if bytes.len() != HEADER_LEN + ADDR_LEN * address_count {
                return Err(crate::event::Error::Vendor(
                    super::Stm32Wb5xError::PartialBondedDeviceAddress,
                ));
            }

            let mut address_buffer =
                [crate::BdAddrType::Public(crate::BdAddr([0; 6])); MAX_ADDRESSES];
            for (i, byte) in address_buffer.iter_mut().enumerate().take(address_count) {
                let index = HEADER_LEN + i * ADDR_LEN;
                let mut addr = [0; 6];
                addr.copy_from_slice(&bytes[(1 + index)..(7 + index)]);
                *byte = crate::to_bd_addr_type(bytes[index], crate::BdAddr(addr)).map_err(|e| {
                    crate::event::Error::Vendor(super::Stm32Wb5xError::BadBdAddrType(e.0))
                })?;
            }

            Ok(GapBondedDevices {
                status,
                address_count,
                address_buffer,
            })
        }
        _ => Ok(GapBondedDevices {
            status,
            address_count: 0,
            address_buffer: [crate::BdAddrType::Public(crate::BdAddr([0; 6])); MAX_ADDRESSES],
        }),
    }
}

/// Parameters returned by the [GATT Add Service](crate::vendor::stm32wb::command::gatt::Commands::add_service) and [GATT
/// Include Service](crate::vendor::stm32wb::command::gatt::Commands::include_service) commands.
#[derive(Copy, Clone, Debug, defmt::Format)]
pub struct GattService {
    /// Did the command fail, and if so, how?
    pub status: crate::Status<crate::vendor::stm32wb::event::Status>,

    /// Handle of the Service
    ///
    /// When this service is added to the server, a handle is allocated by the server to this
    /// service. Also server allocates a range of handles for this service from `service_handle` to
    /// `service_handle +
    /// [max_attribute_records](crate::vendor::stm32wb::command::gatt::ServiceParameters::max_attribute_records)`.
    pub service_handle: AttributeHandle,
}

fn to_gatt_service(
    bytes: &[u8],
) -> Result<GattService, crate::event::Error<super::Stm32Wb5xError>> {
    require_len!(bytes, 3);

    Ok(GattService {
        status: to_status(bytes)?,
        service_handle: AttributeHandle(LittleEndian::read_u16(&bytes[1..3])),
    })
}

/// Parameters returned by the [GATT Add Characteristic](crate::vendor::stm32wb::command::gatt::Commands::add_characteristic)
/// command.
#[derive(Copy, Clone, Debug, defmt::Format)]
pub struct GattCharacteristic {
    /// Did the command fail, and if so, how?
    pub status: crate::Status<crate::vendor::stm32wb::event::Status>,

    /// Handle of the characteristic.
    pub characteristic_handle: AttributeHandle,
}

fn to_gatt_characteristic(
    bytes: &[u8],
) -> Result<GattCharacteristic, crate::event::Error<super::Stm32Wb5xError>> {
    require_len!(bytes, 3);

    Ok(GattCharacteristic {
        status: to_status(bytes)?,
        characteristic_handle: AttributeHandle(LittleEndian::read_u16(&bytes[1..3])),
    })
}

/// Parameters returned by the [GATT Add Characteristic
/// Descriptor](crate::vendor::stm32wb::command::gatt::Commands::add_characteristic_descriptor) command.
#[derive(Copy, Clone, Debug, defmt::Format)]
pub struct GattCharacteristicDescriptor {
    /// Did the command fail, and if so, how?
    pub status: crate::Status<crate::vendor::stm32wb::event::Status>,

    /// Handle of the characteristic.
    pub descriptor_handle: AttributeHandle,
}

fn to_gatt_characteristic_descriptor(
    bytes: &[u8],
) -> Result<GattCharacteristicDescriptor, crate::event::Error<super::Stm32Wb5xError>> {
    require_len!(bytes, 3);

    Ok(GattCharacteristicDescriptor {
        status: to_status(bytes)?,
        descriptor_handle: AttributeHandle(LittleEndian::read_u16(&bytes[1..3])),
    })
}

/// Parameters returned by the [GATT Read Handle Value](crate::vendor::stm32wb::command::gatt::Commands::read_handle_value)
/// command.
#[derive(Copy, Clone, defmt::Format)]
pub struct GattHandleValue {
    /// Did the command fail, and if so, how?
    pub status: crate::Status<crate::vendor::stm32wb::event::Status>,

    value_buf: [u8; GattHandleValue::MAX_VALUE_BUF],
    value_len: usize,
}

impl Debug for GattHandleValue {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{{")?;
        write!(f, "status: {:?}; value: {{", self.status)?;
        for addr in self.value().iter() {
            write!(f, "{:?}, ", addr)?;
        }
        write!(f, "}}}}")
    }
}

impl GattHandleValue {
    // Maximum length of the handle value. The spec says the length can be 2 bytes (up to 65535),
    // but the communication layer is limited to 255 bytes in a packet. There are 6 bytes reserved
    // for data other than the value, so the maximum length of the value buffer is 249 bytes.
    const MAX_VALUE_BUF: usize = 249;

    /// Return the handle value. Only valid bytes are returned.
    pub fn value(&self) -> &[u8] {
        &self.value_buf[..self.value_len]
    }
}

fn to_gatt_handle_value(
    bytes: &[u8],
) -> Result<GattHandleValue, crate::event::Error<super::Stm32Wb5xError>> {
    require_len_at_least!(bytes, 3);

    let status = to_status(bytes)?;
    let value_len = LittleEndian::read_u16(&bytes[1..3]) as usize;
    require_len!(bytes, 3 + value_len);

    let mut handle_value = GattHandleValue {
        status,
        value_buf: [0; GattHandleValue::MAX_VALUE_BUF],
        value_len,
    };
    handle_value.value_buf[..value_len].copy_from_slice(&bytes[3..]);

    Ok(handle_value)
}
