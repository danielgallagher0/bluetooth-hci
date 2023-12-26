//! Return parameters for HCI commands.
//!
//! This module defines the return parameters that can be returned in a [Command
//! Complete](super::Event::CommandComplete) event for every HCI command.
//!
//! For the Command Complete event, see the Bluetooth specification, v4.1 or later, Vol 2, Part E,
//! Section 7.7.14.
//!
//! For the return parameters of the commands, see the description of each command in sections 7.1 -
//! 7.6 of the same part of the spec.

use crate::vendor::stm32wb::opcode::VENDOR_OGF;
use crate::{BadStatusError, ConnectionHandle, Status};
use byteorder::{ByteOrder, LittleEndian};
use core::convert::{TryFrom, TryInto};
use core::fmt::{Debug, Formatter, Result as FmtResult};
use core::mem;

/// The [Command Complete](super::Event::CommandComplete) event is used by the Controller for most
/// commands to transmit return status of a command and the other event parameters that are
/// specified for the issued HCI command.
///
/// Must be specialized on the return parameters that may be returned by vendor-specific commands.
///
/// Defined in the Bluetooth spec, Vol 2, Part E, Section 7.7.14.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CommandComplete {
    /// Indicates the number of HCI command packets the Host can send to the Controller. If the
    /// Controller requires the Host to stop sending commands, `num_hci_command_packets` will be set
    /// to zero.  To indicate to the Host that the Controller is ready to receive HCI command
    /// packets, the Controller generates a Command Complete event with `return_params` set to
    /// [`Spontaneous`](ReturnParameters::Spontaneous) and `num_hci_command_packets` parameter set
    /// to 1 or more.  [`Spontaneous`](ReturnParameters::Spontaneous) return parameters indicates
    /// that this event is not associated with a command sent by the Host. The Controller can send a
    /// Spontaneous Command Complete event at any time to change the number of outstanding HCI
    /// command packets that the Host can send before waiting.
    pub num_hci_command_packets: u8,

    /// The type of command that has completed, and any parameters that it returns.
    pub return_params: ReturnParameters,
}

impl CommandComplete {
    /// Deserializes a buffer into a CommandComplete event.
    ///
    /// # Errors
    ///
    /// - [`BadLength`](crate::event::Error::BadLength) if the buffer is not large enough to contain
    ///   a parameter length (1 byte) and opcode (2 bytes)
    /// - Returns errors that may be generated when deserializing specific events. This may be
    ///   [`BadLength`](crate::event::Error::BadLength), which indicates the buffer was not large
    ///   enough to contain all of the required data for the event. Some commands define other
    ///   errors that indicate parameter values are invalid. The error type must be specialized on
    ///   potential vendor-specific errors, though vendor-specific errors are never returned by this
    ///   function.
    pub fn new(bytes: &[u8]) -> Result<CommandComplete, crate::event::Error> {
        require_len_at_least!(bytes, 3);

        let params = match crate::opcode::Opcode(LittleEndian::read_u16(&bytes[1..])) {
            crate::opcode::Opcode(0x0000) => ReturnParameters::Spontaneous,
            crate::opcode::SET_EVENT_MASK => {
                ReturnParameters::SetEventMask(to_status(&bytes[3..])?)
            }
            crate::opcode::RESET => ReturnParameters::Reset(to_status(&bytes[3..])?),
            crate::opcode::READ_TX_POWER_LEVEL => {
                ReturnParameters::ReadTxPowerLevel(to_tx_power_level(&bytes[3..])?)
            }
            crate::opcode::READ_LOCAL_VERSION_INFO => {
                ReturnParameters::ReadLocalVersionInformation(to_local_version_info(&bytes[3..])?)
            }
            crate::opcode::READ_LOCAL_SUPPORTED_COMMANDS => {
                ReturnParameters::ReadLocalSupportedCommands(to_supported_commands(&bytes[3..])?)
            }
            crate::opcode::READ_LOCAL_SUPPORTED_FEATURES => {
                ReturnParameters::ReadLocalSupportedFeatures(to_supported_features(&bytes[3..])?)
            }
            crate::opcode::READ_BD_ADDR => ReturnParameters::ReadBdAddr(to_bd_addr(&bytes[3..])?),
            crate::opcode::READ_RSSI => ReturnParameters::ReadRssi(to_read_rssi(&bytes[3..])?),
            crate::opcode::LE_SET_EVENT_MASK => {
                ReturnParameters::LeSetEventMask(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_READ_BUFFER_SIZE => {
                ReturnParameters::LeReadBufferSize(to_le_read_buffer_status(&bytes[3..])?)
            }
            crate::opcode::LE_READ_LOCAL_SUPPORTED_FEATURES => {
                ReturnParameters::LeReadLocalSupportedFeatures(to_le_local_supported_features(
                    &bytes[3..],
                )?)
            }
            crate::opcode::LE_SET_RANDOM_ADDRESS => {
                ReturnParameters::LeSetRandomAddress(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_SET_ADVERTISING_PARAMETERS => {
                ReturnParameters::LeSetAdvertisingParameters(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_READ_ADVERTISING_CHANNEL_TX_POWER => {
                ReturnParameters::LeReadAdvertisingChannelTxPower(
                    to_le_advertising_channel_tx_power(&bytes[3..])?,
                )
            }
            crate::opcode::LE_SET_ADVERTISING_DATA => {
                ReturnParameters::LeSetAdvertisingData(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_SET_SCAN_RESPONSE_DATA => {
                ReturnParameters::LeSetScanResponseData(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_SET_ADVERTISE_ENABLE => {
                to_le_set_advertise_enable(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_SET_SCAN_PARAMETERS => {
                ReturnParameters::LeSetScanParameters(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_SET_SCAN_ENABLE => {
                ReturnParameters::LeSetScanEnable(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_CREATE_CONNECTION_CANCEL => {
                ReturnParameters::LeCreateConnectionCancel(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_READ_WHITE_LIST_SIZE => {
                ReturnParameters::LeReadWhiteListSize(to_status(&bytes[3..])?, bytes[4] as usize)
            }
            crate::opcode::LE_CLEAR_WHITE_LIST => {
                ReturnParameters::LeClearWhiteList(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_ADD_DEVICE_TO_WHITE_LIST => {
                ReturnParameters::LeAddDeviceToWhiteList(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_REMOVE_DEVICE_FROM_WHITE_LIST => {
                ReturnParameters::LeRemoveDeviceFromWhiteList(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_SET_HOST_CHANNEL_CLASSIFICATION => {
                ReturnParameters::LeSetHostChannelClassification(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_READ_CHANNEL_MAP => {
                ReturnParameters::LeReadChannelMap(to_le_channel_map_parameters(&bytes[3..])?)
            }
            crate::opcode::LE_ENCRYPT => {
                ReturnParameters::LeEncrypt(to_le_encrypted_data(&bytes[3..])?)
            }
            crate::opcode::LE_RAND => ReturnParameters::LeRand(to_random_number(&bytes[3..])?),
            crate::opcode::LE_LTK_REQUEST_REPLY => {
                ReturnParameters::LeLongTermKeyRequestReply(to_le_ltk_request_reply(&bytes[3..])?)
            }
            crate::opcode::LE_LTK_REQUEST_NEGATIVE_REPLY => {
                ReturnParameters::LeLongTermKeyRequestNegativeReply(to_le_ltk_request_reply(
                    &bytes[3..],
                )?)
            }
            crate::opcode::LE_READ_STATES => {
                ReturnParameters::LeReadSupportedStates(to_le_read_states(&bytes[3..])?)
            }
            crate::opcode::LE_RECEIVER_TEST => {
                ReturnParameters::LeReceiverTest(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_TRANSMITTER_TEST => {
                ReturnParameters::LeTransmitterTest(to_status(&bytes[3..])?)
            }
            crate::opcode::LE_TEST_END => ReturnParameters::LeTestEnd(to_le_test_end(&bytes[3..])?),
            other => {
                if other.ogf() != VENDOR_OGF {
                    return Err(crate::event::Error::UnknownOpcode(other));
                }

                ReturnParameters::Vendor(
                    crate::vendor::stm32wb::event::command::VendorReturnParameters::new(bytes)?,
                )
            }
        };
        Ok(CommandComplete {
            num_hci_command_packets: bytes[0],
            return_params: params,
        })
    }
}

/// Commands that may generate the [Command Complete](crate::event::Event::CommandComplete) event.
/// If the commands have defined return parameters, they are included in this enum.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(clippy::large_enum_variant)]
pub enum ReturnParameters {
    /// The controller sent an unsolicited command complete event in order to change the number of
    /// HCI command packets the Host is allowed to send.
    Spontaneous,

    /// Status returned by the [Set Event Mask](crate::host::Hci::set_event_mask) command.
    SetEventMask(Status),

    /// Status returned by the [Reset](crate::host::Hci::reset) command.
    Reset(Status),

    /// [Read Transmit Power Level](crate::host::Hci::read_tx_power_level) return parameters.
    ReadTxPowerLevel(TxPowerLevel),

    /// Local version info returned by the [Read Local Version
    /// Information](crate::host::Hci::read_local_version_information) command.
    ReadLocalVersionInformation(LocalVersionInfo),

    /// Supported commands returned by the [Read Local Supported
    /// Commands](crate::host::Hci::read_local_supported_commands) command.
    ReadLocalSupportedCommands(LocalSupportedCommands),

    /// Supported features returned by the [Read Local Supported
    /// Features](crate::host::Hci::read_local_supported_features) command.
    ReadLocalSupportedFeatures(LocalSupportedFeatures),

    /// BD ADDR returned by the [Read BD ADDR](crate::host::Hci::read_bd_addr) command.
    ReadBdAddr(ReadBdAddr),

    /// RSSI returned by the [Read RSSI](crate::host::Hci::read_rssi) command.
    ReadRssi(ReadRssi),

    /// Status returned by the [LE Set Event Mask](crate::host::Hci::le_set_event_mask) command.
    LeSetEventMask(Status),

    /// Parameters returned by the [LE Read Buffer Size](crate::host::Hci::le_read_buffer_size)
    /// command.
    LeReadBufferSize(LeReadBufferSize),

    /// Parameters returned by the [LE Read Local Supported
    /// Features](crate::host::Hci::le_read_local_supported_features) command.
    LeReadLocalSupportedFeatures(LeSupportedFeatures),

    /// Status returned by the [LE Set Random Address](crate::host::Hci::le_set_random_address)
    /// command.
    LeSetRandomAddress(Status),

    /// Status returned by the [LE Set Advertising
    /// Parameters](crate::host::Hci::le_set_advertising_parameters) command.
    LeSetAdvertisingParameters(Status),

    /// Parameters returned by the [LE Read Advertising Channel TX
    /// Power](crate::host::Hci::le_read_advertising_channel_tx_power) command.
    LeReadAdvertisingChannelTxPower(LeAdvertisingChannelTxPower),

    /// Status returned by the [LE Set Advertising Data](crate::host::Hci::le_set_advertising_data)
    /// command.
    LeSetAdvertisingData(Status),

    /// Status returned by the [LE Set Scan Response
    /// Data](crate::host::Hci::le_set_scan_response_data) command.
    LeSetScanResponseData(Status),

    /// Status returned by the [LE Set Advertising
    /// Enable](crate::host::Hci::le_set_advertising_enable) command.
    LeSetAdvertisingEnable(Status),

    /// Status returned by the [LE Set Scan Parameters](crate::host::Hci::le_set_scan_parameters)
    /// command.
    LeSetScanParameters(Status),

    /// Status returned by the [LE Set Scan Enable](crate::host::Hci::le_set_scan_enable) command.
    LeSetScanEnable(Status),

    /// Status returned by the [LE Create Connection
    /// Cancel](crate::host::Hci::le_create_connection_cancel) command.
    LeCreateConnectionCancel(Status),

    /// Status and white list size returned by the [LE Read White List
    /// Size](crate::host::Hci::le_read_white_list_size) command.
    LeReadWhiteListSize(Status, usize),

    /// Status returned by the [LE Clear White List](crate::host::Hci::le_clear_white_list) command.
    LeClearWhiteList(Status),

    /// Status returned by the [LE Add Device to White
    /// List](crate::host::Hci::le_add_device_to_white_list) command.
    LeAddDeviceToWhiteList(Status),

    /// Status returned by the [LE Remove Device from White
    /// List](crate::host::Hci::le_remove_device_from_white_list) command.
    LeRemoveDeviceFromWhiteList(Status),

    /// Status returned by the [LE Set Host Channel
    /// Classification](crate::host::Hci::le_set_host_channel_classification) command.
    LeSetHostChannelClassification(Status),

    /// Parameters returned by the [LE Read Channel Map](crate::host::Hci::le_read_channel_map)
    /// command.
    LeReadChannelMap(ChannelMapParameters),

    /// Parameters returned by the [LE Encrypt](crate::host::Hci::le_encrypt) command.
    LeEncrypt(EncryptedReturnParameters),

    /// Parameters returned by the [LE Rand](crate::host::Hci::le_rand) command.
    LeRand(LeRandom),

    /// Parameters returned by the [LE Long Term Key Request
    /// Reply](crate::host::Hci::le_long_term_key_request_reply) command.
    LeLongTermKeyRequestReply(LeLongTermRequestReply),

    /// Parameters returned by the [LE Long Term Key Request Negative
    /// Reply](crate::host::Hci::le_long_term_key_request_negative_reply) command.
    LeLongTermKeyRequestNegativeReply(LeLongTermRequestReply),

    /// Parameters returned by the [LE Read States](crate::host::Hci::le_read_supported_states))
    /// command.
    LeReadSupportedStates(LeReadSupportedStates),

    /// Status returned by the [LE Receiver Test](crate::host::Hci::le_receiver_test) command.
    LeReceiverTest(Status),

    /// Status returned by the [LE Transmitter Test](crate::host::Hci::le_transmitter_test) command.
    LeTransmitterTest(Status),

    /// Parameters returned by the [LE Test End](crate::host::Hci::le_test_end) command.
    LeTestEnd(LeTestEnd),

    /// Parameters returned by vendor-specific commands.
    Vendor(crate::vendor::stm32wb::event::command::VendorReturnParameters),
}

fn to_status(bytes: &[u8]) -> Result<Status, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    bytes[0].try_into().map_err(super::rewrap_bad_status)
}

/// Values returned by the [Read Transmit Power Level](crate::host::Hci::read_tx_power_level)
/// command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TxPowerLevel {
    /// Did the command fail, and if so, how?
    pub status: Status,

    /// Specifies which connection handle's transmit power level setting is returned
    pub conn_handle: ConnectionHandle,

    /// Power level for the connection handle, in dBm.
    ///
    /// Valid range is -30 dBm to +20 dBm, but that is not enforced by this implementation.
    pub tx_power_level_dbm: i8,
}

fn to_tx_power_level(bytes: &[u8]) -> Result<TxPowerLevel, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 4);
    Ok(TxPowerLevel {
        status: to_status(bytes)?,
        conn_handle: ConnectionHandle(LittleEndian::read_u16(&bytes[1..])),
        tx_power_level_dbm: unsafe { mem::transmute::<u8, i8>(bytes[3]) },
    })
}

/// Values returned by [Read Local Version
/// Information](crate::host::Hci::read_local_version_information) command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LocalVersionInfo {
    /// Did the command fail, and if so, how?
    pub status: Status,

    /// The version information of the HCI layer.
    ///
    /// See the Bluetooth [Assigned
    /// Numbers](https://www.bluetooth.com/specifications/assigned-numbers/host-controller-interface).
    pub hci_version: u8,

    /// Revision of the Current HCI in the BR/EDR Controller.  This value is implementation
    /// dependent.
    pub hci_revision: u16,

    /// Version of the Current [LMP] or [PAL] in the Controller.
    ///
    /// [LMP]: https://www.bluetooth.com/specifications/assigned-numbers/link-manager
    /// [PAL]: https://www.bluetooth.com/specifications/assigned-numbers/protocol-adaptation-layer
    pub lmp_version: u8,

    /// Manufacturer Name of the BR/EDR Controller.  See Bluetooth [Assigned
    /// Numbers](https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers)
    pub manufacturer_name: u16,

    /// Subversion of the Current [LMP] or [PAL] in the Controller. This value is implementation
    /// dependent.
    ///
    /// [LMP]: https://www.bluetooth.com/specifications/assigned-numbers/link-manager
    /// [PAL]: https://www.bluetooth.com/specifications/assigned-numbers/protocol-adaptation-layer
    pub lmp_subversion: u16,
}

fn to_local_version_info(bytes: &[u8]) -> Result<LocalVersionInfo, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 9);

    Ok(LocalVersionInfo {
        status: bytes[0].try_into().map_err(super::rewrap_bad_status)?,
        hci_version: bytes[1],
        hci_revision: LittleEndian::read_u16(&bytes[2..]),
        lmp_version: bytes[4],
        manufacturer_name: LittleEndian::read_u16(&bytes[5..]),
        lmp_subversion: LittleEndian::read_u16(&bytes[7..]),
    })
}

/// Values returned by the [Read Local Supported
/// Commands](crate::host::Hci::read_local_supported_commands) command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LocalSupportedCommands {
    /// Did the command fail, and if so, how?
    pub status: Status,

    /// Flags for supported commands.
    pub supported_commands: CommandFlags,
}

const COMMAND_FLAGS_SIZE: usize = 64;

bitflag_array! {
    /// Extended bit field for the command flags of the [`LocalSupportedCommands`] return
    /// parameters.
    #[derive(Copy, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct CommandFlags : COMMAND_FLAGS_SIZE;
    pub struct CommandFlag;

    /// Inquiry
    const INQUIRY = 0, 1 << 0;
    /// Cancel Inquiry
    const INQUIRY_CANCEL = 0, 1 << 1;
    /// Periodic Inquiry Mode
    const PERIODIC_INQUIRY_MODE = 0, 1 << 2;
    /// Exit Periodic Inquiry Mode
    const EXIT_PERIODIC_INQUIRY_MODE = 0, 1 << 3;
    /// Create Connection
    const CREATE_CONNECTION = 0, 1 << 4;
    /// Disconnect
    const DISCONNECT = 0, 1 << 5;
    /// Add SCO Connection (deprecated by the spec)
    #[deprecated]
    const ADD_SCO_CONNECTION = 0, 1 << 6;
    /// Create Connection Cancel
    const CREATE_CONNECTION_CANCEL = 0, 1 << 7;
    /// Accept Connection Request
    const ACCEPT_CONNECTION_REQUEST = 1, 1 << 0;
    /// Reject Connection Request
    const REJECT_CONNECTION_REQUEST = 1, 1 << 1;
    /// Link Key Request Reply
    const LINK_KEY_REQUEST_REPLY = 1, 1 << 2;
    /// Link Key Request Negative Reply
    const LINK_KEY_REQUEST_NEGATIVE_REPLY = 1, 1 << 3;
    /// PIN Code Request Reply
    const PIN_CODE_REQUEST_REPLY = 1, 1 << 4;
    /// PIN Code Request Negative Reply
    const PIN_CODE_REQUEST_NEGATIVE_REPLY = 1, 1 << 5;
    /// Change Connection Packet Type
    const CHANGE_CONNECTION_PACKET_TYPE = 1, 1 << 6;
    /// Authentication Requested
    const AUTHENTICATION_REQUESTED = 1, 1 << 7;
    /// Set Connection Encryption
    const SET_CONNECTION_ENCRYPTION = 2, 1 << 0;
    /// Change Connection Link Key
    const CHANGE_CONNECTION_LINK_KEY = 2, 1 << 1;
    /// Master Link Key
    const MASTER_LINK_KEY = 2, 1 << 2;
    /// Remote Name Request
    const REMOTE_NAME_REQUEST = 2, 1 << 3;
    /// Remote Name Request Cancel
    const REMOTE_NAME_REQUEST_CANCEL = 2, 1 << 4;
    /// Read Remote Supported Features
    const READ_REMOTE_SUPPORTED_FEATURES = 2, 1 << 5;
    /// Read Remote Extended Features
    const READ_REMOTE_EXTENDED_FEATURES = 2, 1 << 6;
    /// Read Remote Version Information
    const READ_REMOTE_VERSION_INFORMATION = 2, 1 << 7;
    /// Read Clock Offset
    const READ_CLOCK_OFFSET = 3, 1 << 0;
    /// Read LMP Handle
    const READ_LMP_HANDLE = 3, 1 << 1;
    /// Hold Mode
    const HOLD_MODE = 4, 1 << 1;
    /// Sniff Mode
    const SNIFF_MODE = 4, 1 << 2;
    /// Exit Sniff Mode
    const EXIT_SNIFF_MODE = 4, 1 << 3;
    /// Park State
    const PARK_STATE = 4, 1 << 4;
    /// Exit Park State
    const EXIT_PARK_STATE = 4, 1 << 5;
    /// QoS Setup
    const QOS_SETUP = 4, 1 << 6;
    /// Role Discovery
    const ROLE_DISCOVERY = 4, 1 << 7;
    /// Switch Role
    const SWITCH_ROLE = 5, 1 << 0;
    /// Read Link Policy Settings
    const READ_LINK_POLICY_SETTINGS = 5, 1 << 1;
    /// Write Link Policy Settings
    const WRITE_LINK_POLICY_SETTINGS = 5, 1 << 2;
    /// Read Default Link Policy Settings
    const READ_DEFAULT_LINK_POLICY_SETTINGS = 5, 1 << 3;
    /// Write Default Link Policy Settings
    const WRITE_DEFAULT_LINK_POLICY_SETTINGS = 5, 1 << 4;
    /// Flow Specification
    const FLOW_SPECIFICATION = 5, 1 << 5;
    /// Set Event Mask
    const SET_EVENT_MASK = 5, 1 << 6;
    /// Reset
    const RESET = 5, 1 << 7;
    /// Set Event Filter
    const SET_EVENT_FILTER = 6, 1 << 0;
    /// Flush
    const FLUSH = 6, 1 << 1;
    /// Read PIN Type
    const READ_PIN_TYPE = 6, 1 << 2;
    /// Write PIN Type
    const WRITE_PIN_TYPE = 6, 1 << 3;
    /// Create New Unit Key
    const CREATE_NEW_UNIT_KEY = 6, 1 << 4;
    /// Read Stored Link Key
    const READ_STORED_LINK_KEY = 6, 1 << 5;
    /// Write Stored Link Key
    const WRITE_STORED_LINK_KEY = 6, 1 << 6;
    /// Delete Stored Link Key
    const DELETE_STORED_LINK_KEY = 6, 1 << 7;
    /// Write Local Name
    const WRITE_LOCAL_NAME = 7, 1 << 0;
    /// Read Local Name
    const READ_LOCAL_NAME = 7, 1 << 1;
    /// Read Connection Accept Timeout
    const READ_CONNECTION_ACCEPT_TIMEOUT = 7, 1 << 2;
    /// Write Connection Accept Timeout
    const WRITE_CONNECTION_ACCEPT_TIMEOUT = 7, 1 << 3;
    /// Read Page Timeout
    const READ_PAGE_TIMEOUT = 7, 1 << 4;
    /// Write Page Timeout
    const WRITE_PAGE_TIMEOUT = 7, 1 << 5;
    /// Read Scan Enable
    const READ_SCAN_ENABLE = 7, 1 << 6;
    /// Write Scan Enable
    const WRITE_SCAN_ENABLE = 7, 1 << 7;
    /// Read Page Scan Activity
    const READ_PAGE_SCAN_ACTIVITY = 8, 1 << 0;
    /// Write Page Scan Activity
    const WRITE_PAGE_SCAN_ACTIVITY = 8, 1 << 1;
    /// Read Inquiry Scan Activity
    const READ_INQUIRY_SCAN_ACTIVITY = 8, 1 << 2;
    /// Write Inquiry Scan Activity
    const WRITE_INQUIRY_SCAN_ACTIVITY = 8, 1 << 3;
    /// Read Authentication Enable
    const READ_AUTHENTICATION_ENABLE = 8, 1 << 4;
    /// Write Authentication Enable
    const WRITE_AUTHENTICATION_ENABLE = 8, 1 << 5;
    /// Read Encryption Mode (deprecated by the spec)
    #[deprecated]
    const READ_ENCRYPTION_MODE = 8, 1 << 6;
    /// Write Encryption Mode (deprecated by the spec)
    #[deprecated]
    const WRITE_ENCRYPTION_MODE = 8, 1 << 7;
    /// Read Class Of Device
    const READ_CLASS_OF_DEVICE = 9, 1 << 0;
    /// Write Class Of Device
    const WRITE_CLASS_OF_DEVICE = 9, 1 << 1;
    /// Read Voice Setting
    const READ_VOICE_SETTING = 9, 1 << 2;
    /// Write Voice Setting
    const WRITE_VOICE_SETTING = 9, 1 << 3;
    /// Read Automatic Flush Timeout
    const READ_AUTOMATIC_FLUSH_TIMEOUT = 9, 1 << 4;
    /// Write Automatic Flush Timeout
    const WRITE_AUTOMATIC_FLUSH_TIMEOUT = 9, 1 << 5;
    /// Read Num Broadcast Retransmissions
    const READ_NUM_BROADCAST_RETRANSMISSIONS = 9, 1 << 6;
    /// Write Num Broadcast Retransmissions
    const WRITE_NUM_BROADCAST_RETRANSMISSIONS = 9, 1 << 7;
    /// Read Hold Mode Activity
    const READ_HOLD_MODE_ACTIVITY = 10, 1 << 0;
    /// Write Hold Mode Activity
    const WRITE_HOLD_MODE_ACTIVITY = 10, 1 << 1;
    /// Read Transmit Power Level
    const READ_TRANSMIT_POWER_LEVEL = 10, 1 << 2;
    /// Read Synchronous Flow Control Enable
    const READ_SYNCHRONOUS_FLOW_CONTROL_ENABLE = 10, 1 << 3;
    /// Write Synchronous Flow Control Enable
    const WRITE_SYNCHRONOUS_FLOW_CONTROL_ENABLE = 10, 1 << 4;
    /// Set Controller To Host Flow Control
    const SET_CONTROLLER_TO_HOST_FLOW_CONTROL = 10, 1 << 5;
    /// Host Buffer Size
    const HOST_BUFFER_SIZE = 10, 1 << 6;
    /// Host Number Of Completed Packets
    const HOST_NUMBER_OF_COMPLETED_PACKETS = 10, 1 << 7;
    /// Read Link Supervision Timeout
    const READ_LINK_SUPERVISION_TIMEOUT = 11, 1 << 0;
    /// Write Link Supervision Timeout
    const WRITE_LINK_SUPERVISION_TIMEOUT = 11, 1 << 1;
    /// Read Number of Supported IAC
    const READ_NUMBER_OF_SUPPORTED_IAC = 11, 1 << 2;
    /// Read Current IAC LAP
    const READ_CURRENT_IAC_LAP = 11, 1 << 3;
    /// Write Current IAC LAP
    const WRITE_CURRENT_IAC_LAP = 11, 1 << 4;
    /// Read Page Scan Mode Period (deprecated by the spec)
    #[deprecated]
    const READ_PAGE_SCAN_MODE_PERIOD = 11, 1 << 5;
    /// Write Page Scan Mode Period (deprecated by the spec)
    #[deprecated]
    const WRITE_PAGE_SCAN_MODE_PERIOD = 11, 1 << 6;
    /// Read Page Scan Mode (deprecated by the spec)
    #[deprecated]
    const READ_PAGE_SCAN_MODE = 11, 1 << 7;
    /// Write Page Scan Mode (deprecated by the spec)
    #[deprecated]
    const WRITE_PAGE_SCAN_MODE = 12, 1 << 0;
    /// Set AFH Host Channel Classification
    const SET_AFH_HOST_CHANNEL_CLASSIFICATION = 12, 1 << 1;
    /// Read Inquiry Scan Type
    const READ_INQUIRY_SCAN_TYPE = 12, 1 << 4;
    /// Write Inquiry Scan Type
    const WRITE_INQUIRY_SCAN_TYPE = 12, 1 << 5;
    /// Read Inquiry Mode
    const READ_INQUIRY_MODE = 12, 1 << 6;
    /// Write Inquiry Mode
    const WRITE_INQUIRY_MODE = 12, 1 << 7;
    /// Read Page Scan Type
    const READ_PAGE_SCAN_TYPE = 13, 1 << 0;
    /// Write Page Scan Type
    const WRITE_PAGE_SCAN_TYPE = 13, 1 << 1;
    /// Read AFH Channel Assessment Mode
    const READ_AFH_CHANNEL_ASSESSMENT_MODE = 13, 1 << 2;
    /// Write AFH Channel Assessment Mode
    const WRITE_AFH_CHANNEL_ASSESSMENT_MODE = 13, 1 << 3;
    /// Read Local Version Information
    const READ_LOCAL_VERSION_INFORMATION = 14, 1 << 3;
    /// Read Local Supported Features
    const READ_LOCAL_SUPPORTED_FEATURES = 14, 1 << 5;
    /// Read Local Extended Features
    const READ_LOCAL_EXTENDED_FEATURES = 14, 1 << 6;
    /// Read Buffer Size
    const READ_BUFFER_SIZE = 14, 1 << 7;
    /// Read Country Code [Deprecated by the spec]
    #[deprecated]
    const READ_COUNTRY_CODE = 15, 1 << 0;
    /// Read BD ADDR
    const READ_BD_ADDR = 15, 1 << 1;
    /// Read Failed Contact Counter
    const READ_FAILED_CONTACT_COUNTER = 15, 1 << 2;
    /// Reset Failed Contact Counter
    const RESET_FAILED_CONTACT_COUNTER = 15, 1 << 3;
    /// Read Link Quality
    const READ_LINK_QUALITY = 15, 1 << 4;
    /// Read RSSI
    const READ_RSSI = 15, 1 << 5;
    /// Read AFH Channel Map
    const READ_AFH_CHANNEL_MAP = 15, 1 << 6;
    /// Read Clock
    const READ_CLOCK = 15, 1 << 7;
    /// Read Loopback Mode
    const READ_LOOPBACK_MODE = 16, 1 << 0;
    /// Write Loopback Mode
    const WRITE_LOOPBACK_MODE = 16, 1 << 1;
    /// Enable Device Under Test Mode
    const ENABLE_DEVICE_UNDER_TEST_MODE = 16, 1 << 2;
    /// Setup Synchronous Connection Request
    const SETUP_SYNCHRONOUS_CONNECTION_REQUEST = 16, 1 << 3;
    /// Accept Synchronous Connection Request
    const ACCEPT_SYNCHRONOUS_CONNECTION_REQUEST = 16, 1 << 4;
    /// Reject Synchronous Connection Request
    const REJECT_SYNCHRONOUS_CONNECTION_REQUEST = 16, 1 << 5;
    /// Read Extended Inquiry Response
    const READ_EXTENDED_INQUIRY_RESPONSE = 17, 1 << 0;
    /// Write Extended Inquiry Response
    const WRITE_EXTENDED_INQUIRY_RESPONSE = 17, 1 << 1;
    /// Refresh Encryption Key
    const REFRESH_ENCRYPTION_KEY = 17, 1 << 2;
    /// Sniff Subrating
    const SNIFF_SUBRATING = 17, 1 << 4;
    /// Read Simple Pairing Mode
    const READ_SIMPLE_PAIRING_MODE = 17, 1 << 5;
    /// Write Simple Pairing Mode
    const WRITE_SIMPLE_PAIRING_MODE = 17, 1 << 6;
    /// Read Local OOB Data
    const READ_LOCAL_OOB_DATA = 17, 1 << 7;
    /// Read Inquiry Response Transmit Power Level
    const READ_INQUIRY_RESPONSE_TRANSMIT_POWER_LEVEL = 18, 1 << 0;
    /// Write Inquiry Transmit Power Level
    const WRITE_INQUIRY_TRANSMIT_POWER_LEVEL = 18, 1 << 1;
    /// Read Default Erroneous Data Reporting
    const READ_DEFAULT_ERRONEOUS_DATA_REPORTING = 18, 1 << 2;
    /// Write Default Erroneous Data Reporting
    const WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING = 18, 1 << 3;
    /// IO Capability Request Reply
    const IO_CAPABILITY_REQUEST_REPLY = 18, 1 << 7;
    /// User Confirmation Request Reply
    const USER_CONFIRMATION_REQUEST_REPLY = 19, 1 << 0;
    /// User Confirmation Request Negative Reply
    const USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY = 19, 1 << 1;
    /// User Passkey Request Reply
    const USER_PASSKEY_REQUEST_REPLY = 19, 1 << 2;
    /// User Passkey Request Negative Reply
    const USER_PASSKEY_REQUEST_NEGATIVE_REPLY = 19, 1 << 3;
    /// Remote OOB Data Request Reply
    const REMOTE_OOB_DATA_REQUEST_REPLY = 19, 1 << 4;
    /// Write Simple Pairing Debug Mode
    const WRITE_SIMPLE_PAIRING_DEBUG_MODE = 19, 1 << 5;
    /// Enhanced Flush
    const ENHANCED_FLUSH = 19, 1 << 6;
    /// Remote OOB Data Request Negative Reply
    const REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY = 19, 1 << 7;
    /// Send Keypress Notification
    const SEND_KEYPRESS_NOTIFICATION = 20, 1 << 2;
    /// IO Capability Request Negative Reply
    const IO_CAPABILITY_REQUEST_NEGATIVE_REPLY = 20, 1 << 3;
    /// Read Encryption Key Size
    const READ_ENCRYPTION_KEY_SIZE = 20, 1 << 4;
    /// Create Physical Link
    const CREATE_PHYSICAL_LINK = 21, 1 << 0;
    /// Accept Physical Link
    const ACCEPT_PHYSICAL_LINK = 21, 1 << 1;
    /// Disconnect Physical Link
    const DISCONNECT_PHYSICAL_LINK = 21, 1 << 2;
    /// Create Logical Link
    const CREATE_LOGICAL_LINK = 21, 1 << 3;
    /// Accept Logical Link
    const ACCEPT_LOGICAL_LINK = 21, 1 << 4;
    /// Disconnect Logical Link
    const DISCONNECT_LOGICAL_LINK = 21, 1 << 5;
    /// Logical Link Cancel
    const LOGICAL_LINK_CANCEL = 21, 1 << 6;
    /// Flow Spec Modify
    const FLOW_SPEC_MODIFY = 21, 1 << 7;
    /// Read Logical Link Accept Timeout
    const READ_LOGICAL_LINK_ACCEPT_TIMEOUT = 22, 1 << 0;
    /// Write Logical Link Accept Timeout
    const WRITE_LOGICAL_LINK_ACCEPT_TIMEOUT = 22, 1 << 1;
    /// Set Event Mask Page 2
    const SET_EVENT_MASK_PAGE_2 = 22, 1 << 2;
    /// Read Location Data
    const READ_LOCATION_DATA = 22, 1 << 3;
    /// Write Location Data
    const WRITE_LOCATION_DATA = 22, 1 << 4;
    /// Read Local AMP Info
    const READ_LOCAL_AMP_INFO = 22, 1 << 5;
    /// Read Local AMP_ASSOC
    const READ_LOCAL_AMP_ASSOC = 22, 1 << 6;
    /// Write Remote AMP_ASSOC
    const WRITE_REMOTE_AMP_ASSOC = 22, 1 << 7;
    /// Read Flow Control Mode
    const READ_FLOW_CONTROL_MODE = 23, 1 << 0;
    /// Write Flow Control Mode
    const WRITE_FLOW_CONTROL_MODE = 23, 1 << 1;
    /// Read Data Block Size
    const READ_DATA_BLOCK_SIZE = 23, 1 << 2;
    /// Enable AMP Receiver Reports
    const ENABLE_AMP_RECEIVER_REPORTS = 23, 1 << 5;
    /// AMP Test End
    const AMP_TEST_END = 23, 1 << 6;
    /// AMP Test
    const AMP_TEST = 23, 1 << 7;
    /// Read Enhanced Transmit Power Level
    const READ_ENHANCED_TRANSMIT_POWER_LEVEL = 24, 1 << 0;
    /// Read Best Effort Flush Timeout
    const READ_BEST_EFFORT_FLUSH_TIMEOUT = 24, 1 << 2;
    /// Write Best Effort Flush Timeout
    const WRITE_BEST_EFFORT_FLUSH_TIMEOUT = 24, 1 << 3;
    /// Short Range Mode
    const SHORT_RANGE_MODE = 24, 1 << 4;
    /// Read LE Host Support
    const READ_LE_HOST_SUPPORT = 24, 1 << 5;
    /// Write LE Host Support
    const WRITE_LE_HOST_SUPPORT = 24, 1 << 6;
    /// LE Set Event Mask
    const LE_SET_EVENT_MASK = 25, 1 << 0;
    /// LE Read Buffer Size
    const LE_READ_BUFFER_SIZE = 25, 1 << 1;
    /// LE Read Local Supported Features
    const LE_READ_LOCAL_SUPPORTED_FEATURES = 25, 1 << 2;
    /// LE Set Random Address
    const LE_SET_RANDOM_ADDRESS = 25, 1 << 4;
    /// LE Set Advertising Parameters
    const LE_SET_ADVERTISING_PARAMETERS = 25, 1 << 5;
    /// LE Read Advertising Channel TX Power
    const LE_READ_ADVERTISING_CHANNEL_TX_POWER = 25, 1 << 6;
    /// LE Set Advertising Data
    const LE_SET_ADVERTISING_DATA = 25, 1 << 7;
    /// LE Set Scan Response Data
    const LE_SET_SCAN_RESPONSE_DATA = 26, 1 << 0;
    /// LE Set Advertise Enable
    const LE_SET_ADVERTISE_ENABLE = 26, 1 << 1;
    /// LE Set Scan Parameters
    const LE_SET_SCAN_PARAMETERS = 26, 1 << 2;
    /// LE Set Scan Enable
    const LE_SET_SCAN_ENABLE = 26, 1 << 3;
    /// LE Create Connection
    const LE_CREATE_CONNECTION = 26, 1 << 4;
    /// LE Create Connection Cancel
    const LE_CREATE_CONNECTION_CANCEL = 26, 1 << 5;
    /// LE Read White List Size
    const LE_READ_WHITE_LIST_SIZE = 26, 1 << 6;
    /// LE Clear White List
    const LE_CLEAR_WHITE_LIST = 26, 1 << 7;
    /// LE Add Device To White List
    const LE_ADD_DEVICE_TO_WHITE_LIST = 27, 1 << 0;
    /// LE Remove Device From White List
    const LE_REMOVE_DEVICE_FROM_WHITE_LIST = 27, 1 << 1;
    /// LE Connection Update
    const LE_CONNECTION_UPDATE = 27, 1 << 2;
    /// LE Set Host Channel Classification
    const LE_SET_HOST_CHANNEL_CLASSIFICATION = 27, 1 << 3;
    /// LE Read Channel Map
    const LE_READ_CHANNEL_MAP = 27, 1 << 4;
    /// LE Read Remote Used Features
    const LE_READ_REMOTE_USED_FEATURES = 27, 1 << 5;
    /// LE Encrypt
    const LE_ENCRYPT = 27, 1 << 6;
    /// LE Rand
    const LE_RAND = 27, 1 << 7;
    /// LE Start Encryption
    const LE_START_ENCRYPTION = 28, 1 << 0;
    /// LE Long Term Key Request Reply
    const LE_LONG_TERM_KEY_REQUEST_REPLY = 28, 1 << 1;
    /// LE Long Term Key Request Negative Reply
    const LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY = 28, 1 << 2;
    /// LE Read Supported States
    const LE_READ_SUPPORTED_STATES = 28, 1 << 3;
    /// LE Receiver Test
    const LE_RECEIVER_TEST = 28, 1 << 4;
    /// LE Transmitter Test
    const LE_TRANSMITTER_TEST = 28, 1 << 5;
    /// LE Test End
    const LE_TEST_END = 28, 1 << 6;
    /// Enhanced Setup Synchronous Connection
    const ENHANCED_SETUP_SYNCHRONOUS_CONNECTION = 29, 1 << 3;
    /// Enhanced Accept Synchronous Connection
    const ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION = 29, 1 << 4;
    /// Read Local Supported Codecs
    const READ_LOCAL_SUPPORTED_CODECS = 29, 1 << 5;
    /// Set MWS Channel Parameters Command
    const SET_MWS_CHANNEL_PARAMETERS_COMMAND = 29, 1 << 6;
    /// Set External Frame Configuration Command
    const SET_EXTERNAL_FRAME_CONFIGURATION_COMMAND = 29, 1 << 7;
    /// Set MWS Signaling Command
    const SET_MWS_SIGNALING_COMMAND = 30, 1 << 0;
    /// Set Transport Layer Command
    const SET_TRANSPORT_LAYER_COMMAND = 30, 1 << 1;
    /// Set MWS Scan Frequency Table Command
    const SET_MWS_SCAN_FREQUENCY_TABLE_COMMAND = 30, 1 << 2;
    /// Get Transport Layer Configuration Command
    const GET_TRANSPORT_LAYER_CONFIGURATION_COMMAND = 30, 1 << 3;
    /// Set MWS PATTERN Configuration Command
    const SET_MWS_PATTERN_CONFIGURATION_COMMAND = 30, 1 << 4;
    /// Set Triggered Clock Capture
    const SET_TRIGGERED_CLOCK_CAPTURE = 30, 1 << 5;
    /// Truncated Page
    const TRUNCATED_PAGE = 30, 1 << 6;
    /// Truncated Page Cancel
    const TRUNCATED_PAGE_CANCEL = 30, 1 << 7;
    /// Set Connectionless Peripheral Broadcast
    const SET_CONNECTIONLESS_PERIPHERAL_BROADCAST = 31, 1 << 0;
    /// Set Connectionless Peripheral Broadcast Receive
    const SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVE = 31, 1 << 1;
    /// Start Synchronization Train
    const START_SYNCHRONIZATION_TRAIN = 31, 1 << 2;
    /// Receive Synchronization Train
    const RECEIVE_SYNCHRONIZATION_TRAIN = 31, 1 << 3;
    /// Set Connectionless Peripheral Broadcast Data
    const SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_DATA = 31, 1 << 6;
    /// Read Synchronization Train Parameters
    const READ_SYNCHRONIZATION_TRAIN_PARAMETERS = 31, 1 << 7;
    /// Write Synchronization Train Parameters
    const WRITE_SYNCHRONIZATION_TRAIN_PARAMETERS = 32, 1 << 0;
    /// Remote OOB Extended Data Request Reply
    const REMOTE_OOB_EXTENDED_DATA_REQUEST_REPLY = 32, 1 << 1;
    /// Read Secure Connections Host Support
    const READ_SECURE_CONNECTIONS_HOST_SUPPORT = 32, 1 << 2;
    /// Write Secure Connections Host Support
    const WRITE_SECURE_CONNECTIONS_HOST_SUPPORT = 32, 1 << 3;
    /// Read Authenticated Payload Timeout
    const READ_AUTHENTICATED_PAYLOAD_TIMEOUT = 32, 1 << 4;
    /// Write Authenticated Payload Timeout
    const WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT = 32, 1 << 5;
    /// Read Local OOB Extended Data
    const READ_LOCAL_OOB_EXTENDED_DATA = 32, 1 << 6;
    /// Write Secure Connections Test Mode
    const WRITE_SECURE_CONNECTIONS_TEST_MODE = 32, 1 << 7;
    /// Read Extended Page Timeout
    const READ_EXTENDED_PAGE_TIMEOUT = 33, 1 << 0;
    /// Write Extended Page Timeout
    const WRITE_EXTENDED_PAGE_TIMEOUT = 33, 1 << 1;
    /// Read Extended Inquiry Length
    const READ_EXTENDED_INQUIRY_LENGTH = 33, 1 << 2;
    /// Write Extended Inquiry Length
    const WRITE_EXTENDED_INQUIRY_LENGTH = 33, 1 << 3;
    /// LE Remote Connection Parameter Request Reply Command
    const LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY_COMMAND = 33, 1 << 4;
    /// LE Remote Connection Parameter Request Negative Reply Command
    const LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY_COMMAND = 33, 1 << 5;
    /// LE Set Data Length
    const LE_SET_DATA_LENGTH = 33, 1 << 6;
    /// LE Read Suggested Default Data Length
    const LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH = 33, 1 << 7;
    /// LE Write Suggested Default Data Length
    const LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH = 34, 1 << 0;
    /// LE Read Local P-256 Public Key
    const LE_READ_LOCAL_P256_PUBLIC_KEY = 34, 1 << 1;
    /// LE Generate DH Key
    const LE_GENERATE_DH_KEY = 34, 1 << 2;
    /// LE Add Device To Resolving List
    const LE_ADD_DEVICE_TO_RESOLVING_LIST = 34, 1 << 3;
    /// LE Remove Device From Resolving List
    const LE_REMOVE_DEVICE_FROM_RESOLVING_LIST = 34, 1 << 4;
    /// LE Clear Resolving List
    const LE_CLEAR_RESOLVING_LIST = 34, 1 << 5;
    /// LE Read Resolving List Size
    const LE_READ_RESOLVING_LIST_SIZE = 34, 1 << 6;
    /// LE Read Peer Resolvable Address
    const LE_READ_PEER_RESOLVABLE_ADDRESS = 34, 1 << 7;
    /// LE Read Local Resolvable Address
    const LE_READ_LOCAL_RESOLVABLE_ADDRESS = 35, 1 << 0;
    /// LE Set Address Resolution Enable
    const LE_SET_ADDRESS_RESOLUTION_ENABLE = 35, 1 << 1;
    /// LE Set Resolvable Private Address Timeout
    const LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT = 35, 1 << 2;
    /// LE Read Maximum Data Length
    const LE_READ_MAXIMUM_DATA_LENGTH = 35, 1 << 3;
    /// LE Read PHY Command
    const LE_READ_PHY_COMMAND = 35, 1 << 4;
    /// LE Set Default PHY Command
    const LE_SET_DEFAULT_PHY_COMMAND = 35, 1 << 5;
    /// LE Set PHY Command
    const LE_SET_PHY_COMMAND = 35, 1 << 6;
    /// LE Enhanced Receiver Test Command
    const LE_ENHANCED_RECEIVER_TEST_COMMAND = 35, 1 << 7;
    /// LE Enhanced Transmitter Test Command
    const LE_ENHANCED_TRANSMITTER_TEST_COMMAND = 36, 1 << 0;
    /// LE Set Advertising Set Random Address Command
    const LE_SET_ADVERTISING_SET_RANDOM_ADDRESS_COMMAND = 36, 1 << 1;
    /// LE Set Extended Advertising Parameters Command
    const LE_SET_EXTENDED_ADVERTISING_PARAMETERS_COMMAND = 36, 1 << 2;
    /// LE Set Extended Advertising Data Command
    const LE_SET_EXTENDED_ADVERTISING_DATA_COMMAND = 36, 1 << 3;
    /// LE Set Extended Scan Response Data Command
    const LE_SET_EXTENDED_SCAN_RESPONSE_DATA_COMMAND = 36, 1 << 4;
    /// LE Set Extended Advertising Enable Command
    const LE_SET_EXTENDED_ADVERTISING_ENABLE_COMMAND = 36, 1 << 5;
    /// LE Read Maximum Advertising Data Length Command
    const LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_COMMAND = 36, 1 << 6;
    /// LE Read Number of Supported Advertising Sets Command
    const LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_COMMAND = 36, 1 << 7;
    /// LE Remove Advertising Set Command
    const LE_REMOVE_ADVERTISING_SET_COMMAND = 37, 1 << 0;
    /// LE Clear Advertising Sets Command
    const LE_CLEAR_ADVERTISING_SETS_COMMAND = 37, 1 << 1;
    /// LE Set Periodic Advertising Parameters Command
    const LE_SET_PERIODIC_ADVERTISING_PARAMETERS_COMMAND = 37, 1 << 2;
    /// LE Set Periodic Advertising Data Command
    const LE_SET_PERIODIC_ADVERTISING_DATA_COMMAND = 37, 1 << 3;
    /// LE Set Periodic Advertising Enable Command
    const LE_SET_PERIODIC_ADVERTISING_ENABLE_COMMAND = 37, 1 << 4;
    /// LE Set Extended Scan Parameters Command
    const LE_SET_EXTENDED_SCAN_PARAMETERS_COMMAND = 37, 1 << 5;
    /// LE Set Extended Scan Enable Command
    const LE_SET_EXTENDED_SCAN_ENABLE_COMMAND = 37, 1 << 6;
    /// LE Extended Create Connection Command
    const LE_EXTENDED_CREATE_CONNECTION_COMMAND = 37, 1 << 7;
    /// LE Periodic Advertising Create Sync Command
    const LE_PERIODIC_ADVERTISING_CREATE_SYNC_COMMAND = 38, 1 << 0;
    /// LE Periodic Advertising Create Sync Cancel Command
    const LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL_COMMAND = 38, 1 << 1;
    /// LE Periodic Advertising Terminate Sync Command
    const LE_PERIODIC_ADVERTISING_TERMINATE_SYNC_COMMAND = 38, 1 << 2;
    /// LE Add Device To Periodic Advertiser List Command
    const LE_ADD_DEVICE_TO_PERIODIC_ADVERTISER_LIST_COMMAND = 38, 1 << 3;
    /// LE Remove Device From Periodic Advertiser List Command
    const LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISER_LIST_COMMAND = 38, 1 << 4;
    /// LE Clear Periodic Advertiser List Command
    const LE_CLEAR_PERIODIC_ADVERTISER_LIST_COMMAND = 38, 1 << 5;
    /// LE Read Periodic Advertiser List Size Command
    const LE_READ_PERIODIC_ADVERTISER_LIST_SIZE_COMMAND = 38, 1 << 6;
    /// LE Read Transmit Power Command
    const LE_READ_TRANSMIT_POWER_COMMAND = 38, 1 << 7;
    /// LE Read RF Path Compensation Command
    const LE_READ_RF_PATH_COMPENSATION_COMMAND = 39, 1 << 0;
    /// LE Write RF Path Compensation Command
    const LE_WRITE_RF_PATH_COMPENSATION_COMMAND = 39, 1 << 1;
    /// LE Set Privacy Mode
    const LE_SET_PRIVACY_MODE = 39, 1 << 2;
}

impl Debug for CommandFlags {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        writeln!(f, "{:?}", &self.0[..16])?;
        writeln!(f, "{:?}", &self.0[16..32])?;
        writeln!(f, "{:?}", &self.0[32..39])
    }
}

impl<'a> TryFrom<&'a [u8]> for CommandFlags {
    type Error = crate::event::Error;
    fn try_from(value: &[u8]) -> Result<CommandFlags, Self::Error> {
        require_len!(value, COMMAND_FLAGS_SIZE);

        CommandFlags::from_bits(value).ok_or(crate::event::Error::BadCommandFlag)
    }
}

fn to_supported_commands(bytes: &[u8]) -> Result<LocalSupportedCommands, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 1 + COMMAND_FLAGS_SIZE);
    Ok(LocalSupportedCommands {
        status: bytes[0].try_into().map_err(super::rewrap_bad_status)?,
        supported_commands: bytes[1..=COMMAND_FLAGS_SIZE]
            .try_into()
            .map_err(|e| match e {
                crate::event::Error::BadLength(actual, expected) => {
                    crate::event::Error::BadLength(actual, expected)
                }
                crate::event::Error::BadCommandFlag => crate::event::Error::BadCommandFlag,
                _ => unreachable!(),
            })?,
    })
}

/// Values returned by the [Read Local Supported
/// Features](crate::host::Hci::read_local_supported_features) command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LocalSupportedFeatures {
    /// Did the command fail, and if so, how?
    pub status: Status,

    /// Flags for supported features.
    pub supported_features: LmpFeatures,
}

#[cfg(not(feature = "defmt"))]
bitflags::bitflags! {
    /// See the Bluetooth Specification, v4.1 or later, Vol 2, Part C, Section 3.3 (Table 3.2).
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct LmpFeatures : u64 {
        /// 3-slot packets
        const THREE_SLOT_PACKETS = 1 << 0;
        /// 5-slot packets
        const FIVE_SLOT_PACKETS = 1 << 1;
        /// Encryption
        const ENCRYPTION = 1 << 2;
        /// Slot offset
        const SLOT_OFFSET = 1 << 3;
        /// Timing accuracy
        const TIMING_ACCURACY = 1 << 4;
        /// Role switch
        const ROLE_SWITCH = 1 << 5;
        /// Hold mode
        const HOLD_MODE = 1 << 6;
        /// Sniff mode
        const SNIFF_MODE = 1 << 7;
        /// Power control requests
        const POWER_CONTROL_REQUESTS = 1 << 9;
        /// Channel quality driven data rate (CQDDR)
        const CHANNEL_QUALITY_DRIVEN_DATA_RATE_CQDDR = 1 << 10;
        /// SCO link
        const SCO_LINK = 1 << 11;
        /// HV2 packets
        const HV2_PACKETS = 1 << 12;
        /// HV3 packets
        const HV3_PACKETS = 1 << 13;
        /// μ-law log synchronous data
        const MU_LAW_LOG_SYNCHRONOUS_DATA = 1 << 14;
        /// A-law log synchronous data
        const A_LAW_LOG_SYNCHRONOUS_DATA = 1 << 15;
        /// CVSD synchronous data
        const CVSD_SYNCHRONOUS_DATA = 1 << 16;
        /// Paging parameter negotiation
        const PAGING_PARAMETER_NEGOTIATION = 1 << 17;
        /// Power control
        const POWER_CONTROL = 1 << 18;
        /// Transparent synchronous data
        const TRANSPARENT_SYNCHRONOUS_DATA = 1 << 19;
        /// Flow control lag (least significant bit)
        const FLOW_CONTROL_LAG_LSB = 1 << 20;
        /// Flow control lag (middle bit)
        const FLOW_CONTROL_LAG_MID = 1 << 21;
        /// Flow control lag (most significant bit)
        const FLOW_CONTROL_LAG_MSB = 1 << 22;
        /// Broadcast Encryption
        const BROADCAST_ENCRYPTION = 1 << 23;
        /// Enhanced Data Rate ACL 2 Mb/s mode
        const ENHANCED_DATA_RATE_ACL_2_MB_PER_S_MODE = 1 << 25;
        /// Enhanced Data Rate ACL 3 Mb/s mode
        const ENHANCED_DATA_RATE_ACL_3_MB_PER_S_MODE = 1 << 26;
        /// Enhanced inquiry scan
        const ENHANCED_INQUIRY_SCAN = 1 << 27;
        /// Interlaced inquiry scan
        const INTERLACED_INQUIRY_SCAN = 1 << 28;
        /// Interlaced page scan
        const INTERLACED_PAGE_SCAN = 1 << 29;
        /// RSSI with inquiry results
        const RSSI_WITH_INQUIRY_RESULTS = 1 << 30;
        /// Extended SCO link (EV3 packets)
        const EXTENDED_SCO_LINK_EV3_PACKETS = 1 << 31;
        /// EV4 packets
        const EV4_PACKETS = 1 << 32;
        /// EV5 packets
        const EV5_PACKETS = 1 << 33;
        /// AFH capable peripheral
        const AFH_CAPABLE_PERIPHERAL = 1 << 35;
        /// AFH classification peripheral
        const AFH_CLASSIFICATION_PERIPHERAL = 1 << 36;
        /// BR/EDR Not Supported
        const BR_EDR_NOT_SUPPORTED = 1 << 37;
        /// LE Supported (Controller)
        const LE_SUPPORTED_BY_CONTROLLER = 1 << 38;
        /// 3-slot Enhanced Data Rate ACL packets
        const THREE_SLOT_ENHANCED_DATA_RATE_ACL_PACKETS = 1 << 39;
        /// 5-slot Enhanced Data Rate ACL packets
        const FIVE_SLOT_ENHANCED_DATA_RATE_ACL_PACKETS = 1 << 40;
        /// Sniff subrating
        const SNIFF_SUBRATING = 1 << 41;
        /// Pause encryption
        const PAUSE_ENCRYPTION = 1 << 42;
        /// AFH capable central device
        const AFH_CAPABLE_CENTRAL_DEVICE = 1 << 43;
        /// AFH classification central device
        const AFH_CLASSIFICATION_CENTRAL_DEVICE = 1 << 44;
        /// Enhanced Data Rate eSCO 2 Mb/s mode
        const ENHANCED_DATA_RATE_ESCO_2_MB_PER_S_MODE = 1 << 45;
        /// Enhanced Data Rate eSCO 3 Mb/s mode
        const ENHANCED_DATA_RATE_ESCO_3_MB_PER_S_MODE = 1 << 46;
        /// 3-slot Enhanced Data Rate eSCO packets
        const THREE_SLOT_ENHANCED_DATA_RATE_ESCO_PACKETS = 1 << 47;
        /// Extended Inquiry Response
        const EXTENDED_INQUIRY_RESPONSE = 1 << 48;
        /// Simultaneous LE and BR/EDR to Same Device Capable (Controller)
        const SIMULTANEOUS_LE_AND_BR_EDR_TO_SAME_DEVICE_CAPABLE = 1 << 49;
        /// Secure Simple Pairing
        const SECURE_SIMPLE_PAIRING = 1 << 51;
        /// Encapsulated PDU
        const ENCAPSULATED_PDU = 1 << 52;
        /// Erroneous Data Reporting
        const ERRONEOUS_DATA_REPORTING = 1 << 53;
        /// Non-flushable Packet Boundary Flag
        const NON_FLUSHABLE_PACKET_BOUNDARY_FLAG = 1 << 54;
        /// Link Supervision Timeout Changed Event
        const LINK_SUPERVISION_TIMEOUT_CHANGED_EVENT = 1 << 56;
        /// Inquiry TX Power Level
        const INQUIRY_TX_POWER_LEVEL = 1 << 57;
        /// Enhanced Power Control
        const ENHANCED_POWER_CONTROL = 1 << 58;
        /// Extended features
        const EXTENDED_FEATURES = 1 << 63;
    }
}

#[cfg(feature = "defmt")]
defmt::bitflags! {
    /// See the Bluetooth Specification, v4.1 or later, Vol 2, Part C, Section 3.3 (Table 3.2).
    #[derive(Default)]
    pub struct LmpFeatures : u64 {
        /// 3-slot packets
        const THREE_SLOT_PACKETS = 1 << 0;
        /// 5-slot packets
        const FIVE_SLOT_PACKETS = 1 << 1;
        /// Encryption
        const ENCRYPTION = 1 << 2;
        /// Slot offset
        const SLOT_OFFSET = 1 << 3;
        /// Timing accuracy
        const TIMING_ACCURACY = 1 << 4;
        /// Role switch
        const ROLE_SWITCH = 1 << 5;
        /// Hold mode
        const HOLD_MODE = 1 << 6;
        /// Sniff mode
        const SNIFF_MODE = 1 << 7;
        /// Power control requests
        const POWER_CONTROL_REQUESTS = 1 << 9;
        /// Channel quality driven data rate (CQDDR)
        const CHANNEL_QUALITY_DRIVEN_DATA_RATE_CQDDR = 1 << 10;
        /// SCO link
        const SCO_LINK = 1 << 11;
        /// HV2 packets
        const HV2_PACKETS = 1 << 12;
        /// HV3 packets
        const HV3_PACKETS = 1 << 13;
        /// μ-law log synchronous data
        const MU_LAW_LOG_SYNCHRONOUS_DATA = 1 << 14;
        /// A-law log synchronous data
        const A_LAW_LOG_SYNCHRONOUS_DATA = 1 << 15;
        /// CVSD synchronous data
        const CVSD_SYNCHRONOUS_DATA = 1 << 16;
        /// Paging parameter negotiation
        const PAGING_PARAMETER_NEGOTIATION = 1 << 17;
        /// Power control
        const POWER_CONTROL = 1 << 18;
        /// Transparent synchronous data
        const TRANSPARENT_SYNCHRONOUS_DATA = 1 << 19;
        /// Flow control lag (least significant bit)
        const FLOW_CONTROL_LAG_LSB = 1 << 20;
        /// Flow control lag (middle bit)
        const FLOW_CONTROL_LAG_MID = 1 << 21;
        /// Flow control lag (most significant bit)
        const FLOW_CONTROL_LAG_MSB = 1 << 22;
        /// Broadcast Encryption
        const BROADCAST_ENCRYPTION = 1 << 23;
        /// Enhanced Data Rate ACL 2 Mb/s mode
        const ENHANCED_DATA_RATE_ACL_2_MB_PER_S_MODE = 1 << 25;
        /// Enhanced Data Rate ACL 3 Mb/s mode
        const ENHANCED_DATA_RATE_ACL_3_MB_PER_S_MODE = 1 << 26;
        /// Enhanced inquiry scan
        const ENHANCED_INQUIRY_SCAN = 1 << 27;
        /// Interlaced inquiry scan
        const INTERLACED_INQUIRY_SCAN = 1 << 28;
        /// Interlaced page scan
        const INTERLACED_PAGE_SCAN = 1 << 29;
        /// RSSI with inquiry results
        const RSSI_WITH_INQUIRY_RESULTS = 1 << 30;
        /// Extended SCO link (EV3 packets)
        const EXTENDED_SCO_LINK_EV3_PACKETS = 1 << 31;
        /// EV4 packets
        const EV4_PACKETS = 1 << 32;
        /// EV5 packets
        const EV5_PACKETS = 1 << 33;
        /// AFH capable peripheral
        const AFH_CAPABLE_PERIPHERAL = 1 << 35;
        /// AFH classification peripheral
        const AFH_CLASSIFICATION_PERIPHERAL = 1 << 36;
        /// BR/EDR Not Supported
        const BR_EDR_NOT_SUPPORTED = 1 << 37;
        /// LE Supported (Controller)
        const LE_SUPPORTED_BY_CONTROLLER = 1 << 38;
        /// 3-slot Enhanced Data Rate ACL packets
        const THREE_SLOT_ENHANCED_DATA_RATE_ACL_PACKETS = 1 << 39;
        /// 5-slot Enhanced Data Rate ACL packets
        const FIVE_SLOT_ENHANCED_DATA_RATE_ACL_PACKETS = 1 << 40;
        /// Sniff subrating
        const SNIFF_SUBRATING = 1 << 41;
        /// Pause encryption
        const PAUSE_ENCRYPTION = 1 << 42;
        /// AFH capable central device
        const AFH_CAPABLE_CENTRAL_DEVICE = 1 << 43;
        /// AFH classification central device
        const AFH_CLASSIFICATION_CENTRAL_DEVICE = 1 << 44;
        /// Enhanced Data Rate eSCO 2 Mb/s mode
        const ENHANCED_DATA_RATE_ESCO_2_MB_PER_S_MODE = 1 << 45;
        /// Enhanced Data Rate eSCO 3 Mb/s mode
        const ENHANCED_DATA_RATE_ESCO_3_MB_PER_S_MODE = 1 << 46;
        /// 3-slot Enhanced Data Rate eSCO packets
        const THREE_SLOT_ENHANCED_DATA_RATE_ESCO_PACKETS = 1 << 47;
        /// Extended Inquiry Response
        const EXTENDED_INQUIRY_RESPONSE = 1 << 48;
        /// Simultaneous LE and BR/EDR to Same Device Capable (Controller)
        const SIMULTANEOUS_LE_AND_BR_EDR_TO_SAME_DEVICE_CAPABLE = 1 << 49;
        /// Secure Simple Pairing
        const SECURE_SIMPLE_PAIRING = 1 << 51;
        /// Encapsulated PDU
        const ENCAPSULATED_PDU = 1 << 52;
        /// Erroneous Data Reporting
        const ERRONEOUS_DATA_REPORTING = 1 << 53;
        /// Non-flushable Packet Boundary Flag
        const NON_FLUSHABLE_PACKET_BOUNDARY_FLAG = 1 << 54;
        /// Link Supervision Timeout Changed Event
        const LINK_SUPERVISION_TIMEOUT_CHANGED_EVENT = 1 << 56;
        /// Inquiry TX Power Level
        const INQUIRY_TX_POWER_LEVEL = 1 << 57;
        /// Enhanced Power Control
        const ENHANCED_POWER_CONTROL = 1 << 58;
        /// Extended features
        const EXTENDED_FEATURES = 1 << 63;
    }
}

fn to_supported_features(bytes: &[u8]) -> Result<LocalSupportedFeatures, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 9);
    Ok(LocalSupportedFeatures {
        status: to_status(bytes)?,
        supported_features: LmpFeatures::from_bits_truncate(LittleEndian::read_u64(&bytes[1..])),
    })
}

/// Values returned by the [Read BD ADDR](crate::host::Hci::read_bd_addr) command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReadBdAddr {
    /// Did the command fail, and if so, how?
    pub status: Status,

    /// Address of the device.
    pub bd_addr: crate::BdAddr,
}

fn to_bd_addr(bytes: &[u8]) -> Result<ReadBdAddr, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 7);
    let mut bd_addr = crate::BdAddr([0; 6]);
    bd_addr.0.copy_from_slice(&bytes[1..]);
    Ok(ReadBdAddr {
        status: to_status(bytes)?,
        bd_addr,
    })
}

/// Values returned by the [Read RSSI](crate::host::Hci::read_rssi) command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReadRssi {
    /// Did the command fail, and if so, how?
    pub status: Status,

    /// The Handle for the connection for which the RSSI has been read.
    ///
    /// The Handle is a connection handle for a BR/EDR Controller and a physical link handle for an
    /// AMP Controller.
    pub conn_handle: ConnectionHandle,

    /// - BR/EDR
    ///   - No range restriction
    ///   - Units: dB
    /// - AMP:
    ///   - Range: AMP type specific
    ///   - Units: dBm
    /// - LE:
    ///   - Range: -127 to 20, range not checked by this implementation. 127 indicates RSSI not
    ///     available.
    ///   - Units: dBm
    pub rssi: i8,
}

fn to_read_rssi(bytes: &[u8]) -> Result<ReadRssi, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 4);
    Ok(ReadRssi {
        status: to_status(bytes)?,
        conn_handle: ConnectionHandle(LittleEndian::read_u16(&bytes[1..])),
        rssi: unsafe { mem::transmute::<u8, i8>(bytes[3]) },
    })
}

/// Values returned by the [LE Read Buffer Size](crate::host::Hci::le_read_buffer_size) command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeReadBufferSize {
    /// Did the command fail, and if so, how?
    pub status: Status,

    /// The size of the L2CAP PDU segments contained in ACL Data Packets, which are transferred from
    /// the Host to the Controller to be broken up into packets by the Link Layer. Both the Host and
    /// the Controller shall support command and event packets, where the data portion (excluding
    /// header) contained in the packets is 255 octets in size.
    ///
    /// Note: Does not include the length of the HCI Data Packet header.
    ///
    /// If `data_packet_count` is 0, then the controller has no dedicated LE read buffer, so the
    /// caller should use the `read_buffer_size` command.
    pub data_packet_length: u16,

    /// Contains the total number of HCI ACL Data Packets that can be stored in the data buffers of
    /// the Controller. The Host determines how the buffers are to be divided between different
    /// Connection Handles.
    ///
    /// If `data_packet_count` is 0, then the controller has no dedicated LE read buffer, so the
    /// caller should use the `read_buffer_size` command.
    pub data_packet_count: u8,
}

fn to_le_read_buffer_status(bytes: &[u8]) -> Result<LeReadBufferSize, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 4);
    Ok(LeReadBufferSize {
        status: to_status(bytes)?,
        data_packet_length: LittleEndian::read_u16(&bytes[1..]),
        data_packet_count: bytes[3],
    })
}

/// Values returned by the [LE Read Local Supported
/// Features](crate::host::Hci::le_read_local_supported_features) command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeSupportedFeatures {
    /// Did the command fail, and if so, how?
    pub status: Status,

    /// Supported LE features.
    pub supported_features: LeFeatures,
}

#[cfg(not(feature = "defmt"))]
bitflags::bitflags! {
    /// Possible LE features for the [LE Read Local Supported
    /// Features](::host::Hci::le_read_local_supported_features) command.  See the Bluetooth
    /// specification, Vol 6, Part B, Section 4.6.  See Table 4.3 (v4.1 of the spec), Table 4.4
    /// (v4.2 and v5.0).
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct LeFeatures : u64 {
        /// LE Encryption.  Valid from controller to controller.
        const ENCRYPTION = 1 << 0;
        /// Connection Parameters Request Procedure.  Valid from controller to controller.
        const CONNECTION_PARAMETERS_REQUEST_PROCEDURE = 1 << 1;
        /// Extended Reject Indication.  Valid from controller to controller.
        const EXTENDED_REJECT_INDICATION = 1 << 2;
        /// Peripheral-initiated Features Exchange.  Valid from controller to controller.
        const PERIPHERALINITIATED_FEATURES_EXCHANGE = 1 << 3;
        /// LE Ping.  Not valid from controller to controller.
        const PING = 1 << 4;
        /// LE Data Packet Length Extension.  Valid from controller to controller.
        const DATA_PACKET_LENGTH_EXTENSION = 1 << 5;
        /// LL Privacy.  Not valid from controller to controller.
        const LL_PRIVACY = 1 << 6;
        /// Extended Scanner Filter Policies.  Not valid from controller to controller.
        const EXTENDED_SCANNER_FILTER_POLICIES = 1 << 7;
        /// LE 2M PHY.  Valid from controller to controller.
        const PHY_2M = 1 << 8;
        /// Stable Modulation Index - Transmitter.  Valid from controller to controller.
        const STABLE_MODULATION_INDEX_TX = 1 << 9;
        /// Stable Modulation Index - Receiver.  Valid from controller to controller.
        const STABLE_MODULATION_INDEX_RX = 1 << 10;
        /// LE Coded PHY.  Valid from controller to controller.
        const CODED_PHY = 1 << 11;
        /// LE Extended Advertising.  Not valid from controller to controller.
        const EXTENDED_ADVERTISING = 1 << 12;
        /// LE Periodic Advertising.  Not valid from controller to controller.
        const PERIODIC_ADVERTISING = 1 << 13;
        /// Channel Selection Algorithm #2.  Valid from controller to controller.
        const CHANNEL_SELECTION_ALGORITHM_2 = 1 << 14;
        /// LE Power Class 1.  Valid from controller to controller.
        const POWER_CLASS_1 = 1 << 15;
        /// Minimum Number of Used Channels Procedure
        const MINIMUM_NUMBER_OF_USED_CHANNELS_PROCEDURE = 1 << 16;
    }
}

#[cfg(feature = "defmt")]
defmt::bitflags! {
    /// Possible LE features for the [LE Read Local Supported
    /// Features](::host::Hci::le_read_local_supported_features) command.  See the Bluetooth
    /// specification, Vol 6, Part B, Section 4.6.  See Table 4.3 (v4.1 of the spec), Table 4.4
    /// (v4.2 and v5.0).
    #[derive(Default)]
    pub struct LeFeatures : u64 {
        /// LE Encryption.  Valid from controller to controller.
        const ENCRYPTION = 1 << 0;
        /// Connection Parameters Request Procedure.  Valid from controller to controller.
        const CONNECTION_PARAMETERS_REQUEST_PROCEDURE = 1 << 1;
        /// Extended Reject Indication.  Valid from controller to controller.
        const EXTENDED_REJECT_INDICATION = 1 << 2;
        /// Peripheral-initiated Features Exchange.  Valid from controller to controller.
        const PERIPHERALINITIATED_FEATURES_EXCHANGE = 1 << 3;
        /// LE Ping.  Not valid from controller to controller.
        const PING = 1 << 4;
        /// LE Data Packet Length Extension.  Valid from controller to controller.
        const DATA_PACKET_LENGTH_EXTENSION = 1 << 5;
        /// LL Privacy.  Not valid from controller to controller.
        const LL_PRIVACY = 1 << 6;
        /// Extended Scanner Filter Policies.  Not valid from controller to controller.
        const EXTENDED_SCANNER_FILTER_POLICIES = 1 << 7;
        /// LE 2M PHY.  Valid from controller to controller.
        const PHY_2M = 1 << 8;
        /// Stable Modulation Index - Transmitter.  Valid from controller to controller.
        const STABLE_MODULATION_INDEX_TX = 1 << 9;
        /// Stable Modulation Index - Receiver.  Valid from controller to controller.
        const STABLE_MODULATION_INDEX_RX = 1 << 10;
        /// LE Coded PHY.  Valid from controller to controller.
        const CODED_PHY = 1 << 11;
        /// LE Extended Advertising.  Not valid from controller to controller.
        const EXTENDED_ADVERTISING = 1 << 12;
        /// LE Periodic Advertising.  Not valid from controller to controller.
        const PERIODIC_ADVERTISING = 1 << 13;
        /// Channel Selection Algorithm #2.  Valid from controller to controller.
        const CHANNEL_SELECTION_ALGORITHM_2 = 1 << 14;
        /// LE Power Class 1.  Valid from controller to controller.
        const POWER_CLASS_1 = 1 << 15;
        /// Minimum Number of Used Channels Procedure
        const MINIMUM_NUMBER_OF_USED_CHANNELS_PROCEDURE = 1 << 16;
    }
}

fn to_le_local_supported_features(bytes: &[u8]) -> Result<LeSupportedFeatures, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 9);
    Ok(LeSupportedFeatures {
        status: to_status(bytes)?,
        supported_features: LeFeatures::from_bits_truncate(LittleEndian::read_u64(&bytes[1..])),
    })
}

/// Values returned by the [LE Read Advertising Channel TX
/// Power](crate::host::Hci::le_read_advertising_channel_tx_power) command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeAdvertisingChannelTxPower {
    /// Did the command fail, and if so, how?
    pub status: Status,
    /// The transmit power of the advertising channel.
    ///   - Range: -20 ≤ N ≤ 10 (this is not enforced in this implementation)
    ///   - Units: dBm
    ///   - Accuracy: ±4 dB
    pub power: i8,
}

fn to_le_advertising_channel_tx_power(
    bytes: &[u8],
) -> Result<LeAdvertisingChannelTxPower, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 2);
    Ok(LeAdvertisingChannelTxPower {
        status: to_status(bytes)?,
        power: unsafe { mem::transmute::<u8, i8>(bytes[1]) },
    })
}

fn to_le_set_advertise_enable(status: Status) -> ReturnParameters {
    ReturnParameters::LeSetAdvertisingEnable(status)
}

/// Parameters returned by the [LE Read Channel Map](crate::host::Hci::le_read_channel_map) command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChannelMapParameters {
    /// Did the command fail, and if so, how?
    pub status: Status,

    /// Connection handle whose channel map is returned.
    pub conn_handle: ConnectionHandle,

    /// Channels that may be used for this connection.
    pub channel_map: crate::ChannelClassification,
}

fn to_le_channel_map_parameters(bytes: &[u8]) -> Result<ChannelMapParameters, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 8);

    let mut channel_bits = [0; 5];
    channel_bits.copy_from_slice(&bytes[3..8]);
    let channel_bits = channel_bits;
    Ok(ChannelMapParameters {
        status: to_status(&bytes[0..])?,
        conn_handle: ConnectionHandle(LittleEndian::read_u16(&bytes[1..])),
        channel_map: crate::ChannelClassification::from_bits(&bytes[3..])
            .ok_or(crate::event::Error::InvalidChannelMap(channel_bits))?,
    })
}

/// Parameters returned by the [LE Encrypt](crate::host::Hci::le_encrypt) command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EncryptedReturnParameters {
    /// Did the command fail, and if so, how?
    pub status: Status,

    /// Encrypted data block.
    ///
    /// The most significant octet (last) of the block corresponds to `out[0]` using the notation
    /// specified in FIPS 197.
    pub encrypted_data: EncryptedBlock,
}

/// Newtype for a 128-bit encrypted block of data.
///
/// See [`EncryptedReturnParameters`].
#[derive(Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EncryptedBlock(pub [u8; 16]);

impl Debug for EncryptedBlock {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        writeln!(f, "AES-128 Encrypted Data ({:X?})", &self.0)
    }
}

fn to_le_encrypted_data(bytes: &[u8]) -> Result<EncryptedReturnParameters, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 17);

    let mut block = [0; 16];
    block.copy_from_slice(&bytes[1..]);
    Ok(EncryptedReturnParameters {
        status: to_status(bytes)?,
        encrypted_data: EncryptedBlock(block),
    })
}

/// Return parameters for the [LE Rand](crate::host::Hci::le_rand) command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeRandom {
    /// Did the command fail, and if so, how?
    pub status: Status,

    /// Controller-generated random number.
    pub random_number: u64,
}

fn to_random_number(bytes: &[u8]) -> Result<LeRandom, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 9);

    Ok(LeRandom {
        status: to_status(bytes)?,
        random_number: LittleEndian::read_u64(&bytes[1..]),
    })
}

/// Parameters returned by the [LE LTK Request
/// Reply](crate::host::Hci::le_long_term_key_request_reply) command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeLongTermRequestReply {
    /// Did the command fail, and if so, how?
    pub status: Status,

    /// Connection handle that the request came from
    pub conn_handle: ConnectionHandle,
}

fn to_le_ltk_request_reply(bytes: &[u8]) -> Result<LeLongTermRequestReply, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 3);

    Ok(LeLongTermRequestReply {
        status: to_status(bytes)?,
        conn_handle: ConnectionHandle(LittleEndian::read_u16(&bytes[1..])),
    })
}

/// Parameters returned by the [LE Read Supported
/// States](crate::host::Hci::le_read_supported_states) command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeReadSupportedStates {
    /// Did the command fail, and if so, how?
    pub status: Status,

    /// States or state combinations supported by the Controller. Multiple state and state
    /// combinations may be supported.
    pub supported_states: LeStates,
}

#[cfg(not(feature = "defmt"))]
bitflags::bitflags! {
    /// Possible LE states or state combinations for the [LE Read Supported
    /// States](::host::Hci::le_read_supported_states) command.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct LeStates : u64 {
        /// Non-connectable advertising state alone.
        const NON_CONNECTABLE_ADVERTISING = 1 << 0;
        /// Scannable advertising state alone
        const SCANNABLE_ADVERTISING = 1 << 1;
        /// Connectable advertising state alone
        const CONNECTABLE_ADVERTISING = 1 << 2;
        /// Directed advertising (high duty cycle) state alone
        const DIRECTED_ADVERTISING_HIGH_DUTY_CYCLE = 1 << 3;
        /// Passive scanning state alone
        const PASSIVE_SCANNING = 1 << 4;
        /// Active scanning state alone
        const ACTIVE_SCANNING = 1 << 5;
        /// Initianing state alone
        const INITIATING = 1 << 6;
        /// Peripheral (slave) connection state alone
        const PERIPHERAL_CONNECTION = 1 << 7;
        /// Non-connectable advertising and passive scan states.
        const NONCONN_AD_AND_PASS_SCAN = 1 << 8;
        /// Scannable advertising and passive scan states
        const SCAN_AD_AND_PASS_SCAN = 1 << 9;
        /// Connectable advertising and passive scan states
        const CONN_AD_AND_PASS_SCAN = 1 << 10;
        /// Directed advertising (high duty cycle) and passive scan states
        const DIR_AD_HDC_AND_PASS_SCAN = 1 << 11;
        /// Non-connectable advertising and active scan states.
        const NONCONN_AD_AND_ACT_SCAN = 1 << 12;
        /// Scannable advertising and active scan states
        const SCAN_AD_AND_ACT_SCAN = 1 << 13;
        /// Connectable advertising and active scan states
        const CONN_AD_AND_ACT_SCAN = 1 << 14;
        /// Directed advertising (high duty cycle) and active scan states
        const DIR_AD_HDC_AND_ACT_SCAN = 1 << 15;
        /// Non-connectable advertising and initiating states.
        const NONCONN_AD_AND_INITIATING = 1 << 16;
        /// Scannable advertising and initiating states
        const SCAN_AD_AND_INITIATING = 1 << 17;
        /// Non-connectable advertising and central (master) connection states.
        const NONCONN_AD_AND_CENTRAL_CONN = 1 << 18;
        /// Scannable advertising and central (master) connection states
        const SCAN_AD_AND_CENTRAL_CONN = 1 << 19;
        /// Non-connectable advertising and peripheral (slave) connection states.
        const NONCONN_AD_AND_PERIPH_CONN = 1 << 20;
        /// Scannable advertising and peripheral (slave) connection states
        const SCAN_AD_AND_PERIPH_CONN = 1 << 21;
        /// Passive scan and initiating states
        const PASS_SCAN_AND_INITIATING = 1 << 22;
        /// Active scan and initiating states
        const ACT_SCAN_AND_INITIATING = 1 << 23;
        /// Passive scan and central (master) connection states
        const PASS_SCAN_AND_CENTRAL_CONN = 1 << 24;
        /// Active scan and central (master) connection states
        const ACT_SCAN_AND_CENTRAL_CONN = 1 << 25;
        /// Passive scan and peripheral (slave) connection states
        const PASS_SCAN_AND_PERIPH_CONN = 1 << 26;
        /// Active scan and peripheral (slave) connection states
        const ACT_SCAN_AND_PERIPH_CONN = 1 << 27;
        /// Initiating and central (master) connection states
        const INITIATING_AND_CENTRAL_CONN = 1 << 28;
        /// Directed advertising (low duty cycle) state alone
        const DIRECTED_ADVERTISING_LOW_DUTY_CYCLE = 1 << 29;
        /// Directed advertising (low duty cycle) and passive scan states
        const DIR_AD_LDC_AND_PASS_SCAN = 1 << 30;
        /// Directed advertising (low duty cycle) and active scan states
        const DIR_AD_LDC_AND_ACT_SCAN = 1 << 31;
        /// Connectable advertising and initiating states
        const CONN_AD_AND_INITIATING = 1 << 32;
        /// Directed advertising (high duty cycle) and initiating states
        const DIR_AD_HDC_AND_INITIATING = 1 << 33;
        /// Directed advertising (low duty cycle) and initiating states
        const DIR_AD_LDC_AND_INITIATING = 1 << 34;
        /// Connectable advertising and central (master) connection states
        const CONN_AD_AND_CENTRAL_CONN = 1 << 35;
        /// Directed advertising (high duty cycle) and central (master) states
        const DIR_AD_HDC_AND_CENTRAL_CONN = 1 << 36;
        /// Directed advertising (low duty cycle) and central (master) states
        const DIR_AD_LDC_AND_CENTRAL_CONN = 1 << 37;
        /// Connectable advertising and peripheral (slave) connection states
        const CONN_AD_AND_PERIPH_CONN = 1 << 38;
        /// Directed advertising (high duty cycle) and peripheral (slave) states
        const DIR_AD_HDC_AND_PERIPH_CONN = 1 << 39;
        /// Directed advertising (low duty cycle) and peripheral (slave) states
        const DIR_AD_LDC_AND_PERIPH_CONN = 1 << 40;
        /// Initiating and peripheral (slave) connection states
        const INITIATING_AND_PERIPH_CONN = 1 << 41;
    }
}

#[cfg(feature = "defmt")]
defmt::bitflags! {
    /// Possible LE states or state combinations for the [LE Read Supported
    /// States](::host::Hci::le_read_supported_states) command.
    #[derive(Default)]
    pub struct LeStates : u64 {
        /// Non-connectable advertising state alone.
        const NON_CONNECTABLE_ADVERTISING = 1 << 0;
        /// Scannable advertising state alone
        const SCANNABLE_ADVERTISING = 1 << 1;
        /// Connectable advertising state alone
        const CONNECTABLE_ADVERTISING = 1 << 2;
        /// Directed advertising (high duty cycle) state alone
        const DIRECTED_ADVERTISING_HIGH_DUTY_CYCLE = 1 << 3;
        /// Passive scanning state alone
        const PASSIVE_SCANNING = 1 << 4;
        /// Active scanning state alone
        const ACTIVE_SCANNING = 1 << 5;
        /// Initianing state alone
        const INITIATING = 1 << 6;
        /// Peripheral (slave) connection state alone
        const PERIPHERAL_CONNECTION = 1 << 7;
        /// Non-connectable advertising and passive scan states.
        const NONCONN_AD_AND_PASS_SCAN = 1 << 8;
        /// Scannable advertising and passive scan states
        const SCAN_AD_AND_PASS_SCAN = 1 << 9;
        /// Connectable advertising and passive scan states
        const CONN_AD_AND_PASS_SCAN = 1 << 10;
        /// Directed advertising (high duty cycle) and passive scan states
        const DIR_AD_HDC_AND_PASS_SCAN = 1 << 11;
        /// Non-connectable advertising and active scan states.
        const NONCONN_AD_AND_ACT_SCAN = 1 << 12;
        /// Scannable advertising and active scan states
        const SCAN_AD_AND_ACT_SCAN = 1 << 13;
        /// Connectable advertising and active scan states
        const CONN_AD_AND_ACT_SCAN = 1 << 14;
        /// Directed advertising (high duty cycle) and active scan states
        const DIR_AD_HDC_AND_ACT_SCAN = 1 << 15;
        /// Non-connectable advertising and initiating states.
        const NONCONN_AD_AND_INITIATING = 1 << 16;
        /// Scannable advertising and initiating states
        const SCAN_AD_AND_INITIATING = 1 << 17;
        /// Non-connectable advertising and central (master) connection states.
        const NONCONN_AD_AND_CENTRAL_CONN = 1 << 18;
        /// Scannable advertising and central (master) connection states
        const SCAN_AD_AND_CENTRAL_CONN = 1 << 19;
        /// Non-connectable advertising and peripheral (slave) connection states.
        const NONCONN_AD_AND_PERIPH_CONN = 1 << 20;
        /// Scannable advertising and peripheral (slave) connection states
        const SCAN_AD_AND_PERIPH_CONN = 1 << 21;
        /// Passive scan and initiating states
        const PASS_SCAN_AND_INITIATING = 1 << 22;
        /// Active scan and initiating states
        const ACT_SCAN_AND_INITIATING = 1 << 23;
        /// Passive scan and central (master) connection states
        const PASS_SCAN_AND_CENTRAL_CONN = 1 << 24;
        /// Active scan and central (master) connection states
        const ACT_SCAN_AND_CENTRAL_CONN = 1 << 25;
        /// Passive scan and peripheral (slave) connection states
        const PASS_SCAN_AND_PERIPH_CONN = 1 << 26;
        /// Active scan and peripheral (slave) connection states
        const ACT_SCAN_AND_PERIPH_CONN = 1 << 27;
        /// Initiating and central (master) connection states
        const INITIATING_AND_CENTRAL_CONN = 1 << 28;
        /// Directed advertising (low duty cycle) state alone
        const DIRECTED_ADVERTISING_LOW_DUTY_CYCLE = 1 << 29;
        /// Directed advertising (low duty cycle) and passive scan states
        const DIR_AD_LDC_AND_PASS_SCAN = 1 << 30;
        /// Directed advertising (low duty cycle) and active scan states
        const DIR_AD_LDC_AND_ACT_SCAN = 1 << 31;
        /// Connectable advertising and initiating states
        const CONN_AD_AND_INITIATING = 1 << 32;
        /// Directed advertising (high duty cycle) and initiating states
        const DIR_AD_HDC_AND_INITIATING = 1 << 33;
        /// Directed advertising (low duty cycle) and initiating states
        const DIR_AD_LDC_AND_INITIATING = 1 << 34;
        /// Connectable advertising and central (master) connection states
        const CONN_AD_AND_CENTRAL_CONN = 1 << 35;
        /// Directed advertising (high duty cycle) and central (master) states
        const DIR_AD_HDC_AND_CENTRAL_CONN = 1 << 36;
        /// Directed advertising (low duty cycle) and central (master) states
        const DIR_AD_LDC_AND_CENTRAL_CONN = 1 << 37;
        /// Connectable advertising and peripheral (slave) connection states
        const CONN_AD_AND_PERIPH_CONN = 1 << 38;
        /// Directed advertising (high duty cycle) and peripheral (slave) states
        const DIR_AD_HDC_AND_PERIPH_CONN = 1 << 39;
        /// Directed advertising (low duty cycle) and peripheral (slave) states
        const DIR_AD_LDC_AND_PERIPH_CONN = 1 << 40;
        /// Initiating and peripheral (slave) connection states
        const INITIATING_AND_PERIPH_CONN = 1 << 41;
    }
}

fn to_le_read_states(bytes: &[u8]) -> Result<LeReadSupportedStates, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 9);

    let bitfield = LittleEndian::read_u64(&bytes[1..]);
    Ok(LeReadSupportedStates {
        status: to_status(bytes)?,
        supported_states: LeStates::from_bits(bitfield)
            .ok_or(crate::event::Error::InvalidLeStates(bitfield))?,
    })
}

/// Parameters returned by the [LE Test End](crate::host::Hci::le_test_end) command.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LeTestEnd {
    /// Did the command fail, and if so, how?
    pub status: Status,

    /// The number of packets received during the test.  For transmitter tests, this value shall be
    /// 0.
    pub number_of_packets: usize,
}

fn to_le_test_end(bytes: &[u8]) -> Result<LeTestEnd, crate::event::Error>
where
    Status: TryFrom<u8, Error = BadStatusError>,
{
    require_len!(bytes, 3);

    Ok(LeTestEnd {
        status: to_status(bytes)?,
        number_of_packets: LittleEndian::read_u16(&bytes[1..]) as usize,
    })
}
