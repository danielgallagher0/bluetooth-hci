//! Return parameters for HCI commands.
//!
//! This module defines the return parameters that can be returned in a Command Complete event for
//! every HCI command.
//!
//! For the Command Complete event, see the Bluetooth specification, v4.1 or later, Vol 2, Part E,
//! Section 7.7.14.
//!
//! For the return parameters of the commands, see the description of each command in sections 7.1 -
//! 7.6 of the same part of the spec.

use byteorder::{ByteOrder, LittleEndian};
use core::convert::TryInto;
use core::mem;

/// The Command Complete event is used by the Controller for most commands to transmit return status
/// of a command and the other event parameters that are specified for the issued HCI command.
///
/// Defined in the Bluetooth Spec, v4.1 or later, Vol 2, Part E, Section 7.7.14.
#[derive(Clone, Debug)]
pub struct CommandComplete {
    /// Indicates the number of HCI command packets the Host can send to the Controller. If the
    /// Controller requires the Host to stop sending commands, num_hci_command_packets will be set
    /// to zero.  To indicate to the Host that the Controller is ready to receive HCI command
    /// packets, the Controller generates a Command Complete event with `return_params` set to
    /// `Spontaneous` and `num_hci_command_packets` parameter set to 1 or more.  `Spontaneous`
    /// return parameters indicates that this event is not associated with a command sent by the
    /// Host. The Controller can send a Spontaneous Command Complete event at any time to change the
    /// number of outstanding HCI command packets that the Host can send before waiting.
    pub num_hci_command_packets: u8,

    /// Parameters that are returned with the event. Also used to indicate the type of command that
    /// has completed.
    pub return_params: ReturnParameters,
}

impl CommandComplete {
    /// Deserializes a buffer into a CommandComplete event.
    ///
    /// # Errors
    ///
    /// - Returns BadLength if the buffer is not large enough to contain a parameter length (1 byte)
    ///   and opcode (2 bytes)
    ///
    /// - Returns errors that may be generated when deserializing specific events. Typically, this
    ///   will be BadLength, which indicates the buffer was not large enough to contain all of the
    ///   required data for the event. The error type must be specialized on potential
    ///   vendor-specific errors, though vendor-specific errors are never returned.
    pub fn new<VE>(bytes: &[u8]) -> Result<CommandComplete, ::event::Error<VE>> {
        require_len_at_least!(bytes, 3);

        let params = match ::opcode::Opcode(LittleEndian::read_u16(&bytes[1..])) {
            ::opcode::Opcode(0x0000) => ReturnParameters::Spontaneous,
            ::opcode::SET_EVENT_MASK => ReturnParameters::SetEventMask(to_status(&bytes[3..])?),
            ::opcode::RESET => ReturnParameters::Reset(to_status(&bytes[3..])?),
            ::opcode::READ_TX_POWER_LEVEL => {
                ReturnParameters::ReadTxPowerLevel(to_tx_power_level(&bytes[3..])?)
            }
            ::opcode::READ_LOCAL_VERSION_INFO => {
                ReturnParameters::ReadLocalVersionInformation(to_local_version_info(&bytes[3..])?)
            }
            other => return Err(::event::Error::UnknownOpcode(other)),
        };
        Ok(CommandComplete {
            num_hci_command_packets: bytes[0],
            return_params: params,
        })
    }
}

/// Commands that may generate the Command Complete event.  If the commands have defined return
/// parameters, they are included in this enum.
#[derive(Copy, Clone, Debug)]
pub enum ReturnParameters {
    /// The controller sent an unsolicited command complete event in order to change the number of
    /// HCI command packets the Host is allowed to send.
    Spontaneous,

    /// Status returned by the Set Event Mask command.
    SetEventMask(::Status),

    /// Status returned by the Reset command.
    Reset(::Status),

    /// Read Transmit Power Level return parameters.
    ReadTxPowerLevel(TxPowerLevel),

    /// Local version info returned by the Read Local Version Information command.
    ReadLocalVersionInformation(LocalVersionInfo),
}

fn to_status<VE>(bytes: &[u8]) -> Result<::Status, ::event::Error<VE>> {
    bytes[0].try_into().map_err(super::rewrap_bad_status)
}

/// Values returned by the Read Transmit Power Level command.  See the Bluetooth spec, Vol 2, Part
/// E, Section 7.3.35.
#[derive(Copy, Clone, Debug)]
pub struct TxPowerLevel {
    /// Did the command fail, and if so, how?
    pub status: ::Status,

    /// Specifies which connection handle’s Transmit Power Level setting is returned
    pub conn_handle: ::ConnectionHandle,

    /// Power level for the connection handle, in dBm.
    ///
    /// Valid range is -30 dBm to +20 dBm, but that is not enforced by this implementation.
    pub tx_power_level_dbm: i8,
}

fn to_tx_power_level<VE>(bytes: &[u8]) -> Result<TxPowerLevel, ::event::Error<VE>> {
    require_len!(bytes, 4);
    Ok(TxPowerLevel {
        status: to_status(bytes)?,
        conn_handle: ::ConnectionHandle(LittleEndian::read_u16(&bytes[1..])),
        tx_power_level_dbm: unsafe { mem::transmute::<u8, i8>(bytes[3]) },
    })
}

/// Values returned by Read Local Version Information command.  See the Bluetooth Specification,
/// v4.1 or later, Vol 2, Part E, Section 7.4.1.
#[derive(Copy, Clone, Debug)]
pub struct LocalVersionInfo {
    /// Whether or not the command succeeded.
    pub status: ::Status,

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

    /// Subversion of the Current LMP or PAL in the Controller. This value is implementation
    /// dependent.
    pub lmp_subversion: u16,
}

fn to_local_version_info<VE>(bytes: &[u8]) -> Result<LocalVersionInfo, ::event::Error<VE>> {
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
