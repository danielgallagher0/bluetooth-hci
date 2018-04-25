//! Return parameters for HCI commands.
//!
//! This module defines the return parameters that can be returned in a Command Complete event for
//! every HCI command.
//!
//! For the Command Complete event, see the Bluetooth specification, version 5.0, Vol 2, Part E,
//! Section 7.7.14.
//!
//! For the return parameters of the commands, see the description of each command in sections 7.1 -
//! 7.6 of the same part of the spec.

use byteorder::{ByteOrder, LittleEndian};

/// Values returned by local version information query. Bluetooth Specification 5.0, Vol 2 Part E,
/// 7.4.1: Read Local Version Information Command
#[derive(Clone, Debug)]
pub struct LocalVersionInfo {
    /// HCI Version. See Bluetooth [Assigned
    /// Numbers](https://www.bluetooth.org/Technical/AssignedNumbers/home.htm)
    pub hci_version: u8,

    /// Revision of the Current HCI in the BR/EDR Controller
    pub hci_revision: u16,

    /// Version of the Current LMP or PAL in the Controller.  See Bluetooth [Assigned
    /// Numbers](https://www.bluetooth.org/Technical/AssignedNumbers/home.htm)
    pub lmp_version: u8,

    /// Manufacturer Name of the BR/EDR Controller.  See Bluetooth [Assigned
    /// Numbers](https://www.bluetooth.org/Technical/AssignedNumbers/home.htm)
    pub manufacturer_name: u16,

    /// Subversion of the Current LMP or PAL in the Controller. This value is implementation
    /// dependent.
    pub lmp_subversion: u16,
}

impl LocalVersionInfo {
    fn new<VE>(bytes: &[u8]) -> Result<LocalVersionInfo, ::event::Error<VE>> {
        if bytes.len() < 8 {
            return Err(::event::Error::BadLength(bytes.len(), 8));
        }

        Ok(LocalVersionInfo {
            hci_version: bytes[0],
            hci_revision: LittleEndian::read_u16(&bytes[1..]),
            lmp_version: bytes[3],
            manufacturer_name: LittleEndian::read_u16(&bytes[4..]),
            lmp_subversion: LittleEndian::read_u16(&bytes[6..]),
        })
    }
}

/// Parameters that may be returned in a Command Complete event. Not all commands have return
/// parameters, in which case, None is returned.
///
/// # TODO
///
/// - Use different values for each command type, to allow callers to distinguish between commands
///   that do not have return parameters. Or provide the opcode in the [`CommandComplete`]
///   structure, but that would provide redundant (and therefore potentially conflicting)
///   information.
#[derive(Clone, Debug)]
pub enum ReturnParameters {
    /// The command has no return parameters.
    None,

    /// Local version info returned by the Read Local Version Information command.
    ReadLocalVersion(LocalVersionInfo),
}

/// The Command Complete event. This event is generated to indicate that a command has been
/// completed.
///
/// Defined in Vol 2, Part E, Section 7.7.14 of the spec, version 5.0.
#[derive(Clone, Debug)]
pub struct CommandComplete {
    /// Number of HCI Command packets that can be sent to the controller from the host.
    pub num_hci_command_packets: u8,

    /// Parameters that are returned with the event.
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
        if bytes.len() < 3 {
            return Err(::event::Error::BadLength(bytes.len(), 3));
        }

        let params = match ::opcode::OpCode(LittleEndian::read_u16(&bytes[1..])) {
            ::opcode::LOCAL_VERSION_INFO => {
                ReturnParameters::ReadLocalVersion(LocalVersionInfo::new(&bytes)?)
            }
            _ => ReturnParameters::None,
        };
        Ok(CommandComplete {
            num_hci_command_packets: bytes[0],
            return_params: params,
        })
    }
}
