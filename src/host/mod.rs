//! Host-side interface to the Bluetooth HCI.
//!
//! # Ideas for discussion and improvements
//!
//! - Remove [`cmd_link`] and [`event_link`] modules. These provide alternative mechanisms for
//!   writing to and reading from the controller, respectively, without the packet identifier
//!   byte. The open-source Bluetooth implementations I have found (admittedly, I haven't looked
//!   hard) only support sending the packet ID, as [`uart`] does. In that case, it would make sense
//!   to also remove [`uart`] and move its contents up one level.

extern crate nb;

use byteorder::{ByteOrder, LittleEndian};

pub mod cmd_link;
pub mod event_link;
pub mod uart;

const MAX_HEADER_LENGTH: usize = 5;

/// Trait to define a command packet header.
///
/// See the Bluetooth Specification Vol 2, Part E, section 5.4.1. The command packet header contains
/// an opcode (comprising a 6-bit OGF and 10-bit OCF) and a 1-byte parameter length. The packet
/// itself then contains various parameters as defined by the Bluetooth specification.
///
/// Before this command header, many (all?) Bluetooth implementations include a 1-byte packet type
/// preceding the command header. This version of the HciHeader is implemented by [`uart::HciHeader`],
/// while versions without the packet byte are implemented by [`cmd_link::Header`] and
/// [`event_link::EventHeader`].
pub trait HciHeader {
    /// Defines the length of the packet header. With the packet byte, this is 4. Without it, the
    /// length shall be 3.
    const HEADER_LENGTH: usize;

    /// Returns a new header with the given opcode and parameter length.
    fn new(opcode: ::opcode::Opcode, param_len: usize) -> Self;

    /// Serialize the header into the given buffer, in Bluetooth byte order (little-endian).
    ///
    /// # Panics
    ///
    /// Panics if `buf.len() < Self::HEADER_LENGTH`
    fn into_bytes(&self, buf: &mut [u8]);
}

/// Trait defining the interface from the host to the controller.
///
/// Defines one function for each command in the Bluetooth Specification Vol 2, Part E, Sections 7.1
/// - 7.6.
///
/// Specializations must define the error type `E`, used for communication errors, and the header
/// type `Header`, which should be either uart::CommandHeader`, `cmd_link::CommandHeader`, or
/// `event_link::CommandHeader`, depending on the controller implementation.
///
/// An implementation is defined or all types that implement `host::Controller`.
pub trait Hci<E, Header> {
    /// The Disconnection command is used to terminate an existing connection.  All synchronous
    /// connections on a physical link should be disconnected before the ACL connection on the same
    /// physical connection is disconnected.
    ///
    /// - `conn_handle` indicates which connection is to be disconnected.
    /// - `reason` indicates the reason for ending the connection. The remote Controller will
    ///   receive the Reason command parameter in the Disconnection Complete event.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.1.6.
    ///
    /// # Errors
    ///
    /// - `Error::BadDisconnectionReason` when the provided `reason` is not a valid disconnection
    ///   reason.  The reason must be one of `Status::AuthFailure`,
    ///   `Status::RemoteTerminationByUser`, `Status::RemoteTerminationLowResources`,
    ///   `Status::RemoteTerminationPowerOff`, `Status::UnsupportedRemoteFeature`,
    ///   `Status::PairingWithUnitKeyNotSupported`, or `Status::UnacceptableConnectionParameters`.
    /// - Underlying communication errors.
    ///
    /// # Generated Events
    ///
    /// When the Controller receives the Disconnect command, it shall send the Command Status event
    /// to the Host. The Disconnection Complete event will occur at each Host when the termination
    /// of the connection has completed, and indicates that this command has been completed.
    ///
    /// Note: No Command Complete event will be sent by the Controller to indicate that this command
    /// has been completed. Instead, the Disconnection Complete event will indicate that this
    /// command has been completed.
    fn disconnect(
        &mut self,
        conn_handle: ::ConnectionHandle,
        reason: ::Status,
    ) -> nb::Result<(), Error<E>>;

    /// This command obtains the values for the version information for the remote device identified
    /// by the `conn_handle` parameter, which must be a connection handle for an ACL or LE
    /// connection.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.1.23.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated Events
    ///
    /// When the Controller receives the Read Remote Version Information command, the Controller
    /// shall send the Command Status event to the Host. When the Link Manager or Link Layer has
    /// completed the sequence to determine the remote version information, the local Controller
    /// shall send a Read Remote Version Information Complete event to the Host. The Read Remote
    /// Version Information Complete event contains the status of this command, and parameters
    /// describing the version and subversion of the LMP or Link Layer used by the remote device.
    ///
    /// Note: No Command Complete event will be sent by the Controller to indicate that this command
    /// has been completed. Instead, the Read Remote Version Information Complete event will
    /// indicate that this command has been completed.
    fn read_remote_version_information(
        &mut self,
        conn_handle: ::ConnectionHandle,
    ) -> nb::Result<(), E>;

    /// The Set_Event_Mask command is used to control which events are generated by the HCI for the
    /// Host. If the bit in the event mask is set to a one, then the event associated with that bit
    /// will be enabled. For an LE Controller, the “LE Meta Event” bit in the Event_Mask shall
    /// enable or disable all LE events in the LE Meta Event (see Section 7.7.65). The Host has to
    /// deal with each event that occurs. The event mask allows the Host to control how much it is
    /// interrupted.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.3.1.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated Events
    ///
    /// Returns a status in a Command Complete event.
    fn set_event_mask(&mut self, mask: EventFlags) -> nb::Result<(), E>;

    /// The Reset command will reset the Controller and the Link Manager on the BR/EDR Controller,
    /// the PAL on an AMP Controller, or the Link Layer on an LE Controller. If the Controller
    /// supports both BR/EDR and LE then the Reset command shall reset the Link Manager, Baseband
    /// and Link Layer. The Reset command shall not affect the used HCI transport layer since the
    /// HCI transport layers may have reset mechanisms of their own. After the reset is completed,
    /// the current operational state will be lost, the Controller will enter standby mode and the
    /// Controller will automatically revert to the default values for the parameters for which
    /// default values are defined in the specification.
    ///
    /// Note: The Reset command will not necessarily perform a hardware reset. This is
    /// implementation defined. On an AMP Controller, the Reset command shall reset the service
    /// provided at the logical HCI to its initial state, but beyond this the exact effect on the
    /// Controller device is implementation defined and should not interrupt the service provided to
    /// other protocol stacks.
    ///
    /// The Host shall not send additional HCI commands before the Command Complete event related to
    /// the Reset command has been received.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.3.2.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated Events
    ///
    /// Returns a status in a Command Complete event.
    fn reset(&mut self) -> nb::Result<(), E>;

    /// This command reads the values for the Transmit_Power_Level parameter for the specified
    /// `conn_handle`. `conn_handle` shall be a connection handle for an ACL connection.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.3.35.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported
    ///
    /// # Generated Events
    ///
    /// Returns the transmit power level in a Command Complete event.
    fn read_tx_power_level(
        &mut self,
        conn_handle: ::ConnectionHandle,
        power_level_type: TxPowerLevel,
    ) -> nb::Result<(), E>;

    /// This command reads the values for the version information for the local Controller.
    ///
    /// Defined in Bluetooth Specification Vol 2, Part E, Section 7.4.1.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported
    ///
    /// # Generated events
    ///
    /// Returns the local version info in a Command complete event.
    fn read_local_version_information(&mut self) -> nb::Result<(), E>;

    /// This command reads the list of HCI commands supported for the local Controller.
    ///
    /// This command shall return the Supported_Commands configuration parameter. It is implied that
    /// if a command is listed as supported, the feature underlying that command is also supported.
    ///
    /// See the Bluetooth Spec, Vol 2, Part E, Section 6.27 for more information.
    ///
    /// See the Bluetoth spec, Vol 2, Part E, Section 7.4.2.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported
    ///
    /// # Generated events
    ///
    /// Generates a command complete event with the local supported commands.
    fn read_local_supported_commands(&mut self) -> nb::Result<(), E>;
}

/// Errors that may occur when sending commands to the controller.  Must be specialized on the types
/// of communication errors.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error<E> {
    /// For the Disconnect command: The provided reason is not a valid disconnection reason.
    /// Includes the reported reason.
    BadDisconnectionReason(::Status),

    /// Underlying communication error.
    Comm(E),
}

fn rewrap_as_comm<E>(err: nb::Error<E>) -> nb::Error<Error<E>> {
    match err {
        nb::Error::WouldBlock => nb::Error::WouldBlock,
        nb::Error::Other(e) => nb::Error::Other(Error::Comm(e)),
    }
}

fn write_command<Header, T, E>(
    controller: &mut T,
    opcode: ::opcode::Opcode,
    params: &[u8],
) -> nb::Result<(), E>
where
    Header: HciHeader,
    T: ::Controller<Error = E>,
{
    let mut header = [0; MAX_HEADER_LENGTH];
    Header::new(opcode, params.len()).into_bytes(&mut header);

    controller.write(&header[..Header::HEADER_LENGTH], &params)
}

impl<E, T, Header> Hci<E, Header> for T
where
    T: ::Controller<Error = E>,
    Header: HciHeader,
{
    fn disconnect(
        &mut self,
        conn_handle: ::ConnectionHandle,
        reason: ::Status,
    ) -> nb::Result<(), Error<E>> {
        match reason {
            ::Status::AuthFailure
            | ::Status::RemoteTerminationByUser
            | ::Status::RemoteTerminationLowResources
            | ::Status::RemoteTerminationPowerOff
            | ::Status::UnsupportedRemoteFeature
            | ::Status::PairingWithUnitKeyNotSupported
            | ::Status::UnacceptableConnectionParameters => (),
            _ => return Err(nb::Error::Other(Error::BadDisconnectionReason(reason))),
        }

        let mut params = [0; 3];
        LittleEndian::write_u16(&mut params[0..], conn_handle.0);
        params[2] = reason as u8;
        write_command::<Header, T, E>(self, ::opcode::DISCONNECT, &params).map_err(rewrap_as_comm)
    }

    fn read_remote_version_information(
        &mut self,
        conn_handle: ::ConnectionHandle,
    ) -> nb::Result<(), E> {
        let mut params = [0; 2];
        LittleEndian::write_u16(&mut params, conn_handle.0);
        write_command::<Header, T, E>(self, ::opcode::READ_REMOTE_VERSION_INFO, &params)
    }

    fn set_event_mask(&mut self, mask: EventFlags) -> nb::Result<(), E> {
        let mut params = [0; 8];
        LittleEndian::write_u64(&mut params, mask.bits());

        write_command::<Header, T, E>(self, ::opcode::SET_EVENT_MASK, &params)
    }

    fn reset(&mut self) -> nb::Result<(), E> {
        write_command::<Header, T, E>(self, ::opcode::RESET, &[])
    }

    fn read_tx_power_level(
        &mut self,
        conn_handle: ::ConnectionHandle,
        power_level_type: TxPowerLevel,
    ) -> nb::Result<(), E> {
        let mut params = [0; 3];
        LittleEndian::write_u16(&mut params, conn_handle.0);
        params[2] = power_level_type as u8;
        write_command::<Header, T, E>(self, ::opcode::READ_TX_POWER_LEVEL, &params)
    }

    fn read_local_version_information(&mut self) -> nb::Result<(), E> {
        write_command::<Header, T, E>(self, ::opcode::READ_LOCAL_VERSION_INFO, &[])
    }

    fn read_local_supported_commands(&mut self) -> nb::Result<(), E> {
        write_command::<Header, T, E>(self, ::opcode::READ_LOCAL_SUPPORTED_COMMANDS, &[])
    }
}

bitflags! {
    /// Event flags defined for the Set Event Mask command.
    #[derive(Default)]
    pub struct EventFlags : u64 {
        /// Inquiry complete event
        const INQUIRY_COMPLETE = 0x0000000000000001;
        /// Inquiry result event
        const INQUIRY_RESULT = 0x0000000000000002;
        /// Connection complete event
        const CONNECTION_COMPLETE = 0x0000000000000004;
        /// Connection request event
        const CONNECTION_REQUEST = 0x0000000000000008;
        /// Disconnection complete event
        const DISCONNECTION_COMPLETE = 0x0000000000000010;
        /// Authentication complete event
        const AUTHENTICATION_COMPLETE = 0x0000000000000020;
        /// Remote name request complete event
        const REMOTE_NAME_REQUEST_COMPLETE = 0x0000000000000040;
        /// Encryption change event
        const ENCRYPTION_CHANGE = 0x0000000000000080;
        /// Change connection link key complete event
        const CHANGE_CONNECTION_LINK_KEY_COMPLETE = 0x0000000000000100;
        /// Master link key complete event
        const MASTER_LINK_KEY_COMPLETE = 0x0000000000000200;
        /// Read remote supported features complete event
        const READ_REMOTE_SUPPORTED_FEATURES_COMPLETE = 0x0000000000000400;
        /// Read remote version information complete event
        const READ_REMOTE_VERSION_INFORMATION_COMPLETE = 0x0000000000000800;
        /// Qos setup complete event
        const QOS_SETUP_COMPLETE = 0x0000000000001000;
        /// Hardware error event
        const HARDWARE_ERROR = 0x0000000000008000;
        /// Flush occurred event
        const FLUSH_OCCURRED = 0x0000000000010000;
        /// Role change event
        const ROLE_CHANGE = 0x0000000000020000;
        /// Mode change event
        const MODE_CHANGE = 0x0000000000080000;
        /// Return link keys event
        const RETURN_LINK_KEYS = 0x0000000000100000;
        /// Pin code request event
        const PIN_CODE_REQUEST = 0x0000000000200000;
        /// Link key request event
        const LINK_KEY_REQUEST = 0x0000000000400000;
        /// Link key notification event
        const LINK_KEY_NOTIFICATION = 0x0000000000800000;
        /// Loopback command event
        const LOOPBACK_COMMAND = 0x0000000001000000;
        /// Data buffer overflow event
        const DATA_BUFFER_OVERFLOW = 0x0000000002000000;
        /// Max slots change event
        const MAX_SLOTS_CHANGE = 0x0000000004000000;
        /// Read clock offset complete event
        const READ_CLOCK_OFFSET_COMPLETE = 0x0000000008000000;
        /// Connection packet type changed event
        const CONNECTION_PACKET_TYPE_CHANGED = 0x0000000010000000;
        /// Qos violation event
        const QOS_VIOLATION = 0x0000000020000000;
        /// Page scan mode change event. Deprecated in Bluetooth spec.
        #[deprecated]
        const PAGE_SCAN_MODE_CHANGE = 0x0000000040000000;
        /// Page scan repetition mode change event
        const PAGE_SCAN_REPETITION_MODE_CHANGE = 0x0000000080000000;
        /// Flow specification complete event
        const FLOW_SPECIFICATION_COMPLETE = 0x0000000100000000;
        /// Inquiry result with rssi event
        const INQUIRY_RESULT_WITH_RSSI = 0x0000000200000000;
        /// Read remote extended features complete event
        const READ_REMOTE_EXTENDED_FEATURES_COMPLETE = 0x0000000400000000;
        /// Synchronous connection complete event
        const SYNCHRONOUS_CONNECTION_COMPLETE = 0x0000080000000000;
        /// Synchronous connection changed event
        const SYNCHRONOUS_CONNECTION_CHANGED = 0x0000100000000000;
        /// Sniff subrating event
        const SNIFF_SUBRATING = 0x0000200000000000;
        /// Extended inquiry result event
        const EXTENDED_INQUIRY_RESULT = 0x0000400000000000;
        /// Encryption key refresh complete event
        const ENCRYPTION_KEY_REFRESH_COMPLETE = 0x0000800000000000;
        /// Io capability request event
        const IO_CAPABILITY_REQUEST = 0x0001000000000000;
        /// Io capability request reply event
        const IO_CAPABILITY_REQUEST_REPLY = 0x0002000000000000;
        /// User confirmation request event
        const USER_CONFIRMATION_REQUEST = 0x0004000000000000;
        /// User passkey request event
        const USER_PASSKEY_REQUEST = 0x0008000000000000;
        /// Remote oob data request event
        const REMOTE_OOB_DATA_REQUEST = 0x0010000000000000;
        /// Simple pairing complete event
        const SIMPLE_PAIRING_COMPLETE = 0x0020000000000000;
        /// Link supervision timeout changed event
        const LINK_SUPERVISION_TIMEOUT_CHANGED = 0x0080000000000000;
        /// Enhanced flush complete event
        const ENHANCED_FLUSH_COMPLETE = 0x0100000000000000;
        /// User passkey notification event
        const USER_PASSKEY_NOTIFICATION = 0x0400000000000000;
        /// Keypress notification event
        const KEYPRESS_NOTIFICATION = 0x0800000000000000;
        /// Remote host supported features notification event
        const REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION = 0x1000000000000000;
        /// LE meta-events
        const LE_META_EVENT = 0x2000000000000000;
    }
}

/// For the Read Tx Power Level command, the allowed values for the type of power level to read.
///
/// See the Bluetooth spec, Vol 2, Part E, Section 7.3.35.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TxPowerLevel {
    /// Read Current Transmit Power Level.
    Current = 0x00,
    /// Read Maximum Transmit Power Level.
    Maximum = 0x01,
}
