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
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.4.2.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported
    ///
    /// # Generated events
    ///
    /// Generates a command complete event with the local supported commands.
    fn read_local_supported_commands(&mut self) -> nb::Result<(), E>;

    /// This command requests a list of the supported features for the local BR/EDR Controller.
    ///
    /// See the Bluetooth Spec, Vol 2, Part C, Section 3.3 for more information about the features.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.4.3.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// Generates a command complete event with the local supported features.
    fn read_local_supported_features(&mut self) -> nb::Result<(), E>;

    /// On a BR/EDR Controller, this command reads the Bluetooth Controller address (BD_ADDR).
    ///
    /// On an LE Controller, this command shall read the Public Device Address as defined in the
    /// Bluetooth spec, Vol 6, Part B, Section 1.3. If this Controller does not have a Public Device
    /// Address, the value 0x000000000000 shall be returned.
    ///
    /// On a BR/EDR/LE Controller, the public address shall be the same as the BD_ADDR.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.4.6.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// Generates a command complete event with the BDADDR.
    fn read_bd_addr(&mut self) -> nb::Result<(), E>;

    /// This command reads the Received Signal Strength Indication (RSSI) value from a Controller.
    ///
    /// For a BR/EDR Controller, a connection handle is used as the Handle command parameter and
    /// return parameter. The RSSI parameter returns the difference between the measured Received
    /// Signal Strength Indication (RSSI) and the limits of the Golden Receive Power Range for a
    /// connection handle to another BR/EDR Controller. The connection handle must be a
    /// connection handle for an ACL connection. Any positive RSSI value returned by the Controller
    /// indicates how many dB the RSSI is above the upper limit, any negative value indicates how
    /// many dB the RSSI is below the lower limit. The value zero indicates that the RSSI is inside
    /// the Golden Receive Power Range.
    ///
    /// Note: How accurate the dB values will be depends on the Bluetooth hardware. The only
    /// requirements for the hardware are that the BR/EDR Controller is able to tell whether the
    /// RSSI is inside, above or below the Golden Device Power Range.
    ///
    /// The RSSI measurement compares the received signal power with two threshold levels, which
    /// define the Golden Receive Power Range. The lower threshold level corresponds to a received
    /// power between -56 dBm and 6 dB above the actual sensitivity of the receiver. The upper
    /// threshold level is 20 dB above the lower threshold level to an accuracy of +/- 6 dB.
    ///
    /// For an AMP Controller, a physical link handle is used for the Handle command parameter and
    /// return parameter. The meaning of the RSSI metric is AMP type specific and defined in the AMP
    /// PALs (see Volume 5, Core System Package [AMP Controller volume]).
    ///
    /// For an LE transport, a connection handle is used as the Handle command parameter and return
    /// parameter. The meaning of the RSSI metric is an absolute receiver signal strength value in
    /// dBm to ± 6 dB accuracy. If the RSSI cannot be read, the RSSI metric shall be set to 127.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.5.4.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// Generates a command complete event with the RSSI value.
    fn read_rssi(&mut self, conn_handle: ::ConnectionHandle) -> nb::Result<(), E>;

    /// The LE_Set_Event_Mask command is used to control which LE events are generated by the HCI
    /// for the Host. If the bit in the LE_Event_Mask is set to a one, then the event associated
    /// with that bit will be enabled. The Host has to deal with each event that is generated by an
    /// LE Controller. The event mask allows the Host to control which events will interrupt it.
    ///
    /// For LE events to be generated, the LE Meta-Event bit in the Event_Mask shall also be set. If
    /// that bit is not set, then LE events shall not be generated, regardless of how the
    /// LE_Event_Mask is set.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.1.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// Generates a command complete event with the status.
    fn le_set_event_mask(&mut self, event_mask: LeEventFlags) -> nb::Result<(), E>;

    /// The LE_Read_Buffer_Size command is used to read the maximum size of the data portion of HCI
    /// LE ACL Data Packets sent from the Host to the Controller.  The Host will segment the data
    /// transmitted to the Controller according to these values, so that the HCI Data Packets will
    /// contain data with up to this size. The LE_Read_Buffer_Size command also returns the total
    /// number of HCI LE ACL Data Packets that can be stored in the data buffers of the
    /// Controller. The LE_Read_Buffer_Size command must be issued by the Host before it sends any
    /// data to an LE Controller (see Section 4.1.1).
    ///
    /// If the Controller returns a length value of zero, the Host shall use the Read_Buffer_Size
    /// command to determine the size of the data buffers (shared between BR/EDR and LE
    /// transports).
    ///
    /// Note: Both the Read_Buffer_Size and LE_Read_Buffer_Size commands may return buffer length
    /// and number of packets parameter values that are nonzero. This allows a Controller to offer
    /// different buffers and number of buffers for BR/EDR data packets and LE data packets.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.2.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// Generates a command complete event with the buffer size and number of ACL data packets.
    fn le_read_buffer_size(&mut self) -> nb::Result<(), E>;

    /// This command requests the list of the supported LE features for the Controller.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.3.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// Generates a command complete event with the buffer size and number of ACL data packets.
    fn le_read_local_supported_features(&mut self) -> nb::Result<(), E>;

    /// The LE_Set_Random_Address command is used by the Host to set the LE Random Device Address in
    /// the Controller (see [Vol 6] Part B, Section 1.3).
    ///
    /// Details added in v5.0:
    ///
    /// - If this command is used to change the address, the new random address shall take effect
    ///   for advertising no later than the next successful LE Set Advertising Enable Command, for
    ///   scanning no later than the next successful LE Set Scan Enable Command or LE Set Extended
    ///   Scan Enable Command, and for initiating no later than the next successful LE Create
    ///   Connection Command or LE Extended Create Connection Command.
    ///
    /// - Note: If Extended Advertising is in use, this command only affects the address used for
    ///   scanning and initiating. The addresses used for advertising are set by the
    ///   LE_Set_Advertising_Set_Random_Address command (see Section 7.8.52).
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.4.
    ///
    /// # Errors
    ///
    /// - If the given address does not meet the requirements from Vol 6, Part B, Section 1.3, a
    ///   BadRandomAddress error is returned.
    ///   - The 2 most significant bits of the (last byte of the) address must be 00 (non-resolvable
    ///     private address), 10 (resolvable private address), or 11 (static address).
    ///   - The random part of the address must contain at least one 0 and at least one 1.  For
    ///     static and non-resolvable private addresses, the random part is the entire address
    ///     (except the 2 most significant bits).  For resolvable private addresses, the 3 least
    ///     significant bytes are a hash, and the random part is the 3 most significant bytes.  The
    ///     hash part of resolvable private addresses is not checked.
    /// - Underlying communication errors are reported.
    ///
    /// # Generated Events
    ///
    /// A command complete event is generated.
    ///
    /// (v5.0) If the Host issues this command when scanning or legacy advertising is enabled, the
    /// Controller shall return the error code Command Disallowed (0x0C).
    fn le_set_random_address(&mut self, bd_addr: ::BdAddr) -> nb::Result<(), Error<E>>;
}

/// Errors that may occur when sending commands to the controller.  Must be specialized on the types
/// of communication errors.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error<E> {
    /// For the Disconnect command: The provided reason is not a valid disconnection reason.
    /// Includes the reported reason.
    BadDisconnectionReason(::Status),

    /// For the LE Set Random Address command: The provided address does not meet the rules for
    /// random addresses in the Bluetooth Spec, Vol 6, Part B, Section 1.3.  Includes the invalid
    /// address.
    BadRandomAddress(::BdAddr),

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

    fn read_local_supported_features(&mut self) -> nb::Result<(), E> {
        write_command::<Header, T, E>(self, ::opcode::READ_LOCAL_SUPPORTED_FEATURES, &[])
    }

    fn read_bd_addr(&mut self) -> nb::Result<(), E> {
        write_command::<Header, T, E>(self, ::opcode::READ_BD_ADDR, &[])
    }

    fn read_rssi(&mut self, conn_handle: ::ConnectionHandle) -> nb::Result<(), E> {
        let mut params = [0; 2];
        LittleEndian::write_u16(&mut params, conn_handle.0);
        write_command::<Header, T, E>(self, ::opcode::READ_RSSI, &params)
    }

    fn le_set_event_mask(&mut self, event_mask: LeEventFlags) -> nb::Result<(), E> {
        let mut params = [0; 8];
        LittleEndian::write_u64(&mut params, event_mask.bits());

        write_command::<Header, T, E>(self, ::opcode::LE_SET_EVENT_MASK, &params)
    }

    fn le_read_buffer_size(&mut self) -> nb::Result<(), E> {
        write_command::<Header, T, E>(self, ::opcode::LE_READ_BUFFER_SIZE, &[])
    }

    fn le_read_local_supported_features(&mut self) -> nb::Result<(), E> {
        write_command::<Header, T, E>(self, ::opcode::LE_READ_LOCAL_SUPPORTED_FEATURES, &[])
    }

    fn le_set_random_address(&mut self, bd_addr: ::BdAddr) -> nb::Result<(), Error<E>> {
        validate_random_address(&bd_addr).map_err(nb::Error::Other)?;
        write_command::<Header, T, E>(self, ::opcode::LE_SET_RANDOM_ADDRESS, &bd_addr.0)
            .map_err(rewrap_as_comm)
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

bitflags! {
    /// Event flags defined for the LE Set Event Mask command.
    #[derive(Default)]
    pub struct LeEventFlags : u64 {
        /// LE connection complete event
        const CONNECTION_COMPLETE = 1 << 0;
        /// LE advertising report event
        const ADVERTISING_REPORT = 1 << 1;
        /// LE connection update complete event
        const CONNECTION_UPDATE_COMPLETE = 1 << 2;
        /// LE read remote features complete event
        const READ_REMOTE_FEATURES_COMPLETE = 1 << 3;
        /// LE long term key request event
        const LONG_TERM_KEY_REQUEST = 1 << 4;
        /// LE remote connection parameter request event
        const REMOTE_CONNECTION_PARAMETER_REQUEST = 1 << 5;
        /// LE data length change event
        #[cfg(any(feature = "version-4-2", feature = "version-5-0"))]
        const DATA_LENGTH_CHANGE = 1 << 6;
        /// LE read local p256 public key complete event
        #[cfg(any(feature = "version-4-2", feature = "version-5-0"))]
        const READ_LOCAL_P256_PUBLIC_KEY_COMPLETE = 1 << 7;
        /// LE generate dhkey complete event
        #[cfg(any(feature = "version-4-2", feature = "version-5-0"))]
        const GENERATE_DHKEY_COMPLETE = 1 << 8;
        /// LE enhanced connection complete event
        #[cfg(any(feature = "version-4-2", feature = "version-5-0"))]
        const ENHANCED_CONNECTION_COMPLETE = 1 << 9;
        /// LE directed advertising report event
        #[cfg(any(feature = "version-4-2", feature = "version-5-0"))]
        const DIRECTED_ADVERTISING_REPORT = 1 << 10;
        /// LE phy update complete event
        #[cfg(feature = "version-5-0")]
        const PHY_UPDATE_COMPLETE = 1 << 11;
        /// LE extended advertising report event
        #[cfg(feature = "version-5-0")]
        const EXTENDED_ADVERTISING_REPORT = 1 << 12;
        /// LE periodic advertising sync established event
        #[cfg(feature = "version-5-0")]
        const PERIODIC_ADVERTISING_SYNC_ESTABLISHED = 1 << 13;
        /// LE periodic advertising report event
        #[cfg(feature = "version-5-0")]
        const PERIODIC_ADVERTISING_REPORT = 1 << 14;
        /// LE periodic advertising sync lost event
        #[cfg(feature = "version-5-0")]
        const PERIODIC_ADVERTISING_SYNC_LOST = 1 << 15;
        /// LE extended scan timeout event
        #[cfg(feature = "version-5-0")]
        const EXTENDED_SCAN_TIMEOUT = 1 << 16;
        /// LE extended advertising set terminated event
        #[cfg(feature = "version-5-0")]
        const EXTENDED_ADVERTISING_SET_TERMINATED = 1 << 17;
        /// LE scan request received event
        #[cfg(feature = "version-5-0")]
        const SCAN_REQUEST_RECEIVED = 1 << 18;
        /// LE channel selection algorithm event
        #[cfg(feature = "version-5-0")]
        const CHANNEL_SELECTION_ALGORITHM = 1 << 19;
    }
}

fn validate_random_address<E>(bd_addr: &::BdAddr) -> Result<(), Error<E>> {
    let (pop_count, bit_count) = match (bd_addr.0[5] & 0b1100_0000) >> 6 {
        0b00 | 0b11 => (pop_count_except_top_2_bits(&bd_addr.0[0..]), 46),
        0b10 => (pop_count_except_top_2_bits(&bd_addr.0[3..]), 22),
        _ => return Err(Error::BadRandomAddress(*bd_addr)),
    };

    if pop_count == 0 || pop_count == bit_count {
        return Err(Error::BadRandomAddress(*bd_addr));
    }

    Ok(())
}

fn pop_count_except_top_2_bits(bytes: &[u8]) -> u32 {
    let mut pop_count = 0;
    for byte in bytes[..bytes.len() - 1].iter() {
        pop_count += pop_count_of(*byte);
    }
    pop_count += pop_count_of(bytes[bytes.len() - 1] & 0b0011_1111);

    pop_count
}

fn pop_count_of(byte: u8) -> u32 {
    byte.count_ones()
}
