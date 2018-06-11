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
use core::time::Duration;

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

    /// Sets the advertising parameters on the Controller.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.5.
    ///
    /// # Errors
    ///
    /// - `Error::BadAdvertisingInterval` if the minimum is greater than the maximum, or if the
    ///   minimum is less than 20 ms, or the maximum is greater than 10240 ms.
    /// - `Error::BadChannelMap` if no channels are enabled in the channel map.
    /// - `Error::BadAdvertisingIntervalMin` if the advertising type is
    ///   `ScannableUndirected` or `NonconnectableUndirected` and the advertising interval minimum
    ///   is less than 100 ms.  This restriction is removed in version 5.0.
    /// - Underlying communication errors
    ///
    /// # Generated events
    ///
    /// A command complete event is generated.
    ///
    /// The Host shall not issue this command when advertising is enabled in the Controller; if it
    /// is the Command Disallowed error code shall be used.
    fn le_set_advertising_parameters(
        &mut self,
        params: &AdvertisingParameters,
    ) -> nb::Result<(), Error<E>>;

    /// Reads the transmit power level used for LE advertising channel packets.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.6.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A command complete event is generated.
    fn le_read_advertising_channel_tx_power(&mut self) -> nb::Result<(), E>;

    /// Sets the data used in advertising packets that have a data field.
    ///
    /// Only the significant part of the Advertising_Data should be transmitted in the advertising
    /// packets, as defined in the Bluetooth spec, Vol 3, Part C, Section 11.
    ///
    /// If advertising is currently enabled, the Controller shall use the new data in subsequent
    /// advertising events. If an advertising event is in progress when this command is issued, the
    /// Controller may use the old or new data for that event.  If advertising is currently
    /// disabled, the data shall be kept by the Controller and used once advertising is enabled.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.7.
    ///
    /// # Errors
    ///
    /// - `AdvertisingDataTooLong` if `data` is 32 bytes or more.
    /// - Underlying communication errors
    ///
    /// # Generated events
    ///
    /// A command complete is generated.
    fn le_set_advertising_data(&mut self, data: &[u8]) -> nb::Result<(), Error<E>>;

    /// Provides data used in Scanning Packets that have a data field.
    ///
    /// Only the significant part of the Scan_Response_Data should be transmitted in the Scanning
    /// Packets, as defined in the Bluetooth spec, Vol 3, Part C, Section 11.
    ///
    /// If advertising is currently enabled, the Controller shall use the new data in subsequent
    /// advertising events. If an advertising event is in progress when this command is issued, the
    /// Controller may use the old or new data for that event. If advertising is currently disabled,
    /// the data shall be kept by the Controller and used once advertising is enabled.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.8.
    ///
    /// # Errors
    ///
    /// - `AdvertisingDataTooLong` if `data` is 32 bytes or more.
    /// - Underlying communication errors
    ///
    /// # Generated events
    ///
    /// A command complete is generated.
    fn le_set_scan_response_data(&mut self, data: &[u8]) -> nb::Result<(), Error<E>>;

    /// Requests the Controller to start or stop advertising. The Controller manages the timing of
    /// advertisements as per the advertising parameters given in the
    /// [`le_set_advertising_parameters`] command.
    ///
    /// The Controller shall continue advertising until the Host issues an `le_set_advertise_enable`
    /// command with enable set to `false` (Advertising is disabled) or until a connection is
    /// created or until the Advertising is timed out due to high duty cycle Directed
    /// Advertising. In these cases, advertising is then disabled.
    ///
    /// This function is renamed `le_set_advertising_enable` in Bluetooth v5.0.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.9, in versions 4.1 and 4.2.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// When the command has completed, a Command Complete event shall be generated.
    ///
    /// If the `advertising_type` parameter is [`AdvertisingType::ConnectableDirectedHighDutyCycle`]
    /// and the directed advertising fails to create a connection, an LE Connection Complete event
    /// shall be generated with the Status code set to [`::Status::DirectedAdvertisingTimeout`].
    ///
    /// If the `advertising_type` parameter is [`ConnectableUndirected`],
    /// [`ConnectableDirectedHighDutyCycle`], or [`ConnectableDirectedLowDutyCycle`] and a
    /// connection is established, an LE Connection Complete event shall be generated.
    ///
    /// Note: There is a possible race condition if `enable` is set to false (Disable) and the
    /// `advertising_type` parameter is `ConnectableUndirected`, `ConnectableDirectedHighDutyCycle`,
    /// or `ConnectableDirectedLowDutyCycle`. The advertisements might not be stopped before a
    /// connection is created, and therefore both the Command Complete event and an LE Connection
    /// Complete event could be generated. This can also occur when high duty cycle directed
    /// advertising is timed out and this command disables advertising.
    #[cfg(not(feature = "version-5-0"))]
    fn le_set_advertise_enable(&mut self, enable: bool) -> nb::Result<(), E>;

    /// Requests the Controller to start or stop advertising. The Controller manages the timing of
    /// advertisements as per the advertising parameters given in the
    /// `le_set_advertising_parameters` command.
    ///
    /// The Controller shall continue advertising until the Host issues an
    /// `le_set_advertising_enable` command with `enable` set to false (Advertising is disabled) or
    /// until a connection is created or until the Advertising is timed out due to high duty cycle
    /// Directed Advertising. In these cases, advertising is then disabled.
    ///
    /// If the advertising parameters' `own_address_type` parameter is set to 0x01 and the random
    /// address for the device has not been initialized, the Controller shall return the error code
    /// [`::Status::InvalidHciCommandParameters`].
    ///
    /// If the advertising parameters' `own_address_type` parameter is set to 0x03, the controller's
    /// resolving list did not contain a matching entry, and the random address for the device has
    /// not been initialized, the Controller shall return the error code
    /// [`::Status::InvalidHciCommandParameters`].
    ///
    /// Note: Enabling advertising when it is already enabled can cause the random address to
    /// change. Disabling advertising when it is already disabled has no effect.
    ///
    /// This function was renamed from `le_set_advertise_enable` in Bluetooth v5.0.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.9, in versions 5.0.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// When the command has completed, a Command Complete event shall be generated.
    ///
    /// If the `advertising_type` parameter is [`AdvertisingType::ConnectableDirectedHighDutyCycle`]
    /// and the directed advertising fails to create a connection, an LE Connection Complete event
    /// shall be generated with the Status code set to [`::Status::DirectedAdvertisingTimeout`].
    ///
    /// If the `advertising_type` parameter is [`ConnectableUndirected`],
    /// [`ConnectableDirectedHighDutyCycle`], or [`ConnectableDirectedLowDutyCycle`] and a
    /// connection is created, an LE Connection Complete or LE Enhanced Connection Complete event
    /// shall be generated.
    ///
    /// Note: There is a possible race condition if `enable` is set to false (Disable) and the
    /// `advertising_type` parameter is `ConnectableUndirected`, `ConnectableDirectedHighDutyCycle`,
    /// or `ConnectableDirectedLowDutyCycle`. The advertisements might not be stopped before a
    /// connection is created, and therefore both the Command Complete event and an LE Connection
    /// Complete event or an LE Enhanced Connection Complete event could be generated. This can also
    /// occur when high duty cycle directed advertising is timed out and this command disables
    /// advertising.
    #[cfg(feature = "version-5-0")]
    fn le_set_advertising_enable(&mut self, enable: bool) -> nb::Result<(), E>;

    /// Sets the scan parameters.
    ///
    /// The Host shall not issue this command when scanning is enabled in the Controller; if it is
    /// the [`::Status::CommandDisallowed`] error code shall be used.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.10.
    ///
    /// # Errors
    ///
    /// - `BadScanInterval` if either `scan_interval` or `scan_window` is too short (less than 2.5
    ///   ms) or too long (more than 10.24 s), or if `scan_window` is longer than `scan_interval`,
    /// - Underlying communication errors
    ///
    /// # Generated events
    ///
    /// A command complete event is generated
    fn le_set_scan_parameters(&mut self, params: &ScanParameters) -> nb::Result<(), Error<E>>;

    /// Starts scanning. Scanning is used to discover advertising devices nearby.
    ///
    /// `filter_duplicates` controls whether the Link Layer shall filter duplicate advertising
    /// reports to the Host, or if the Link Layer should generate advertising reports for each
    /// packet received.
    ///
    /// If the scanning parameters' Own_Address_Type parameter is set to 0x01 or 0x03 and the random
    /// address for the device has not been initialized, the Controller shall return the error code
    /// Invalid HCI Command Parameters (0x12).
    ///
    /// If the LE_Scan_Enable parameter is set to 0x01 and scanning is already enabled, any change
    /// to the Filter_Duplicates setting shall take effect.
    ///
    /// Note: Disabling scanning when it is disabled has no effect.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.11.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A command complete event is generated.
    ///
    /// Zero or more LE Advertising Reports are generated by the Controller based on advertising
    /// packets received and the duplicate filtering. More than one advertising packet may be
    /// reported in each LE Advertising Report event.
    fn le_set_scan_enable(&mut self, enable: bool, filter_duplicates: bool) -> nb::Result<(), E>;

    /// Create a Link Layer connection to a connectable advertiser.
    ///
    /// The Host shall not issue this command when another LE_Create_Connection is pending in the
    /// Controller; if this does occur the Controller shall return the `::Status::CommandDisallowed`
    /// error code shall be used.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.12.
    ///
    /// # Errors
    ///
    /// - `BadScanInterval` if either `scan_interval` or `scan_window` are too short (less than 2.5
    ///   msec) or too long (more than 10.24 s), or `scan_window` is longer than `scan_interval`.
    /// - `BadConnectionInterval` if the connection interval is inverted, i.e. if the first value
    ///   (min) is greater than the second (max), or if either value is out of range (7.5 ms to 4
    ///   sec).
    /// - `BadConnectionLatency` if `conn_latency` is greater than 514.
    /// - `BadConnectionLengthRange` if the max expected connection length is less than the min
    ///   expected connection length.
    /// - `BadSupervisionTimeout` if `supervision_timeout` is too short (less than 100 ms) or too
    ///   long (more than 32 s).
    /// - Underlying communication errors
    ///
    /// # Generated events
    ///
    /// The Controller sends the Command Status event to the Host when the event is received.  An LE
    /// Connection Complete event shall be generated when a connection is created or the connection
    /// creation procedure is cancelled.
    ///
    /// Note: No Command Complete event is sent by the Controller to indicate that this command has
    /// been completed. Instead, the LE Connection Complete event indicates that this command has
    /// been completed.
    fn le_create_connection(&mut self, params: &ConnectionParameters) -> nb::Result<(), Error<E>>;

    /// Cancels the `le_create_connection` or `le_extended_create_connection` (for v5.0)
    /// command. This command shall only be issued after the `le_create_connection` command has been
    /// issued, a `CommandStatus` event has been received for the `le_create_connection` command and
    /// before the `LeConnectionComplete` event.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.13.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A command complete event shall be generated.
    ///
    /// If the `le_create_connection_cancel` command is sent to the Controller without a preceding
    /// `le_create_connection` command, the Controller shall return a Command Complete event with
    /// the error code `::Status::CommandDisallowed`.
    ///
    /// The LE Connection Complete event with the error code `::Status::UnknownConnectionIdentifier`
    /// shall be sent after the Command Complete event for the `le_create_connection_cancel` command
    /// if the cancellation was successful.
    fn le_create_connection_cancel(&mut self) -> nb::Result<(), E>;

    /// The `le_read_white_list_size` command is used to read the total number of White List entries
    /// that can be stored in the Controller. Note: The number of entries that can be stored is not
    /// fixed and the Controller can change it at any time (e.g. because the memory used to store
    /// the White List can also be used for other purposes).
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.14.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A command complete event is generated.
    fn le_read_white_list_size(&mut self) -> nb::Result<(), E>;

    /// Clears the white list stored in the Controller.
    ///
    /// This command can be used at any time except when:
    /// - the advertising filter policy uses the white list and advertising is enabled.
    /// - the scanning filter policy uses the white list and scanning is enabled.
    /// - the initiator filter policy uses the white list and an LE_Create_Connection command is
    ///   outstanding.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.15
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A command complete event is generated.
    fn le_clear_white_list(&mut self) -> nb::Result<(), E>;

    /// Adds a single device to the white list stored in the Controller.
    ///
    /// This command can be used at any time except when:
    /// - the advertising filter policy uses the white list and advertising is enabled.
    /// - the scanning filter policy uses the white list and scanning is enabled.
    /// - the initiator filter policy uses the white list and a create connection command is
    ///   outstanding.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.16.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A command complete event is generated.  When a Controller cannot add a device to the White
    /// List because there is no space available, it shall return the error code
    /// `::Status::MemoryCapacityExceeded`.
    fn le_add_device_to_white_list(&mut self, addr: ::BdAddrType) -> nb::Result<(), E>;

    /// Adds anonymous devices sending advertisements to the white list stored in the Controller.
    ///
    /// This command can be used at any time except when:
    /// - the advertising filter policy uses the white list and advertising is enabled.
    /// - the scanning filter policy uses the white list and scanning is enabled.
    /// - the initiator filter policy uses the white list and a create connection command is
    ///   outstanding.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.16.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A command complete event with `ReturnParameters::LeAddDeviceToWhiteList` is generated.  When
    /// a Controller cannot add a device to the White List because there is no space available, it
    /// shall return the error code `::Status::MemoryCapacityExceeded`.
    #[cfg(feature = "version-5-0")]
    fn le_add_anon_advertising_devices_to_white_list(&mut self) -> nb::Result<(), E>;

    /// Removes a single device from the white list stored in the Controller.
    ///
    /// This command can be used at any time except when:
    /// - the advertising filter policy uses the white list and advertising is enabled.
    /// - the scanning filter policy uses the white list and scanning is enabled.
    /// - the initiator filter policy uses the white list and a create connection command is
    ///   outstanding.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.17.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A command complete event is generated.
    fn le_remove_device_from_white_list(&mut self, addr: ::BdAddrType) -> nb::Result<(), E>;

    /// Removes anonymous devices sending advertisements from the white list stored in the
    /// Controller.
    ///
    /// This command can be used at any time except when:
    /// - the advertising filter policy uses the white list and advertising is enabled.
    /// - the scanning filter policy uses the white list and scanning is enabled.
    /// - the initiator filter policy uses the white list and a create connection command is
    ///   outstanding.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.17.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A command complete event is generated.
    #[cfg(feature = "version-5-0")]
    fn le_remove_anon_advertising_devices_from_white_list(&mut self) -> nb::Result<(), E>;

    /// Changes the Link Layer connection parameters of a connection. This command may be issued on
    /// both the master and slave.
    ///
    /// The actual parameter values selected by the Link Layer may be different from the parameter
    /// values provided by the Host through this command.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.18.
    ///
    /// # Errors
    ///
    /// - `BadConnectionInterval` if the connection interval is inverted, i.e. if the first value
    ///   (min) is greater than the second (max), or if either value is out of range (7.5 ms to 4
    ///   sec).
    /// - `BadConnectionLatency` if `conn_latency` is greater than 514.
    /// - `BadConnectionLengthRange` if the max expected connection length is less than the min
    ///   expected connection length.
    /// - `BadSupervisionTimeout` if `supervision_timeout` is too short (less than 100 ms) or too
    ///   long (more than 32 s).
    /// - Underlying communication errors
    ///
    /// # Generated events
    ///
    /// When the Controller receives the LE_Connection_Update command, the Controller sends the
    /// Command Status event to the Host. The LE Connection Update Complete event shall be generated
    /// after the connection parameters have been applied by the Controller.
    ///
    /// Note: a Command Complete event is not sent by the Controller to indicate that this command
    /// has been completed. Instead, the LE Connection Update Complete event indicates that this
    /// command has been completed.
    fn le_connection_update(
        &mut self,
        params: &ConnectionUpdateParameters,
    ) -> nb::Result<(), Error<E>>;
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

    /// For the LE Set Advertising Parameters command: The advertising interval is invalid. This
    /// means that either:
    /// - The min is too low (less than 20 ms)
    /// - The max is too high (higher than 10.24 s)
    /// - The min is greater than the max.
    ///
    /// Includes the provided interval as a pair. The first value is the min, second is max.
    BadAdvertisingInterval(Duration, Duration),

    /// For the LE Set Advertising Parameters command: The channel map did not include any enabled
    /// channels.  Includes the provided channel map.
    BadChannelMap(Channels),

    /// For the LE Set Advertising Parameters command: The advertising interval minimum was too low
    /// for the advertising type.  Includes the provided minimum and advertising type.  This
    /// restriction is removed in version 5.0 of the spec.
    #[cfg(not(feature = "version-5-0"))]
    BadAdvertisingIntervalMin(Duration, AdvertisingType),

    /// For the LE Set Advertising Data or LE Set Scan Response Data commands: The provided data is
    /// too long to fit in the command.  The maximum allowed length is 31.  The actual length is
    /// returned.
    AdvertisingDataTooLong(usize),

    /// For the LE Set Scan Parameters or LE Create Connection command: The scan interval is too
    /// short or too long, or the scan window is too short or too long, or the scan window is longer
    /// than the scan interval.  The first value is the scan interval; the second is the scan
    /// window.
    BadScanInterval(Duration, Duration),

    /// For the LE Create Connection command: The connection interval is invalid. This
    /// means that either:
    /// - The min (or max) is too low (less than 7.5 ms)
    /// - The max (or min) is too high (higher than 4 s)
    /// - The min is greater than the max.
    ///
    /// Includes the provided interval as a pair. The first value is the min, second is max.
    BadConnectionInterval(Duration, Duration),

    /// For the LE Create Connection command: the connection latency is too large. The maximum
    /// allowed value is 514 (defined by the spec).  The value is returned.
    BadConnectionLatency(u16),

    /// For the LE Create Connection command: the supervision timeout is too small (less than 100
    /// ms, or does not meet the requirement: `(1 + conn_latency) * conn_interval_max * 2`) or too
    /// large (greater than 32 seconds).  The first value is the provided supervision timeout.  The
    /// second value is the minimum as determined by the `conn_latency` and `conn_interval_max`.
    BadSupervisionTimeout(Duration, Duration),

    /// For the LE Create Connection command: the connection length range is inverted (i.e, the
    /// minimum is greater than the maximum). Returns the range, min first.
    BadConnectionLengthRange(Duration, Duration),

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

fn set_outbound_data<Header, T, E>(
    controller: &mut T,
    opcode: ::opcode::Opcode,
    data: &[u8],
) -> nb::Result<(), Error<E>>
where
    Header: HciHeader,
    T: ::Controller<Error = E>,
{
    const MAX_DATA_LEN: usize = 31;
    if data.len() > MAX_DATA_LEN {
        return Err(nb::Error::Other(Error::AdvertisingDataTooLong(data.len())));
    }
    let mut params = [0; 32];
    params[0] = data.len() as u8;
    params[1..=data.len()].copy_from_slice(data);
    write_command::<Header, T, E>(controller, opcode, &params).map_err(rewrap_as_comm)
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

    fn le_set_advertising_parameters(
        &mut self,
        params: &AdvertisingParameters,
    ) -> nb::Result<(), Error<E>> {
        let mut bytes = [0; 15];
        params.into_bytes(&mut bytes).map_err(nb::Error::Other)?;
        write_command::<Header, T, E>(self, ::opcode::LE_SET_ADVERTISING_PARAMETERS, &bytes)
            .map_err(rewrap_as_comm)
    }

    fn le_read_advertising_channel_tx_power(&mut self) -> nb::Result<(), E> {
        write_command::<Header, T, E>(self, ::opcode::LE_READ_ADVERTISING_CHANNEL_TX_POWER, &[])
    }

    fn le_set_advertising_data(&mut self, data: &[u8]) -> nb::Result<(), Error<E>> {
        set_outbound_data::<Header, T, E>(self, ::opcode::LE_SET_ADVERTISING_DATA, data)
    }

    fn le_set_scan_response_data(&mut self, data: &[u8]) -> nb::Result<(), Error<E>> {
        set_outbound_data::<Header, T, E>(self, ::opcode::LE_SET_SCAN_RESPONSE_DATA, data)
    }

    #[cfg(not(feature = "version-5-0"))]
    fn le_set_advertise_enable(&mut self, enable: bool) -> nb::Result<(), E> {
        write_command::<Header, T, E>(self, ::opcode::LE_SET_ADVERTISE_ENABLE, &[enable as u8])
    }

    #[cfg(feature = "version-5-0")]
    fn le_set_advertising_enable(&mut self, enable: bool) -> nb::Result<(), E> {
        write_command::<Header, T, E>(self, ::opcode::LE_SET_ADVERTISE_ENABLE, &[enable as u8])
    }

    fn le_set_scan_parameters(&mut self, params: &ScanParameters) -> nb::Result<(), Error<E>> {
        let mut bytes = [0; 7];
        params.into_bytes(&mut bytes).map_err(nb::Error::Other)?;
        write_command::<Header, T, E>(self, ::opcode::LE_SET_SCAN_PARAMETERS, &bytes)
            .map_err(rewrap_as_comm)
    }

    fn le_set_scan_enable(&mut self, enable: bool, filter_duplicates: bool) -> nb::Result<(), E> {
        write_command::<Header, T, E>(
            self,
            ::opcode::LE_SET_SCAN_ENABLE,
            &[enable as u8, filter_duplicates as u8],
        )
    }

    fn le_create_connection(&mut self, params: &ConnectionParameters) -> nb::Result<(), Error<E>> {
        let mut bytes = [0; 25];
        params.into_bytes(&mut bytes).map_err(nb::Error::Other)?;
        write_command::<Header, T, E>(self, ::opcode::LE_CREATE_CONNECTION, &bytes)
            .map_err(rewrap_as_comm)
    }

    fn le_create_connection_cancel(&mut self) -> nb::Result<(), E> {
        write_command::<Header, T, E>(self, ::opcode::LE_CREATE_CONNECTION_CANCEL, &[])
    }

    fn le_read_white_list_size(&mut self) -> nb::Result<(), E> {
        write_command::<Header, T, E>(self, ::opcode::LE_READ_WHITE_LIST_SIZE, &[])
    }

    fn le_clear_white_list(&mut self) -> nb::Result<(), E> {
        write_command::<Header, T, E>(self, ::opcode::LE_CLEAR_WHITE_LIST, &[])
    }

    fn le_add_device_to_white_list(&mut self, addr: ::BdAddrType) -> nb::Result<(), E> {
        let mut params = [0; 7];
        addr.into_bytes(&mut params);
        write_command::<Header, T, E>(self, ::opcode::LE_ADD_DEVICE_TO_WHITE_LIST, &params)
    }

    #[cfg(feature = "version-5-0")]
    fn le_add_anon_advertising_devices_to_white_list(&mut self) -> nb::Result<(), E> {
        write_command::<Header, T, E>(
            self,
            ::opcode::LE_ADD_DEVICE_TO_WHITE_LIST,
            &[0xFF, 0, 0, 0, 0, 0, 0],
        )
    }

    fn le_remove_device_from_white_list(&mut self, addr: ::BdAddrType) -> nb::Result<(), E> {
        let mut params = [0; 7];
        addr.into_bytes(&mut params);
        write_command::<Header, T, E>(self, ::opcode::LE_REMOVE_DEVICE_FROM_WHITE_LIST, &params)
    }

    #[cfg(feature = "version-5-0")]
    fn le_remove_anon_advertising_devices_from_white_list(&mut self) -> nb::Result<(), E> {
        write_command::<Header, T, E>(
            self,
            ::opcode::LE_REMOVE_DEVICE_FROM_WHITE_LIST,
            &[0xFF, 0, 0, 0, 0, 0, 0],
        )
    }

    fn le_connection_update(
        &mut self,
        params: &ConnectionUpdateParameters,
    ) -> nb::Result<(), Error<E>> {
        let mut bytes = [0; 14];
        params.into_bytes(&mut bytes).map_err(nb::Error::Other)?;
        write_command::<Header, T, E>(self, ::opcode::LE_CONNECTION_UPDATE, &bytes)
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

/// Parameters for the `le_set_advertising_parameters` command.
#[derive(Clone, Debug)]
pub struct AdvertisingParameters {
    /// The advertising interval min shall be less than or equal to the advertising interval
    /// max. The advertising interval min and advertising interval max should not be the same value
    /// to enable the Controller to determine the best advertising interval given other activities,
    /// though this implementation allows them to be equal.
    ///
    /// For high duty cycle directed advertising,
    /// i.e. `AdvertisingType::ConnectableDirectedHighDutyCycle`, the Advertising_Interval_Min and
    /// advertising interval max parameters are not used and shall be ignored.  This implementation
    /// sends 0 for both fields in that case.
    ///
    /// The advertising interval min and advertising interval max shall not be set to less than 100
    /// ms if the advertising type is `AdvertisingType::ScannableUndirected` or
    /// `AdvertisingType::NonconnectableUndirected`.  This restriction is removed in version 5.0 of
    /// the spec.
    ///
    /// The first field is the min; the second is the max
    pub advertising_interval: (Duration, Duration),

    /// The advertising type is used to determine the packet type that is used for advertising when
    /// advertising is enabled.
    pub advertising_type: AdvertisingType,

    /// Indicates the type of address being used in the advertising packets.
    ///
    /// If this is `PrivateFallbackPublic` or `PrivateFallbackRandom`, the `peer_address` parameter
    /// contains the peer’s Identity Address and type. These parameters are used to locate the
    /// corresponding local IRK in the resolving list; this IRK is used to generate the own address
    /// used in the advertisement.
    pub own_address_type: OwnAddressType,

    /// If directed advertising is performed, i.e. when `advertising_type` is set to
    /// `ConnectableDirectedHighDutyCycle` or `ConnectableDirectedLowDutyCycle`, then the
    /// Peer_Address_Type and Peer_Address shall be valid.
    ///
    /// If `own_address_type` is `PrivateFallbackPublic` or `PrivateFallbackRandom`, the Controller
    /// generates the peer’s Resolvable Private Address using the peer’s IRK corresponding to the
    /// peer’s Identity Address contained in `peer_address`
    pub peer_address: ::BdAddrType,

    /// Bit field that indicates the advertising channels that shall be used when transmitting
    /// advertising packets. At least one channel bit shall be set in the bitfield.
    pub advertising_channel_map: Channels,

    /// This parameter shall be ignored when directed advertising is enabled.
    pub advertising_filter_policy: AdvertisingFilterPolicy,
}

impl AdvertisingParameters {
    fn into_bytes<E>(&self, bytes: &mut [u8]) -> Result<(), Error<E>> {
        assert_eq!(bytes.len(), 15);

        if self.advertising_channel_map.is_empty() {
            return Err(Error::BadChannelMap(self.advertising_channel_map));
        }

        if self.advertising_type == AdvertisingType::ConnectableDirectedHighDutyCycle {
            LittleEndian::write_u16(&mut bytes[0..], 0);
            LittleEndian::write_u16(&mut bytes[2..], 0);
        } else {
            const MIN_ADVERTISING_INTERVAL: Duration = Duration::from_millis(20);
            const MAX_ADVERTISING_INTERVAL: Duration = Duration::from_millis(10240);
            if self.advertising_interval.0 < MIN_ADVERTISING_INTERVAL
                || self.advertising_interval.1 > MAX_ADVERTISING_INTERVAL
                || self.advertising_interval.0 > self.advertising_interval.1
            {
                return Err(Error::BadAdvertisingInterval(
                    self.advertising_interval.0,
                    self.advertising_interval.1,
                ));
            }

            #[cfg(not(feature = "version-5-0"))]
            {
                const MIN_UNDIRECTED_ADVERTISING_INTERVAL: Duration = Duration::from_millis(100);
                if (self.advertising_type == AdvertisingType::ScannableUndirected
                    || self.advertising_type == AdvertisingType::NonConnectableUndirected)
                    && self.advertising_interval.0 < MIN_UNDIRECTED_ADVERTISING_INTERVAL
                {
                    return Err(Error::BadAdvertisingIntervalMin(
                        self.advertising_interval.0,
                        self.advertising_type,
                    ));
                }
            }

            LittleEndian::write_u16(
                &mut bytes[0..],
                to_interval_value(self.advertising_interval.0),
            );
            LittleEndian::write_u16(
                &mut bytes[2..],
                to_interval_value(self.advertising_interval.1),
            );
        }
        bytes[4] = self.advertising_type as u8;
        bytes[5] = self.own_address_type as u8;
        self.peer_address.into_bytes(&mut bytes[6..13]);
        bytes[13] = self.advertising_channel_map.bits();
        bytes[14] = self.advertising_filter_policy as u8;

        Ok(())
    }
}

fn to_interval_value(duration: Duration) -> u16 {
    // 1600 = 1_000_000 / 625
    (1600 * duration.as_secs() as u32 + (duration.subsec_micros() / 625)) as u16
}

/// The advertising type is used in the `AdvertisingParameters` to determine the packet type that is
/// used for advertising when advertising is enabled.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AdvertisingType {
    /// Connectable undirected advertising (ADV_IND) (default)
    ConnectableUndirected = 0x00,
    /// Connectable high duty cycle directed advertising (ADV_DIRECT_IND, high duty cycle)
    ConnectableDirectedHighDutyCycle = 0x01,
    /// Scannable undirected advertising (ADV_SCAN_IND)
    ScannableUndirected = 0x02,
    /// Non connectable undirected advertising (ADV_NONCONN_IND)
    NonConnectableUndirected = 0x03,
    /// Connectable low duty cycle directed advertising (ADV_DIRECT_IND, low duty cycle)
    ConnectableDirectedLowDutyCycle = 0x04,
}

/// Indicates the type of address being used in the advertising packets.  Set in the
/// `AdvertisingParameters`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum OwnAddressType {
    /// Public Device Address (default)
    Public = 0x00,
    /// Random Device Address
    Random = 0x01,
    /// Controller generates Resolvable Private Address based on the local IRK from resolving
    /// list. If resolving list contains no matching entry, use public address.
    #[cfg(any(feature = "version-4-2", feature = "version-5-0"))]
    PrivateFallbackPublic = 0x02,
    /// Controller generates Resolvable Private Address based on the local IRK from resolving
    /// list. If resolving list contains no matching entry, use random address from
    /// LE_Set_Random_Address.
    #[cfg(any(feature = "version-4-2", feature = "version-5-0"))]
    PrivateFallbackRandom = 0x03,
}

bitflags! {
    /// The advertising channels that shall be used when transmitting advertising packets.
    pub struct Channels : u8 {
        /// Channel 37 shall be used
        const CH_37 = 0b0000_0001;
        /// Channel 38 shall be used
        const CH_38 = 0b0000_0010;
        /// Channel 39 shall be used
        const CH_39 = 0b0000_0100;
    }
}

impl Default for Channels {
    fn default() -> Channels {
        Channels::all()
    }
}

/// Possible filter policies used for undirected advertising.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AdvertisingFilterPolicy {
    /// Process scan and connection requests from all devices (i.e., the White List is not in use)
    /// (default).
    AllowConnectionAndScan = 0x00,
    /// Process connection requests from all devices and only scan requests from devices that are in
    /// the White List.
    AllowConnectionWhiteListScan = 0x01,
    /// Process scan requests from all devices and only connection requests from devices that are in
    /// the White List.
    WhiteListConnectionAllowScan = 0x02,
    /// Process scan and connection requests only from devices in the White List.
    WhiteListConnectionAndScan = 0x03,
}

/// Parameters for the `le_set_scan_parameters` command.
#[derive(Clone, Debug)]
pub struct ScanParameters {
    /// The type of scan to perform
    pub scan_type: ScanType,

    /// Recommendation from the host on how frequently the controller should scan.  See the
    /// Bluetooth spec, Vol 6, Part B, Section 4.5.3.  `scan_window` shall always be set to a value
    /// smaller or equal to `scan_interval`. If they are set to the same value scanning should be
    /// run continuously.
    ///
    /// This is defined as the time interval from when the Controller started its last LE scan until
    /// it begins the subsequent LE scan.
    ///
    /// Range: 2.5 msec to 10.24 seconds
    pub scan_interval: Duration,

    /// Recommendation from the host on how long the controller should scan.  See the Bluetooth
    /// spec, Vol 6, Part B, Section 4.5.3. `scan_window` shall be less than or equal to
    /// `scan_interval`.
    ///
    /// Range: 2.5 msec to 10.24 seconds
    pub scan_window: Duration,

    /// Indicates the type of address being used in the scan request packets.
    pub own_address_type: OwnAddressType,

    /// Indicates which advertising packets to accept.
    pub filter_policy: ScanFilterPolicy,
}

fn verify_scan_interval<E>(scan_interval: Duration, scan_window: Duration) -> Result<(), Error<E>> {
    const MIN_SCAN_INTERVAL: Duration = Duration::from_micros(2500);
    const MAX_SCAN_INTERVAL: Duration = Duration::from_millis(10240);
    if scan_interval < MIN_SCAN_INTERVAL
        || scan_interval > MAX_SCAN_INTERVAL
        || scan_window < MIN_SCAN_INTERVAL
        || scan_window > scan_interval
    {
        Err(Error::BadScanInterval(scan_interval, scan_window))
    } else {
        Ok(())
    }
}

impl ScanParameters {
    fn into_bytes<E>(&self, bytes: &mut [u8]) -> Result<(), Error<E>> {
        assert_eq!(bytes.len(), 7);
        verify_scan_interval(self.scan_interval, self.scan_window)?;

        bytes[0] = self.scan_type as u8;
        LittleEndian::write_u16(&mut bytes[1..], to_interval_value(self.scan_interval));
        LittleEndian::write_u16(&mut bytes[3..], to_interval_value(self.scan_window));
        bytes[5] = self.own_address_type as u8;
        bytes[6] = self.filter_policy as u8;

        Ok(())
    }
}

/// Types of scan to perform.
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum ScanType {
    /// Passive Scanning. No scanning PDUs shall be sent (default).
    Passive = 0x00,
    /// Active scanning. Scanning PDUs may be sent.
    Active = 0x01,
}

/// Which advertising packets to accept from a scan.
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum ScanFilterPolicy {
    /// Accept all advertising packets except directed advertising packets not addressed to this
    /// device (default).
    AcceptAll = 0x00,
    /// Accept only advertising packets from devices where the advertiser’s address is in the White
    /// List. Directed advertising packets which are not addressed to this device shall be ignored.
    WhiteList = 0x01,
    /// Accept all advertising packets except directed advertising packets where the initiator's
    /// identity address does not address this device.
    ///
    /// Note: Directed advertising packets where the initiator's address is a resolvable private
    /// address that cannot be resolved are also accepted.
    #[cfg(any(feature = "version-4-2", feature = "version-5-0"))]
    AddressedToThisDevice = 0x02,
    /// Accept all advertising packets except:
    /// - advertising packets where the advertiser's identity address is not in the White List; and
    /// - directed advertising packets where the initiator's identity addressdoes not address this
    ///   device
    ///
    /// Note: Directed advertising packets where the initiator's address is a resolvable private
    /// address that cannot be resolved are also accepted.
    #[cfg(any(feature = "version-4-2", feature = "version-5-0"))]
    WhiteListAddressedToThisDevice = 0x03,
}

/// Parameters for the LE Create Connection event.
#[derive(Clone, Debug)]
pub struct ConnectionParameters {
    /// Recommendation from the host on how frequently the Controller should scan.  `scan_window`
    /// shall always be set to a value smaller or equal to `scan_interval`.  If they are set to the
    /// same value, scanning should run continuously.
    ///
    /// This is defined as the time interval from when the Controller started its last LE scan until
    /// it begins the subsequent LE scan.
    ///
    /// Range: 2.5 msec to 10.24 seconds
    pub scan_interval: Duration,

    /// Recommendation from the host on how long the controller should scan.  `scan_window` shall be
    /// less than or equal to `scan_interval`.
    ///
    /// Range: 2.5 msec to 10.24 seconds
    pub scan_window: Duration,

    /// Determines whether the White List is used.  If the White List is not used, `peer_address`
    /// specifies the address type and address of the advertising device to connect to.
    pub initiator_filter_policy: ConnectionFilterPolicy,

    /// Indicates the type and value of the address used in the connectable advertisement sent by
    /// the peer. The Host shall not use `PeerAddressType::PublicIdentityAddress` or
    /// `PeerAddressType::RandomIdentityAddress` if both the Host and the Controller support the LE
    /// Set Privacy Mode command. If a Controller that supports the LE Set Privacy Mode command
    /// receives the LE Create Connection command with Peer_Address_Type set to either
    /// `PeerAddressType::PublicIdentityAddress` or `PeerAddressType::RandomIdentityAddress`, it may
    /// use either device privacy mode or network privacy mode for that peer device.
    pub peer_address: PeerAddrType,

    /// The type of address being used in the connection request packets.
    ///
    /// If this is `OwnAddressType::Random` and the random address for the device has not been
    /// initialized, the Controller shall return the error code
    /// `::Status::InvalidHciCommandParameters`.
    ///
    /// If this is `OwnAddressType::PrivateFallbackRandom`, `initiator_filter_policy` is
    /// `ConnectionFilterPolicy::NoWhiteList`, the controller's resolving list did not contain a
    /// matching entry, and the random address for the device has not been initialized, the
    /// Controller shall return the error code `::Status::InvalidHciCommandParameters`.
    ///
    /// If this is set `OwnAddressType::PrivateFallbackRandom`, `initiator_filter_policy` is
    /// `ConnectionFilterPolicy::WhiteList`, and the random address for the device has not been
    /// initialized, the Controller shall return the error code
    /// `::Status::InvalidHciCommandParameters`.
    pub own_address_type: OwnAddressType,

    /// Defines the minimum and maximum allowed connection interval. The first value (min) must be
    /// less than the second (max).
    pub conn_interval: (Duration, Duration),

    /// Defines the maximum allowed connection latency. (see the Bluetooth Spec, Vol 6, Part B,
    /// Section 4.5.1).
    pub conn_latency: u16,

    /// Defines the link supervision timeout for the connection. This shall be larger than
    /// `(1 + conn_latency) * conn_interval.1 * 2`.  See the Bluetooth spec, Vol 6, Part B, Section
    /// 4.5.2.
    pub supervision_timeout: Duration,

    /// Informative parameters providing the Controller with the expected minimum and maximum length
    /// of the connection events.  The first value (min) shall be less than or equal to the second
    /// (max).
    pub expected_connection_length_range: (Duration, Duration),
}

impl ConnectionParameters {
    fn into_bytes<E>(&self, bytes: &mut [u8]) -> Result<(), Error<E>> {
        assert_eq!(bytes.len(), 25);

        verify_scan_interval(self.scan_interval, self.scan_window)?;
        verify_conn_interval(self.conn_interval.0, self.conn_interval.1)?;
        verify_conn_latency(self.conn_latency)?;
        verify_supervision_timeout(
            self.supervision_timeout,
            self.conn_interval.1,
            self.conn_latency,
        )?;

        LittleEndian::write_u16(&mut bytes[0..], to_interval_value(self.scan_interval));
        LittleEndian::write_u16(&mut bytes[2..], to_interval_value(self.scan_window));
        bytes[4] = self.initiator_filter_policy as u8;
        match self.initiator_filter_policy {
            ConnectionFilterPolicy::UseAddress => {
                self.peer_address.into_bytes(&mut bytes[5..12]);
            }
            ConnectionFilterPolicy::WhiteList => {
                bytes[5..12].copy_from_slice(&[0; 7]);
            }
        }
        bytes[12] = self.own_address_type as u8;
        LittleEndian::write_u16(
            &mut bytes[13..],
            to_conn_interval_value(self.conn_interval.0),
        );
        LittleEndian::write_u16(
            &mut bytes[15..],
            to_conn_interval_value(self.conn_interval.1),
        );
        LittleEndian::write_u16(&mut bytes[17..], self.conn_latency);
        LittleEndian::write_u16(
            &mut bytes[19..],
            to_supervision_timeout_value(self.supervision_timeout),
        );
        LittleEndian::write_u16(
            &mut bytes[21..],
            to_interval_value(self.expected_connection_length_range.0),
        );
        LittleEndian::write_u16(
            &mut bytes[23..],
            to_interval_value(self.expected_connection_length_range.1),
        );

        Ok(())
    }
}

fn verify_conn_interval<E>(min: Duration, max: Duration) -> Result<(), Error<E>> {
    const CONN_INTERVAL_MIN: Duration = Duration::from_micros(7500);
    const CONN_INTERVAL_MAX: Duration = Duration::from_secs(4);
    if min < CONN_INTERVAL_MIN || max > CONN_INTERVAL_MAX || min > max {
        return Err(Error::BadConnectionInterval(min, max));
    }

    Ok(())
}

fn verify_conn_latency<E>(latency: u16) -> Result<(), Error<E>> {
    const CONN_LATENCY_MAX: u16 = 0x01F3;
    if latency > CONN_LATENCY_MAX {
        return Err(Error::BadConnectionLatency(latency));
    }

    Ok(())
}

fn verify_supervision_timeout<E>(
    supervision_timeout: Duration,
    conn_interval_max: Duration,
    conn_latency: u16,
) -> Result<(), Error<E>> {
    const SUPERVISION_TIMEOUT_ABS_MIN: Duration = Duration::from_millis(100);
    const SUPERVISION_TIMEOUT_MAX: Duration = Duration::from_secs(32);
    let min_supervision_timeout = conn_interval_max * (1 + conn_latency as u32) * 2;
    if supervision_timeout < min_supervision_timeout
        || supervision_timeout < SUPERVISION_TIMEOUT_ABS_MIN
        || supervision_timeout > SUPERVISION_TIMEOUT_MAX
    {
        return Err(Error::BadSupervisionTimeout(
            supervision_timeout,
            min_supervision_timeout,
        ));
    }

    Ok(())
}

fn to_conn_interval_value(d: Duration) -> u16 {
    // Connection interval value: T = N * 1.25 ms
    // We have T, we need to return N.
    // N = T / 1.25 ms
    //   = 4 * T / 5 ms
    let millis = (d.as_secs() * 1000) as u32 + d.subsec_millis();
    (4 * millis / 5) as u16
}

fn to_supervision_timeout_value(d: Duration) -> u16 {
    // Supervision timeout value: T = N * 10 ms
    // We have T, we need to return N.
    // N = T / 10 ms
    let millis = (d.as_secs() * 1000) as u32 + d.subsec_millis();
    (millis / 10) as u16
}

/// Possible values for the initiator filter policy in the Create Connection command.
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum ConnectionFilterPolicy {
    /// White List is not used to determine which advertiser to connect to.  `peer_address shall be
    /// used in the connection complete event.
    UseAddress = 0x00,

    /// White List is used to determine which advertiser to connect to. `peer_address` shall be
    /// ignored in the connection complete event.
    WhiteList = 0x01,
}

/// Possible values for the peer address in the Create Connection event.
#[derive(Clone, Debug)]
pub enum PeerAddrType {
    /// Public Device Address
    PublicDeviceAddress(::BdAddr),
    /// Random Device Address
    RandomDeviceAddress(::BdAddr),
    /// Public Identity Address (Corresponds to peer’s Resolvable Private Address). This value shall
    /// only be used by the Host if either the Host or the Controller does not support the LE Set
    /// Privacy Mode command.
    PublicIdentityAddress(::BdAddr),
    /// Random (static) Identity Address (Corresponds to peer’s Resolvable Private Address). This
    /// value shall only be used by a Host if either the Host or the Controller does not support the
    /// LE Set Privacy Mode command.
    RandomIdentityAddress(::BdAddr),
}

impl PeerAddrType {
    fn into_bytes(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), 7);
        match *self {
            PeerAddrType::PublicDeviceAddress(bd_addr) => {
                bytes[0] = 0x00;
                bytes[1..7].copy_from_slice(&bd_addr.0);
            }
            PeerAddrType::RandomDeviceAddress(bd_addr) => {
                bytes[0] = 0x01;
                bytes[1..7].copy_from_slice(&bd_addr.0);
            }
            PeerAddrType::PublicIdentityAddress(bd_addr) => {
                bytes[0] = 0x02;
                bytes[1..7].copy_from_slice(&bd_addr.0);
            }
            PeerAddrType::RandomIdentityAddress(bd_addr) => {
                bytes[0] = 0x03;
                bytes[1..7].copy_from_slice(&bd_addr.0);
            }
        }
    }
}

/// Parameters for the `le_connection_update` command.
///
/// See the Bluetooth spec, Vol 2, Part E, Section 7.8.18.
pub struct ConnectionUpdateParameters {
    /// Handle for identifying a connection.
    pub conn_handle: ::ConnectionHandle,

    /// Defines the minimum and maximum allowed connection interval. The first value shall not be
    /// greater than the second.
    ///
    /// Range: 7.5 msec to 4 seconds.
    pub conn_interval: (Duration, Duration),

    /// Defines the maximum allowed connection latency, in number of connection events.
    ///
    /// Range: 0x0000 to 0x01F3
    pub conn_latency: u16,

    /// Defines the link supervision timeout for the connection. This shall be larger than
    /// `(1 + conn_latency) * conn_interval.1 * 2`.
    ///
    /// Absolute range: 100 msec to 32 seconds
    pub supervision_timeout: Duration,

    /// Information parameters providing the Controller with a hint about the expected minimum and
    /// maximum length of the connection events. The first value shall be less than the second.
    ///
    /// Range: 0 to 40.959375 seconds.
    pub expected_connection_length_range: (Duration, Duration),
}

impl ConnectionUpdateParameters {
    fn into_bytes<E>(&self, bytes: &mut [u8]) -> Result<(), Error<E>> {
        assert_eq!(bytes.len(), 14);

        verify_conn_interval(self.conn_interval.0, self.conn_interval.1)?;
        verify_conn_latency(self.conn_latency)?;
        verify_supervision_timeout(
            self.supervision_timeout,
            self.conn_interval.1,
            self.conn_latency,
        )?;

        LittleEndian::write_u16(&mut bytes[0..], self.conn_handle.0);
        LittleEndian::write_u16(
            &mut bytes[2..],
            to_conn_interval_value(self.conn_interval.0),
        );
        LittleEndian::write_u16(
            &mut bytes[4..],
            to_conn_interval_value(self.conn_interval.1),
        );
        LittleEndian::write_u16(&mut bytes[6..], self.conn_latency);
        LittleEndian::write_u16(
            &mut bytes[8..],
            to_supervision_timeout_value(self.supervision_timeout),
        );
        LittleEndian::write_u16(
            &mut bytes[10..],
            to_interval_value(self.expected_connection_length_range.0),
        );
        LittleEndian::write_u16(
            &mut bytes[12..],
            to_interval_value(self.expected_connection_length_range.1),
        );

        Ok(())
    }
}
