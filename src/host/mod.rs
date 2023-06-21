//! Host-side interface to the Bluetooth HCI.
//!
//! # Ideas for discussion and improvements
//!
//! - Remove `cmd_link` and `event_link` modules. These provide alternative mechanisms for writing
//! to and reading from the controller, respectively, without the packet identifier byte. The
//! open-source Bluetooth implementations I have found (admittedly, I haven't looked hard) only
//! support sending the packet ID, as `uart` does. In that case, it would make sense to also remove
//! `uart` and move its contents up one level.

use crate::ConnectionHandle;
use byteorder::{ByteOrder, LittleEndian};
use core::convert::Into;
use core::fmt::{Debug, Formatter, Result as FmtResult};
use core::time::Duration;

pub mod uart;

pub use super::types::{
    AdvertisingInterval, AdvertisingType, ConnectionInterval, ConnectionIntervalBuilder,
    ExpectedConnectionLength, ScanWindow,
};

use crate::Status;

/// Trait to define a command packet header.
///
/// See the Bluetooth Specification Vol 2, Part E, section 5.4.1. The command packet header contains
/// an opcode (comprising a 6-bit OGF and 10-bit OCF) and a 1-byte parameter length. The packet
/// itself then contains various parameters as defined by the Bluetooth specification.
///
/// Before this command header, many (all?) Bluetooth implementations include a 1-byte packet type
/// preceding the command header. This version of the `HciHeader` is implemented by
/// [`uart::CommandHeader`], while versions without the packet byte are implemented by
/// [`cmd_link::Header`] and [`event_link::NoCommands`].
pub trait HciHeader {
    /// Defines the length of the packet header. With the packet byte, this is 4. Without it, the
    /// length shall be 3.
    const HEADER_LENGTH: usize;

    /// Returns a new header with the given opcode and parameter length.
    fn new(opcode: crate::opcode::Opcode, param_len: usize) -> Self;

    /// Serialize the header into the given buffer, in Bluetooth byte order (little-endian).
    ///
    /// # Panics
    ///
    /// Panics if `buf.len() < Self::HEADER_LENGTH`
    fn copy_into_slice(&self, buf: &mut [u8]);
}

/// Trait defining the interface from the host to the controller.
///
/// Defines one function for each command in the Bluetooth Specification Vol 2, Part E, Sections
/// 7.1-7.6.
///
/// Specializations must define the error type `E`, used for communication errors.
///
/// An implementation is defined or all types that implement [`Controller`](super::Controller).
pub trait HostHci {
    /// Vendor-specific status codes.
    type VS;

    /// Terminates an existing connection.  All synchronous connections on a physical link should be
    /// disconnected before the ACL connection on the same physical connection is disconnected.
    ///
    /// - `conn_handle` indicates which connection is to be disconnected.
    /// - `reason` indicates the reason for ending the connection. The remote Controller will
    ///   receive the Reason command parameter in the [Disconnection
    ///   Complete](crate::event::Event::DisconnectionComplete) event.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.1.6.
    ///
    /// # Errors
    ///
    /// - [`BadDisconnectionReason`](Error::BadDisconnectionReason) when `reason` is not a valid
    ///   disconnection reason.  The reason must be one of [`AuthFailure`](Status::AuthFailure),
    ///   [`RemoteTerminationByUser`](Status::RemoteTerminationByUser),
    ///   [`RemoteTerminationLowResources`](Status::RemoteTerminationLowResources),
    ///   [`RemoteTerminationPowerOff`](Status::RemoteTerminationPowerOff),
    ///   [`UnsupportedRemoteFeature`](Status::UnsupportedRemoteFeature),
    ///   [`PairingWithUnitKeyNotSupported`](Status::PairingWithUnitKeyNotSupported), or
    ///   [`UnacceptableConnectionParameters`](Status::UnacceptableConnectionParameters).
    /// - Underlying communication errors.
    ///
    /// # Generated Events
    ///
    /// When the Controller receives the Disconnect command, it shall send the
    /// [Command Status](crate::event::Event::CommandStatus) event to the Host. The [Disconnection
    /// Complete](crate::event::Event::DisconnectionComplete) event will occur at each Host when the
    /// termination of the connection has completed, and indicates that this command has been
    /// completed.
    ///
    /// Note: No Command Complete event will be sent by the Controller to indicate that this command
    /// has been completed. Instead, the [Disconnection
    /// Complete](crate::event::Event::DisconnectionComplete) event will indicate that this command
    /// has been completed.
    async fn disconnect(
        &mut self,
        conn_handle: ConnectionHandle,
        reason: Status<Self::VS>,
    ) -> Result<(), Error<Self::VS>>;

    /// Obtains the values for the version information for the remote device identified by the
    /// `conn_handle` parameter, which must be a connection handle for an ACL or LE connection.
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
    /// shall send the [Command Status](crate::event::Event::CommandStatus) event to the Host. When
    /// the Link Manager or Link Layer has completed the sequence to determine the remote version
    /// information, the local Controller shall send a [Read Remote Version Information
    /// Complete](crate::event::Event::ReadRemoteVersionInformationComplete) event to the Host. That
    /// event contains the status of this command, and parameters describing the version and
    /// subversion of the LMP or Link Layer used by the remote device.
    ///
    /// Note: No Command Complete event will be sent by the Controller to indicate that this command
    /// has been completed. Instead, the [Read Remote Version Information
    /// Complete](crate::event::Event::ReadRemoteVersionInformationComplete) event will indicate
    /// that this command has been completed.
    async fn read_remote_version_information(&mut self, conn_handle: ConnectionHandle);

    /// Controls which events are generated by the HCI for the Host. If the flag in the mask is set,
    /// then the event associated with that bit will be enabled. For an LE Controller, the [LE Meta
    /// Event](EventFlags::LE_META_EVENT) flag shall enable or disable all LE events (see Section
    /// 7.7.65). The Host has to deal with each event that occurs. The event mask allows the Host to
    /// control how much it is interrupted.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.3.1.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated Events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::SetEventMask) event is
    /// generated.
    async fn set_event_mask(&mut self, mask: EventFlags);

    /// Resets the Controller and the Link Manager on the BR/EDR Controller, the PAL on an AMP
    /// Controller, or the Link Layer on an LE Controller. If the Controller supports both BR/EDR
    /// and LE then the Reset command shall reset the Link Manager, Baseband and Link Layer. The
    /// Reset command shall not affect the used HCI transport layer since the HCI transport layers
    /// may have reset mechanisms of their own. After the reset is completed, the current
    /// operational state will be lost, the Controller will enter standby mode and the Controller
    /// will automatically revert to the default values for the parameters for which default values
    /// are defined in the specification.
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
    /// A [Command Complete](crate::event::command::ReturnParameters::Reset) event is generated.
    async fn reset(&mut self);

    /// Reads the values for the transmit power level for the specified
    /// `conn_handle`. `conn_handle` shall be a connection handle for an ACL connection.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.3.35.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated Events
    ///
    /// A [Comand Complete](crate::event::command::ReturnParameters::ReadTxPowerLevel) event is
    /// generated.
    async fn read_tx_power_level(
        &mut self,
        conn_handle: ConnectionHandle,
        power_level_type: TxPowerLevel,
    );

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
    /// A [Comand Complete](crate::event::command::ReturnParameters::ReadLocalVersionInformation)
    /// event is generated.
    async fn read_local_version_information(&mut self);

    /// Reads the list of HCI commands supported for the local Controller.
    ///
    /// This command shall return the supported commands configuration parameter. It is implied that
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
    /// A [Command Complete](crate::event::command::ReturnParameters::ReadLocalSupportedCommands)
    /// event is generated.
    async fn read_local_supported_commands(&mut self);

    /// Requests a list of the supported features for the local BR/EDR Controller.
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
    /// A [Command Complete](crate::event::command::ReturnParameters::ReadLocalSupportedFeatures)
    /// event is generated.
    async fn read_local_supported_features(&mut self);

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
    /// A [Command Complete](crate::event::command::ReturnParameters::ReadBdAddr) event is
    /// generated.
    async fn read_bd_addr(&mut self);

    /// Reads the Received Signal Strength Indication (RSSI) value from a Controller.
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
    /// PALs (see Volume 5, Core System Package, AMP Controller volume).
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
    /// A [Command Complete](crate::event::command::ReturnParameters::ReadRssi) event is generated.
    async fn read_rssi(&mut self, conn_handle: ConnectionHandle);

    /// Controls which LE events are generated by the HCI for the Host. If the flag in `event_mask`
    /// is set, then the event associated with that flag will be enabled. The Host has to deal with
    /// each event that is generated by an LE Controller. The event mask allows the Host to control
    /// which events will interrupt it.
    ///
    /// For LE events to be generated, the [LE Meta-Event](EventFlags::LE_META_EVENT) flag in the
    /// [Event Mask](Hci::set_event_mask) shall also be set. If that bit is not set, then LE events
    /// shall not be generated, regardless of how the LE Event Mask is set.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.1.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeSetEventMask) event is
    /// generated.
    async fn le_set_event_mask(&mut self, event_mask: LeEventFlags);

    /// Reads the maximum size of the data portion of HCI LE ACL Data Packets sent from the Host to
    /// the Controller.  The Host will segment the data transmitted to the Controller according to
    /// these values, so that the HCI Data Packets will contain data with up to this size. This
    /// command also returns the total number of HCI LE ACL Data Packets that can be stored in the
    /// data buffers of the Controller. This command must be issued by the Host before it sends any
    /// data to an LE Controller (see Section 4.1.1).
    ///
    /// If the Controller returns a length value of zero, the Host shall use the `read_buffer_size`
    /// command to determine the size of the data buffers (shared between BR/EDR and LE
    /// transports).
    ///
    /// Note: Both the `read_buffer_size` and `le_read_buffer_size` commands may return buffer
    /// length and number of packets parameter values that are nonzero. This allows a Controller to
    /// offer different buffers and number of buffers for BR/EDR data packets and LE data packets.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.2.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeReadBufferSize) event is
    /// generated.
    async fn le_read_buffer_size(&mut self);

    /// Requests the list of the supported LE features for the Controller.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.3.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeReadLocalSupportedFeatures)
    /// event is generated.
    async fn le_read_local_supported_features(&mut self);

    /// Sets the LE Random Device Address in the Controller.
    ///
    /// See the Bluetooth spec, Vol 6, Part B, Section 1.3.
    ///
    /// Details added in v5.0:
    ///
    /// - If this command is used to change the address, the new random address shall take effect
    ///   for advertising no later than the next successful [`le_set_advertise_enable`](Hci) command
    ///   (v4.x, renamed to [`le_set_advertising_enable`](Hci) in v5.0), for scanning no later than
    ///   the next successful [`le_set_scan_enable`](Hci::le_set_scan_enable) command or
    ///   `le_set_extended_scan_enable` command, and for initiating no later than the next
    ///   successful [`le_create_connection`](Hci::le_create_connection) command or
    ///   `le_extended_create_connection` command.
    ///
    /// - Note: If Extended Advertising is in use, this command only affects the address used for
    ///   scanning and initiating. The addresses used for advertising are set by the
    ///   `le_set_advertising_set_random_address` command (see Section 7.8.52).
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.4.
    ///
    /// # Errors
    ///
    /// - If the given address does not meet the requirements from Vol 6, Part B, Section 1.3, a
    ///   [`BadRandomAddress`](Error::BadRandomAddress) error is returned.
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
    /// A [Command Complete](crate::event::command::ReturnParameters::LeSetRandomAddress) event is
    /// generated.
    ///
    /// (v5.0) If the Host issues this command when scanning or legacy advertising is enabled, the
    /// Controller shall return the error code [Command Disallowed](Status::CommandDisallowed).
    async fn le_set_random_address(
        &mut self,
        bd_addr: crate::BdAddr,
    ) -> Result<(), Error<Self::VS>>;

    /// Sets the advertising parameters on the Controller.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.5.
    ///
    /// # Errors
    ///
    /// - [`BadChannelMap`](Error::BadChannelMap) if no channels are enabled in the channel map.
    /// - Underlying communication errors
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeSetAdvertisingParameters)
    /// event is generated.
    ///
    /// The Host shall not issue this command when advertising is enabled in the Controller; if it
    /// is the [Command Disallowed](Status::CommandDisallowed) error code shall be used.
    async fn le_set_advertising_parameters(
        &mut self,
        params: &AdvertisingParameters,
    ) -> Result<(), Error<Self::VS>>;

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
    /// A [Command
    /// Complete](crate::event::command::ReturnParameters::LeReadAdvertisingChannelTxPower) event is
    /// generated.
    async fn le_read_advertising_channel_tx_power(&mut self);

    /// Sets the data used in advertising packets that have a data field.
    ///
    /// Only the significant part of the advertising data should be transmitted in the advertising
    /// packets, as defined in the Bluetooth spec, Vol 3, Part C, Section 11. All bytes in `data`
    /// are considered significant.
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
    /// - [`AdvertisingDataTooLong`](Error::AdvertisingDataTooLong) if `data` is 32 bytes or more.
    /// - Underlying communication errors
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::Event::CommandComplete) event is generated.
    async fn le_set_advertising_data(&mut self, data: &[u8]) -> Result<(), Error<Self::VS>>;

    /// Provides data used in scanning packets that have a data field.
    ///
    /// Only the significant part of the scan response data should be transmitted in the Scanning
    /// Packets, as defined in the Bluetooth spec, Vol 3, Part C, Section 11.  All bytes in `data`
    /// are considered significant.
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
    /// - [`AdvertisingDataTooLong`](Error::AdvertisingDataTooLong) if `data` is 32 bytes or more.
    /// - Underlying communication errors
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeSetScanResponseData) event
    /// is generated.
    async fn le_set_scan_response_data(&mut self, data: &[u8]) -> Result<(), Error<Self::VS>>;

    /// Requests the Controller to start or stop advertising. The Controller manages the timing of
    /// advertisements as per the advertising parameters given in the
    /// [`le_set_advertising_parameters`](Hci::le_set_advertising_parameters) command.
    ///
    /// The Controller shall continue advertising until the Host issues this command with enable set
    /// to `false` (Advertising is disabled) or until a connection is created or until the
    /// advertising is timed out due to high duty cycle directed advertising. In these cases,
    /// advertising is then disabled.
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
    /// When the command has completed, a [Command
    /// Complete](crate::event::command::ReturnParameters::LeSetAdvertiseEnable) event shall be
    /// generated.
    ///
    /// If the [advertising type](AdvertisingInterval::for_type) is
    /// [`ConnectableDirectedHighDutyCycle`](AdvertisingType::ConnectableDirectedHighDutyCycle) and
    /// the directed advertising fails to create a connection, an [LE Connection
    /// Complete](crate::event::Event::LeConnectionComplete) event shall be generated with the
    /// Status code set to [`AdvertisingTimeout`](Status::AdvertisingTimeout).
    ///
    /// If the [advertising type](AdvertisingInterval::for_type) is
    /// [`ConnectableUndirected`](AdvertisingType::ConnectableUndirected),
    /// [`ConnectableDirectedHighDutyCycle`](AdvertisingType::ConnectableDirectedHighDutyCycle), or
    /// [`ConnectableDirectedLowDutyCycle`](AdvertisingType::ConnectableDirectedLowDutyCycle) and a
    /// connection is established, an [LE Connection
    /// Complete](crate::event::Event::LeConnectionComplete) event shall be generated.
    ///
    /// Note: There is a possible race condition if `enable` is set to false (Disable) and the
    /// [advertising type](AdvertisingInterval::for_type) is
    /// [`ConnectableUndirected`](AdvertisingType::ConnectableUndirected),
    /// [`ConnectableDirectedHighDutyCycle`](AdvertisingType::ConnectableDirectedHighDutyCycle), or
    /// [`ConnectableDirectedLowDutyCycle`](AdvertisingType::ConnectableDirectedLowDutyCycle). The
    /// advertisements might not be stopped before a connection is created, and therefore both the
    /// Command Complete event and an LE Connection Complete event could be generated. This can also
    /// occur when high duty cycle directed advertising is timed out and this command disables
    /// advertising.
    #[cfg(not(feature = "version-5-0"))]
    async fn le_set_advertise_enable(&mut self, enable: bool);

    /// Requests the Controller to start or stop advertising. The Controller manages the timing of
    /// advertisements as per the advertising parameters given in the
    /// [`le_set_advertising_parameters`](Hci::le_set_advertising_parameters) command.
    ///
    /// The Controller shall continue advertising until the Host issues this command with `enable`
    /// set to false (Advertising is disabled) or until a connection is created or until the
    /// advertising is timed out due to high duty cycle directed advertising. In these cases,
    /// advertising is then disabled.
    ///
    /// If [`own_address_type`](AdvertisingParameters::own_address_type) is set to
    /// [`Random`](OwnAddressType::Random) and the random address for the device has not been
    /// initialized, the Controller shall return the error code
    /// [`InvalidParameters`](Status::InvalidParameters).
    ///
    /// If [`own_address_type`](AdvertisingParameters::own_address_type) is set to
    /// [`PrivateFallbackRandom`](OwnAddressType::PrivateFallbackRandom), the controller's resolving
    /// list did not contain a matching entry, and the random address for the device has not been
    /// initialized, the Controller shall return the error code
    /// [`InvalidParameters`](Status::InvalidParameters).
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
    /// A [Command Complete](crate::event::command::ReturnParameters::LeSetAdvertisingEnable) event
    /// is generated.
    ///
    /// If [`advertising_type`](crate::types::AdvertisingInterval::_advertising_type) is
    /// [`ConnectableDirectedHighDutyCycle`](AdvertisingType::ConnectableDirectedHighDutyCycle) and
    /// the directed advertising fails to create a connection, an [LE Connection
    /// Complete](crate::event::Event::LeConnectionComplete) event shall be generated with the
    /// Status code set to [`AdvertisingTimeout`](Status::AdvertisingTimeout).
    ///
    /// If [`advertising_type`](crate::types::AdvertisingInterval::_advertising_type) is
    /// [`ConnectableUndirected`](AdvertisingType::ConnectableUndirected),
    /// [`ConnectableDirectedHighDutyCycle`](AdvertisingType::ConnectableDirectedHighDutyCycle), or
    /// [`ConnectableDirectedLowDutyCycle`](AdvertisingType::ConnectableDirectedLowDutyCycle) and a
    /// connection is created, an [LE Connection
    /// Complete](crate::event::Event::LeConnectionComplete) or LE Enhanced Connection Complete
    /// event shall be generated.
    ///
    /// Note: There is a possible race condition if `enable` is set to false (Disable) and
    /// [`advertising_type`](crate::types::AdvertisingInterval::_advertising_type) is
    /// [`ConnectableUndirected`](AdvertisingType::ConnectableUndirected),
    /// [`ConnectableDirectedHighDutyCycle`](AdvertisingType::ConnectableDirectedHighDutyCycle), or
    /// [`ConnectableDirectedLowDutyCycle`](AdvertisingType::ConnectableDirectedLowDutyCycle). The
    /// advertisements might not be stopped before a connection is created, and therefore both the
    /// Command Complete event and an LE Connection Complete event or an LE Enhanced Connection
    /// Complete event could be generated. This can also occur when high duty cycle directed
    /// advertising is timed out and this command disables advertising.
    #[cfg(feature = "version-5-0")]
    async fn le_set_advertising_enable(&mut self, enable: bool);

    /// Sets the scan parameters.
    ///
    /// The Host shall not issue this command when scanning is enabled in the Controller; if it is
    /// the [`CommandDisallowed`](Status::CommandDisallowed) error code shall be used.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.10.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeSetScanParameters) event is
    /// generated.
    async fn le_set_scan_parameters(&mut self, params: &ScanParameters);

    /// Starts scanning. Scanning is used to discover advertising devices nearby.
    ///
    /// `filter_duplicates` controls whether the Link Layer shall filter duplicate advertising
    /// reports to the Host, or if the Link Layer should generate advertising reports for each
    /// packet received.
    ///
    /// If [`own_address_type`](ScanParameters::own_address_type) is set to
    /// [`Random`](OwnAddressType::Random) or [`PrivateFallbackRandom`](OwnAddressType) and the
    /// random address for the device has not been initialized, the Controller shall return the
    /// error code [`InvalidParameters`](Status::InvalidParameters).
    ///
    /// If `enable` is true and scanning is already enabled, any change to the `filter_duplicates`
    /// setting shall take effect.
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
    /// A [Command Complete](crate::event::command::ReturnParameters::LeSetScanEnable) event is
    /// generated.
    ///
    /// Zero or more [LE Advertising Reports](crate::event::Event::LeAdvertisingReport) are
    /// generated by the Controller based on advertising packets received and the duplicate
    /// filtering. More than one advertising packet may be reported in each LE Advertising Report
    /// event.
    async fn le_set_scan_enable(&mut self, enable: bool, filter_duplicates: bool);

    /// Creates a Link Layer connection to a connectable advertiser.
    ///
    /// The Host shall not issue this command when another `le_create_connection` is pending in the
    /// Controller; if this does occur the Controller shall return the
    /// [`CommandDisallowed`](Status::CommandDisallowed) error code.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.12.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// The Controller sends the [Command Status](crate::event::Event::CommandStatus) event to the
    /// Host when the event is received.  An [LE Connection
    /// Complete](crate::event::Event::LeConnectionComplete) event shall be generated when a
    /// connection is created or the connection creation procedure is cancelled.
    ///
    /// Note: No Command Complete event is sent by the Controller to indicate that this command has
    /// been completed. Instead, the LE Connection Complete event indicates that this command has
    /// been completed.
    async fn le_create_connection(&mut self, params: &ConnectionParameters);

    /// Cancels the [`le_create_connection`](Hci::le_create_connection) or
    /// `le_extended_create_connection` (for v5.0) command. This command shall only be issued after
    /// the [`le_create_connection`](Hci::le_create_connection) command has been issued, a
    /// [`CommandStatus`](crate::event::Event::CommandStatus) event has been received for the
    /// [`le_create_connection`](Hci::le_create_connection) command and before the
    /// [`LeConnectionComplete`](crate::event::Event::LeConnectionComplete) event.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.13.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeCreateConnectionCancel)
    /// event shall be generated.
    ///
    /// If this command is sent to the Controller without a preceding
    /// [`le_create_connection`](Hci::le_create_connection) command, the Controller shall return a
    /// [Command Complete](crate::event::command::ReturnParameters::LeCreateConnectionCancel) event
    /// with the error code [`CommandDisallowed`](Status::CommandDisallowed).
    ///
    /// The [LE Connection Complete](crate::event::Event::LeConnectionComplete) event with the error
    /// code [`UnknownConnectionId`](Status::UnknownConnectionId) shall be sent after the Command
    /// Complete event for this command if the cancellation was successful.
    async fn le_create_connection_cancel(&mut self);

    /// Reads the total number of White List entries that can be stored in the Controller.
    ///
    /// Note: The number of entries that can be stored is not fixed and the Controller can change it
    /// at any time (e.g. because the memory used to store the White List can also be used for other
    /// purposes).
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.14.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeReadWhiteListSize) event is
    /// generated.
    async fn le_read_white_list_size(&mut self);

    /// Clears the white list stored in the Controller.
    ///
    /// This command can be used at any time except when:
    /// - the advertising filter policy uses the white list and advertising is enabled.
    /// - the scanning filter policy uses the white list and scanning is enabled.
    /// - the initiator filter policy uses the white list and an
    ///   [`le_create_connection`](Hci::le_create_connection) command is outstanding.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.15
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeClearWhiteList) event is
    /// generated.
    async fn le_clear_white_list(&mut self);

    /// Adds a single device to the white list stored in the Controller.
    ///
    /// This command can be used at any time except when:
    /// - the advertising filter policy uses the white list and advertising is enabled.
    /// - the scanning filter policy uses the white list and scanning is enabled.
    /// - the initiator filter policy uses the white list and a
    ///   [`le_create_connection`](Hci::le_create_connection) command is outstanding.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.16.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeAddDeviceToWhiteList) event
    /// is generated. When a Controller cannot add a device to the White List because there is no
    /// space available, it shall return [`OutOfMemory`](Status::OutOfMemory).
    async fn le_add_device_to_white_list(&mut self, addr: crate::BdAddrType);

    /// Adds anonymous devices sending advertisements to the white list stored in the Controller.
    ///
    /// This command can be used at any time except when:
    /// - the advertising filter policy uses the white list and advertising is enabled.
    /// - the scanning filter policy uses the white list and scanning is enabled.
    /// - the initiator filter policy uses the white list and a
    ///   [`le_create_connection`](Hci::le_create_connection) command is outstanding.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.16.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeAddDeviceToWhiteList) event
    /// is generated.  When a Controller cannot add a device to the White List because there is no
    /// space available, it shall return [`OutOfMemory`](Status::OutOfMemory).
    #[cfg(feature = "version-5-0")]
    async fn le_add_anon_advertising_devices_to_white_list(&mut self);

    /// Removes a single device from the white list stored in the Controller.
    ///
    /// This command can be used at any time except when:
    /// - the advertising filter policy uses the white list and advertising is enabled.
    /// - the scanning filter policy uses the white list and scanning is enabled.
    /// - the initiator filter policy uses the white list and a
    ///   [`le_create_connection`](Hci::le_create_connection) command is outstanding.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.17.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeRemoveDeviceFromWhiteList)
    /// event is generated.
    async fn le_remove_device_from_white_list(&mut self, addr: crate::BdAddrType);

    /// Removes anonymous devices sending advertisements from the white list stored in the
    /// Controller.
    ///
    /// This command can be used at any time except when:
    /// - the advertising filter policy uses the white list and advertising is enabled.
    /// - the scanning filter policy uses the white list and scanning is enabled.
    /// - the initiator filter policy uses the white list and a
    ///   [`le_create_connection`](Hci::le_create_connection) command is outstanding.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.17.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeRemoveDeviceFromWhiteList)
    /// event is generated.
    #[cfg(feature = "version-5-0")]
    async fn le_remove_anon_advertising_devices_from_white_list(&mut self);

    /// Changes the Link Layer connection parameters of a connection. This command may be issued on
    /// both the central and peripheral devices.
    ///
    /// The actual parameter values selected by the Link Layer may be different from the parameter
    /// values provided by the Host through this command.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.18.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// When the Controller receives the command, the Controller sends the [Command
    /// Status](crate::event::Event::CommandStatus) event to the Host. The [LE Connection Update
    /// Complete](crate::event::Event::LeConnectionUpdateComplete) event shall be generated after
    /// the connection parameters have been applied by the Controller.
    ///
    /// Note: a Command Complete event is not sent by the Controller to indicate that this command
    /// has been completed. Instead, the LE Connection Update Complete event indicates that this
    /// command has been completed.
    async fn le_connection_update(&mut self, params: &ConnectionUpdateParameters);

    /// This command allows the Host to specify a channel classification for data channels based on
    /// its "local information". This classification persists until overwritten with a subsequent
    /// `le_set_host_channel_classification` command or until the Controller is reset using the
    /// [`reset`](Hci::reset) command.
    ///
    /// If this command is used, the Host should send it within 10 seconds of knowing that the
    /// channel classification has changed. The interval between two successive commands sent shall
    /// be at least one second.
    ///
    /// This command shall only be used when the local device supports the central role.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.19.
    ///
    /// # Errors
    ///
    /// - [`NoValidChannel`](Error::NoValidChannel) if all channels are reported as bad.
    /// - Underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command
    /// Complete](crate::event::command::ReturnParameters::LeSetHostChannelClassification) event is
    /// generated.
    async fn le_set_host_channel_classification(
        &mut self,
        channels: crate::ChannelClassification,
    ) -> Result<(), Error<Self::VS>>;

    /// Returns the current channel map for the specified connection handle. The returned value
    /// indicates the state of the channel map specified by the last transmitted or received channel
    /// map (in a CONNECT_REQ or LL_CHANNEL_MAP_REQ message) for the specified connection handle,
    /// regardless of whether the Master has received an acknowledgement.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.20.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeReadChannelMap) event is
    /// generated.
    async fn le_read_channel_map(&mut self, conn_handle: ConnectionHandle);

    /// Requests a list of the used LE features from the remote device.  This command shall return a
    /// list of the used LE features.
    ///
    /// This command may be issued on both the central and peripheral devices.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.21.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// When the Controller receives this command, the Controller shall send the [Command
    /// Status](`crate::event::Event::CommandStatus) event to the Host. When the Controller has
    /// completed the procedure to determine the remote features, the Controller shall send a [LE
    /// Read Remote Used Features Complete](crate::event::Event::LeReadRemoteUsedFeaturesComplete)
    /// event to the Host.
    ///
    /// The [LE Read Remote Used Features
    /// Complete](crate::event::Event::LeReadRemoteUsedFeaturesComplete) event contains the status
    /// of this command, and the parameter describing the used features of the remote device.
    ///
    /// Note: A Command Complete event is not sent by the Controller to indicate that this command
    /// has been completed. Instead, the LE Read Remote Used Features Complete event indicates that
    /// this command has been completed.
    async fn le_read_remote_used_features(&mut self, conn_handle: ConnectionHandle);

    /// Requests the Controller to encrypt the plaintext data in the command using the key given in
    /// the command and returns the encrypted data to the Host. The AES-128 bit block cypher is
    /// defined in NIST Publication
    /// [FIPS-197](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf).
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.22.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeEncrypt) event is generated.
    async fn le_encrypt(&mut self, params: &AesParameters);

    /// Requests the Controller to generate 8 octets of random data to be sent to the Host. The
    /// random number shall be generated according to the Bluetooth spec, Vol 2, Part H, Section 2
    /// if the [LL Encryption](crate::event::command::LmpFeatures::ENCRYPTION) Feature is supported.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.23.
    ///
    /// # Errors
    ///
    /// Only underlying communication are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeRand) event is generated.
    async fn le_rand(&mut self);

    /// Authenticates the given encryption key associated with the remote device specified by the
    /// connection handle, and once authenticated will encrypt the connection. The parameters are as
    /// defined in the Bluetooth spec, Vol 3, Part H, Section 2.4.4.
    ///
    /// If the connection is already encrypted then the Controller shall pause connection encryption
    /// before attempting to authenticate the given encryption key, and then re-encrypt the
    /// connection. While encryption is paused no user data shall be transmitted.
    ///
    /// On an authentication failure, the connection shall be automatically disconnected by the Link
    /// Layer. If this command succeeds, then the connection shall be encrypted.
    ///
    /// This command shall only be used when the local device is the central device.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.24.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported
    ///
    /// # Generated events
    ///
    /// When the Controller receives this command it shall send the [Command
    /// Status](crate::event::Event::CommandStatus) event to the Host. If the connection is not
    /// encrypted when this command is issued, an [Encryption
    /// Change](crate::event::Event::EncryptionChange) event shall occur when encryption has been
    /// started for the connection. If the connection is encrypted when this command is issued, an
    /// [Encryption Key Refresh Complete](crate::event::Event::EncryptionKeyRefreshComplete) event
    /// shall occur when encryption has been resumed.
    ///
    /// Note: A Command Complete event is not sent by the Controller to indicate that this command
    /// has been completed. Instead, the Encryption Change or Encryption Key Refresh Complete events
    /// indicate that this command has been completed.
    async fn le_start_encryption(&mut self, params: &EncryptionParameters);

    /// Replies to an [LE Long Term Key Request](crate::event::Event::LeLongTermKeyRequest) event
    /// from the Controller, and specifies the long term key parameter that shall be used for this
    /// connection handle.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.25.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeLongTermKeyRequestReply)
    /// event is generated.
    async fn le_long_term_key_request_reply(
        &mut self,
        conn_handle: ConnectionHandle,
        key: &EncryptionKey,
    );

    /// Replies to an [LE Long Term Key Request](crate::event::Event::LeLongTermKeyRequest) event
    /// from the Controller if the Host cannot provide a Long Term Key for this connection handle.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.26.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported
    ///
    /// # Generated events
    ///
    /// A [Command
    /// Complete](crate::event::command::ReturnParameters::LeLongTermKeyRequestNegativeReply) event
    /// is generated.
    async fn le_long_term_key_request_negative_reply(&mut self, conn_handle: ConnectionHandle);

    /// Reads the states and state combinations that the link layer supports.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.27.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeReadSupportedStates) event
    /// is generated.
    async fn le_read_supported_states(&mut self);

    /// Starts a test where the DUT receives test reference packets at a fixed interval. The tester
    /// generates the test reference packets.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.28.
    ///
    /// # Errors
    ///
    /// - [`InvalidTestChannel`](Error::InvalidTestChannel) if the channel is out of range (greater
    ///   than 39).
    /// - Underlying communication errors
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeReceiverTest) event is
    /// generated.
    async fn le_receiver_test(&mut self, channel: u8) -> Result<(), Error<Self::VS>>;

    /// Starts a test where the DUT generates test reference packets at a fixed interval. The
    /// Controller shall transmit at maximum power.
    ///
    /// An LE Controller supporting the `le_transmitter_test` command shall support `payload` values
    /// [`PrbS9`](TestPacketPayload::PrbS9), [`Nibbles10`](TestPacketPayload::Nibbles10) and
    /// [`Bits10`](TestPacketPayload::Bits10). An LE Controller may support other values of
    /// `payload`.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.29.
    ///
    /// # Errors
    ///
    /// - [`InvalidTestChannel`](Error::InvalidTestChannel) if the channel is out of range (greater
    ///   than 39).
    /// - [`InvalidTestPayloadLength`](Error::InvalidTestPayloadLength) if `payload_length` is out
    ///   of range (greater than 37).
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeTransmitterTest) event is
    /// generated.
    async fn le_transmitter_test(
        &mut self,
        channel: u8,
        payload_length: usize,
        payload: TestPacketPayload,
    ) -> Result<(), Error<Self::VS>>;

    /// Stops any test which is in progress.
    ///
    /// See the Bluetooth spec, Vol 2, Part E, Section 7.8.30.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command Complete](crate::event::command::ReturnParameters::LeTestEnd) event is generated.
    async fn le_test_end(&mut self);
}

/// Errors that may occur when sending commands to the controller.  Must be specialized on the types
/// of communication errors.
#[derive(Copy, Clone, Debug, PartialEq, defmt::Format)]
pub enum Error<VS> {
    /// For the [`disconnect`](Hci::disconnect) command: The provided reason is not a valid
    /// disconnection reason. Includes the reported reason.
    BadDisconnectionReason(Status<VS>),

    /// For the [`le_set_random_address`](Hci::le_set_random_address) command: The provided address
    /// does not meet the rules for random addresses in the Bluetooth Spec, Vol 6, Part B, Section
    /// 1.3.  Includes the invalid address.
    BadRandomAddress(crate::BdAddr),

    /// For the [`le_set_advertising_parameters`](Hci::le_set_advertising_parameters) command: The
    /// channel map did not include any enabled channels.  Includes the provided channel map.
    BadChannelMap(Channels),

    /// For the [`le_set_advertising_data`](Hci::le_set_advertising_data) or
    /// [`le_set_scan_response_data`](Hci::le_set_scan_response_data) commands: The provided data is
    /// too long to fit in the command.  The maximum allowed length is 31.  The actual length is
    /// returned.
    AdvertisingDataTooLong(usize),

    /// For the [`le_create_connection`](Hci::le_create_connection) command: the connection length
    /// range is inverted (i.e, the minimum is greater than the maximum). Returns the range, min
    /// first.
    BadConnectionLengthRange(Duration, Duration),

    /// For the [`le_set_host_channel_classification`](Hci::le_set_host_channel_classification)
    /// command: all channels were marked 'bad'.
    NoValidChannel,

    /// For the [`le_receiver_test`](Hci::le_receiver_test) and
    /// [`le_transmitter_test`](Hci::le_transmitter_test) commands: the channel was out of
    /// range. The maximum allowed channel is 39. Includes the invalid value.
    InvalidTestChannel(u8),

    /// For the [`le_transmitter_test`](Hci::le_transmitter_test) command: The payload length is
    /// invalid. The maximum value is 37. Includes the invalid value.
    InvalidTestPayloadLength(usize),
}

async fn write_command<T>(controller: &mut T, opcode: crate::opcode::Opcode, params: &[u8])
where
    T: crate::Controller,
{
    controller.write(opcode, params).await
}

async fn set_outbound_data<T, VS>(
    controller: &mut T,
    opcode: crate::opcode::Opcode,
    data: &[u8],
) -> Result<(), Error<VS>>
where
    T: crate::Controller,
{
    const MAX_DATA_LEN: usize = 31;
    if data.len() > MAX_DATA_LEN {
        return Err(Error::AdvertisingDataTooLong(data.len()));
    }
    let mut params = [0; 32];
    params[0] = data.len() as u8;
    params[1..=data.len()].copy_from_slice(data);
    write_command::<T>(controller, opcode, &params).await;

    Ok(())
}

impl<T> HostHci for T
where
    T: crate::Controller,
{
    type VS = crate::vendor::stm32wb::event::Status;

    async fn disconnect(
        &mut self,
        conn_handle: ConnectionHandle,
        reason: Status<Self::VS>,
    ) -> Result<(), Error<Self::VS>> {
        match reason {
            Status::AuthFailure
            | Status::RemoteTerminationByUser
            | Status::RemoteTerminationLowResources
            | Status::RemoteTerminationPowerOff
            | Status::UnsupportedRemoteFeature
            | Status::PairingWithUnitKeyNotSupported
            | Status::UnacceptableConnectionParameters => (),
            _ => return Err(Error::BadDisconnectionReason(reason)),
        }

        let mut params = [0; 3];
        LittleEndian::write_u16(&mut params[0..], conn_handle.0);
        params[2] = reason.into();
        write_command::<T>(self, crate::opcode::DISCONNECT, &params).await;

        Ok(())
    }

    async fn read_remote_version_information(&mut self, conn_handle: ConnectionHandle) {
        let mut params = [0; 2];
        LittleEndian::write_u16(&mut params, conn_handle.0);
        write_command::<T>(self, crate::opcode::READ_REMOTE_VERSION_INFO, &params).await;
    }

    async fn set_event_mask(&mut self, mask: EventFlags) {
        let mut params = [0; 8];
        LittleEndian::write_u64(&mut params, mask.bits());

        write_command::<T>(self, crate::opcode::SET_EVENT_MASK, &params).await;
    }

    async fn reset(&mut self) {
        write_command::<T>(self, crate::opcode::RESET, &[]).await;
    }

    async fn read_tx_power_level(
        &mut self,
        conn_handle: ConnectionHandle,
        power_level_type: TxPowerLevel,
    ) {
        let mut params = [0; 3];
        LittleEndian::write_u16(&mut params, conn_handle.0);
        params[2] = power_level_type as u8;
        write_command::<T>(self, crate::opcode::READ_TX_POWER_LEVEL, &params).await;
    }

    async fn read_local_version_information(&mut self) {
        write_command::<T>(self, crate::opcode::READ_LOCAL_VERSION_INFO, &[]).await;
    }

    async fn read_local_supported_commands(&mut self) {
        write_command::<T>(self, crate::opcode::READ_LOCAL_SUPPORTED_COMMANDS, &[]).await;
    }

    async fn read_local_supported_features(&mut self) {
        write_command::<T>(self, crate::opcode::READ_LOCAL_SUPPORTED_FEATURES, &[]).await;
    }

    async fn read_bd_addr(&mut self) {
        write_command::<T>(self, crate::opcode::READ_BD_ADDR, &[]).await;
    }

    async fn read_rssi(&mut self, conn_handle: ConnectionHandle) {
        let mut params = [0; 2];
        LittleEndian::write_u16(&mut params, conn_handle.0);
        write_command::<T>(self, crate::opcode::READ_RSSI, &params).await;
    }

    async fn le_set_event_mask(&mut self, event_mask: LeEventFlags) {
        let mut params = [0; 8];
        LittleEndian::write_u64(&mut params, event_mask.bits());

        write_command::<T>(self, crate::opcode::LE_SET_EVENT_MASK, &params).await;
    }

    async fn le_read_buffer_size(&mut self) {
        write_command::<T>(self, crate::opcode::LE_READ_BUFFER_SIZE, &[]).await;
    }

    async fn le_read_local_supported_features(&mut self) {
        write_command::<T>(self, crate::opcode::LE_READ_LOCAL_SUPPORTED_FEATURES, &[]).await;
    }

    async fn le_set_random_address(
        &mut self,
        bd_addr: crate::BdAddr,
    ) -> Result<(), Error<Self::VS>> {
        validate_random_address(bd_addr)?;
        write_command::<T>(self, crate::opcode::LE_SET_RANDOM_ADDRESS, &bd_addr.0).await;

        Ok(())
    }

    async fn le_set_advertising_parameters(
        &mut self,
        params: &AdvertisingParameters,
    ) -> Result<(), Error<Self::VS>> {
        let mut bytes = [0; 15];
        params.copy_into_slice(&mut bytes)?;
        write_command::<T>(self, crate::opcode::LE_SET_ADVERTISING_PARAMETERS, &bytes).await;

        Ok(())
    }

    async fn le_read_advertising_channel_tx_power(&mut self) {
        write_command::<T>(
            self,
            crate::opcode::LE_READ_ADVERTISING_CHANNEL_TX_POWER,
            &[],
        )
        .await;
    }

    async fn le_set_advertising_data(&mut self, data: &[u8]) -> Result<(), Error<Self::VS>> {
        set_outbound_data::<T, Self::VS>(self, crate::opcode::LE_SET_ADVERTISING_DATA, data).await
    }

    async fn le_set_scan_response_data(&mut self, data: &[u8]) -> Result<(), Error<Self::VS>> {
        set_outbound_data::<T, Self::VS>(self, crate::opcode::LE_SET_SCAN_RESPONSE_DATA, data).await
    }

    #[cfg(not(feature = "version-5-0"))]
    async fn le_set_advertise_enable(&mut self, enable: bool) {
        write_command::<T>(
            self,
            crate::opcode::LE_SET_ADVERTISE_ENABLE,
            &[enable as u8],
        )
        .await;
    }

    #[cfg(feature = "version-5-0")]
    async fn le_set_advertising_enable(&mut self, enable: bool) {
        write_command::<T>(
            self,
            crate::opcode::LE_SET_ADVERTISE_ENABLE,
            &[enable as u8],
        )
        .await
    }

    async fn le_set_scan_parameters(&mut self, params: &ScanParameters) {
        let mut bytes = [0; 7];
        params.copy_into_slice(&mut bytes);
        write_command::<T>(self, crate::opcode::LE_SET_SCAN_PARAMETERS, &bytes).await;
    }

    async fn le_set_scan_enable(&mut self, enable: bool, filter_duplicates: bool) {
        write_command::<T>(
            self,
            crate::opcode::LE_SET_SCAN_ENABLE,
            &[enable as u8, filter_duplicates as u8],
        )
        .await;
    }

    async fn le_create_connection(&mut self, params: &ConnectionParameters) {
        let mut bytes = [0; 25];
        params.copy_into_slice(&mut bytes);
        write_command::<T>(self, crate::opcode::LE_CREATE_CONNECTION, &bytes).await;
    }

    async fn le_create_connection_cancel(&mut self) {
        write_command::<T>(self, crate::opcode::LE_CREATE_CONNECTION_CANCEL, &[]).await;
    }

    async fn le_read_white_list_size(&mut self) {
        write_command::<T>(self, crate::opcode::LE_READ_WHITE_LIST_SIZE, &[]).await;
    }

    async fn le_clear_white_list(&mut self) {
        write_command::<T>(self, crate::opcode::LE_CLEAR_WHITE_LIST, &[]).await;
    }

    async fn le_add_device_to_white_list(&mut self, addr: crate::BdAddrType) {
        let mut params = [0; 7];
        addr.copy_into_slice(&mut params);
        write_command::<T>(self, crate::opcode::LE_ADD_DEVICE_TO_WHITE_LIST, &params).await;
    }

    #[cfg(feature = "version-5-0")]
    async fn le_add_anon_advertising_devices_to_white_list(&mut self) {
        write_command::<T>(
            self,
            crate::opcode::LE_ADD_DEVICE_TO_WHITE_LIST,
            &[0xFF, 0, 0, 0, 0, 0, 0],
        )
        .await;
    }

    async fn le_remove_device_from_white_list(&mut self, addr: crate::BdAddrType) {
        let mut params = [0; 7];
        addr.copy_into_slice(&mut params);
        write_command::<T>(
            self,
            crate::opcode::LE_REMOVE_DEVICE_FROM_WHITE_LIST,
            &params,
        )
        .await;
    }

    #[cfg(feature = "version-5-0")]
    async fn le_remove_anon_advertising_devices_from_white_list(&mut self) {
        write_command::<T>(
            self,
            crate::opcode::LE_REMOVE_DEVICE_FROM_WHITE_LIST,
            &[0xFF, 0, 0, 0, 0, 0, 0],
        )
        .await;
    }

    async fn le_connection_update(&mut self, params: &ConnectionUpdateParameters) {
        let mut bytes = [0; 14];
        params.copy_into_slice(&mut bytes);
        write_command::<T>(self, crate::opcode::LE_CONNECTION_UPDATE, &bytes).await;
    }

    async fn le_set_host_channel_classification(
        &mut self,
        channels: crate::ChannelClassification,
    ) -> Result<(), Error<Self::VS>> {
        if channels.is_empty() {
            return Err(Error::NoValidChannel);
        }

        let mut bytes = [0; 5];
        channels.copy_into_slice(&mut bytes);
        write_command::<T>(
            self,
            crate::opcode::LE_SET_HOST_CHANNEL_CLASSIFICATION,
            &bytes,
        )
        .await;

        Ok(())
    }

    async fn le_read_channel_map(&mut self, conn_handle: ConnectionHandle) {
        let mut bytes = [0; 2];
        LittleEndian::write_u16(&mut bytes, conn_handle.0);
        write_command::<T>(self, crate::opcode::LE_READ_CHANNEL_MAP, &bytes).await;
    }

    async fn le_read_remote_used_features(&mut self, conn_handle: ConnectionHandle) {
        let mut bytes = [0; 2];
        LittleEndian::write_u16(&mut bytes, conn_handle.0);
        write_command::<T>(self, crate::opcode::LE_READ_REMOTE_USED_FEATURES, &bytes).await;
    }

    async fn le_encrypt(&mut self, params: &AesParameters) {
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&params.key.0);
        bytes[16..].copy_from_slice(&params.plaintext_data.0);
        write_command::<T>(self, crate::opcode::LE_ENCRYPT, &bytes).await;
    }

    async fn le_rand(&mut self) {
        write_command::<T>(self, crate::opcode::LE_RAND, &[]).await;
    }

    async fn le_start_encryption(&mut self, params: &EncryptionParameters) {
        let mut bytes = [0; 28];
        LittleEndian::write_u16(&mut bytes[0..], params.conn_handle.0);
        LittleEndian::write_u64(&mut bytes[2..], params.random_number);
        LittleEndian::write_u16(&mut bytes[10..], params.encrypted_diversifier);
        bytes[12..].copy_from_slice(&params.long_term_key.0);
        write_command::<T>(self, crate::opcode::LE_START_ENCRYPTION, &bytes).await;
    }

    async fn le_long_term_key_request_reply(
        &mut self,
        conn_handle: ConnectionHandle,
        key: &EncryptionKey,
    ) {
        let mut bytes = [0; 18];
        LittleEndian::write_u16(&mut bytes[0..], conn_handle.0);
        bytes[2..].copy_from_slice(&key.0);
        write_command::<T>(self, crate::opcode::LE_LTK_REQUEST_REPLY, &bytes).await;
    }

    async fn le_long_term_key_request_negative_reply(&mut self, conn_handle: ConnectionHandle) {
        let mut bytes = [0; 2];
        LittleEndian::write_u16(&mut bytes[0..], conn_handle.0);
        write_command::<T>(self, crate::opcode::LE_LTK_REQUEST_NEGATIVE_REPLY, &bytes).await;
    }

    async fn le_read_supported_states(&mut self) {
        write_command::<T>(self, crate::opcode::LE_READ_STATES, &[]).await;
    }

    async fn le_receiver_test(&mut self, channel: u8) -> Result<(), Error<Self::VS>> {
        if channel > MAX_TEST_CHANNEL {
            return Err(Error::InvalidTestChannel(channel));
        }

        write_command::<T>(self, crate::opcode::LE_RECEIVER_TEST, &[channel]).await;

        Ok(())
    }

    async fn le_transmitter_test(
        &mut self,
        channel: u8,
        payload_length: usize,
        payload: TestPacketPayload,
    ) -> Result<(), Error<Self::VS>> {
        if channel > MAX_TEST_CHANNEL {
            return Err(Error::InvalidTestChannel(channel));
        }

        const MAX_PAYLOAD_LENGTH: usize = 0x25;
        if payload_length > MAX_PAYLOAD_LENGTH {
            return Err(Error::InvalidTestPayloadLength(payload_length));
        }

        write_command::<T>(
            self,
            crate::opcode::LE_TRANSMITTER_TEST,
            &[channel, payload_length as u8, payload as u8],
        )
        .await;

        Ok(())
    }

    async fn le_test_end(&mut self) {
        write_command::<T>(self, crate::opcode::LE_TEST_END, &[]).await;
    }
}

const MAX_TEST_CHANNEL: u8 = 0x27;

defmt::bitflags! {
    /// Event flags defined for the [`set_event_mask`](Hci::set_event_mask) command.
    #[derive(Default)]
    pub struct EventFlags : u64 {
        /// Inquiry complete event
        const INQUIRY_COMPLETE = 0x0000_0000_0000_0001;
        /// Inquiry result event
        const INQUIRY_RESULT = 0x0000_0000_0000_0002;
        /// Connection complete event
        const CONNECTION_COMPLETE = 0x0000_0000_0000_0004;
        /// Connection request event
        const CONNECTION_REQUEST = 0x0000_0000_0000_0008;
        /// Disconnection complete event
        const DISCONNECTION_COMPLETE = 0x0000_0000_0000_0010;
        /// Authentication complete event
        const AUTHENTICATION_COMPLETE = 0x0000_0000_0000_0020;
        /// Remote name request complete event
        const REMOTE_NAME_REQUEST_COMPLETE = 0x0000_0000_0000_0040;
        /// Encryption change event
        const ENCRYPTION_CHANGE = 0x0000_0000_0000_0080;
        /// Change connection link key complete event
        const CHANGE_CONNECTION_LINK_KEY_COMPLETE = 0x0000_0000_0000_0100;
        /// Master link key complete event
        const MASTER_LINK_KEY_COMPLETE = 0x0000_0000_0000_0200;
        /// Read remote supported features complete event
        const READ_REMOTE_SUPPORTED_FEATURES_COMPLETE = 0x0000_0000_0000_0400;
        /// Read remote version information complete event
        const READ_REMOTE_VERSION_INFORMATION_COMPLETE = 0x0000_0000_0000_0800;
        /// Qos setup complete event
        const QOS_SETUP_COMPLETE = 0x0000_0000_0000_1000;
        /// Hardware error event
        const HARDWARE_ERROR = 0x0000_0000_0000_8000;
        /// Flush occurred event
        const FLUSH_OCCURRED = 0x0000_0000_0001_0000;
        /// Role change event
        const ROLE_CHANGE = 0x0000_0000_0002_0000;
        /// Mode change event
        const MODE_CHANGE = 0x0000_0000_0008_0000;
        /// Return link keys event
        const RETURN_LINK_KEYS = 0x0000_0000_0010_0000;
        /// Pin code request event
        const PIN_CODE_REQUEST = 0x0000_0000_0020_0000;
        /// Link key request event
        const LINK_KEY_REQUEST = 0x0000_0000_0040_0000;
        /// Link key notification event
        const LINK_KEY_NOTIFICATION = 0x0000_0000_0080_0000;
        /// Loopback command event
        const LOOPBACK_COMMAND = 0x0000_0000_0100_0000;
        /// Data buffer overflow event
        const DATA_BUFFER_OVERFLOW = 0x0000_0000_0200_0000;
        /// Max slots change event
        const MAX_SLOTS_CHANGE = 0x0000_0000_0400_0000;
        /// Read clock offset complete event
        const READ_CLOCK_OFFSET_COMPLETE = 0x0000_0000_0800_0000;
        /// Connection packet type changed event
        const CONNECTION_PACKET_TYPE_CHANGED = 0x0000_0000_1000_0000;
        /// Qos violation event
        const QOS_VIOLATION = 0x0000_0000_2000_0000;
        /// Page scan mode change event. Deprecated in Bluetooth spec.
        #[deprecated]
        const PAGE_SCAN_MODE_CHANGE = 0x0000_0000_4000_0000;
        /// Page scan repetition mode change event
        const PAGE_SCAN_REPETITION_MODE_CHANGE = 0x0000_0000_8000_0000;
        /// Flow specification complete event
        const FLOW_SPECIFICATION_COMPLETE = 0x0000_0001_0000_0000;
        /// Inquiry result with rssi event
        const INQUIRY_RESULT_WITH_RSSI = 0x0000_0002_0000_0000;
        /// Read remote extended features complete event
        const READ_REMOTE_EXTENDED_FEATURES_COMPLETE = 0x0000_0004_0000_0000;
        /// Synchronous connection complete event
        const SYNCHRONOUS_CONNECTION_COMPLETE = 0x0000_0800_0000_0000;
        /// Synchronous connection changed event
        const SYNCHRONOUS_CONNECTION_CHANGED = 0x0000_1000_0000_0000;
        /// Sniff subrating event
        const SNIFF_SUBRATING = 0x0000_2000_0000_0000;
        /// Extended inquiry result event
        const EXTENDED_INQUIRY_RESULT = 0x0000_4000_0000_0000;
        /// Encryption key refresh complete event
        const ENCRYPTION_KEY_REFRESH_COMPLETE = 0x0000_8000_0000_0000;
        /// Io capability request event
        const IO_CAPABILITY_REQUEST = 0x0001_0000_0000_0000;
        /// Io capability request reply event
        const IO_CAPABILITY_REQUEST_REPLY = 0x0002_0000_0000_0000;
        /// User confirmation request event
        const USER_CONFIRMATION_REQUEST = 0x0004_0000_0000_0000;
        /// User passkey request event
        const USER_PASSKEY_REQUEST = 0x0008_0000_0000_0000;
        /// Remote oob data request event
        const REMOTE_OOB_DATA_REQUEST = 0x0010_0000_0000_0000;
        /// Simple pairing complete event
        const SIMPLE_PAIRING_COMPLETE = 0x0020_0000_0000_0000;
        /// Link supervision timeout changed event
        const LINK_SUPERVISION_TIMEOUT_CHANGED = 0x0080_0000_0000_0000;
        /// Enhanced flush complete event
        const ENHANCED_FLUSH_COMPLETE = 0x0100_0000_0000_0000;
        /// User passkey notification event
        const USER_PASSKEY_NOTIFICATION = 0x0400_0000_0000_0000;
        /// Keypress notification event
        const KEYPRESS_NOTIFICATION = 0x0800_0000_0000_0000;
        /// Remote host supported features notification event
        const REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION = 0x1000_0000_0000_0000;
        /// LE meta-events
        const LE_META_EVENT = 0x2000_0000_0000_0000;
    }
}

/// For the [`read_tx_power_level`](Hci::read_tx_power_level) command, the allowed values for the
/// type of power level to read.
///
/// See the Bluetooth spec, Vol 2, Part E, Section 7.3.35.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, defmt::Format)]
pub enum TxPowerLevel {
    /// Read Current Transmit Power Level.
    Current = 0x00,
    /// Read Maximum Transmit Power Level.
    Maximum = 0x01,
}

defmt::bitflags! {
    /// Event flags defined for the [`le_set_event_mask`](Hci::le_set_event_mask) command.
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

fn validate_random_address<VS>(bd_addr: crate::BdAddr) -> Result<(), Error<VS>> {
    let (pop_count, bit_count) = match (bd_addr.0[5] & 0b1100_0000) >> 6 {
        0b00 | 0b11 => (pop_count_except_top_2_bits(&bd_addr.0[0..]), 46),
        0b10 => (pop_count_except_top_2_bits(&bd_addr.0[3..]), 22),
        _ => return Err(Error::BadRandomAddress(bd_addr)),
    };

    if pop_count == 0 || pop_count == bit_count {
        return Err(Error::BadRandomAddress(bd_addr));
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

/// Parameters for the [`le_set_advertising_parameters`](Hci::le_set_advertising_parameters)
/// command.
#[derive(Clone, Debug)]
pub struct AdvertisingParameters {
    /// Type and allowable duration of advertising.
    pub advertising_interval: AdvertisingInterval,

    /// Indicates the type of address being used in the advertising packets.
    ///
    /// If this is [`PrivateFallbackPublic`](OwnAddressType) or
    /// [`PrivateFallbackRandom`](OwnAddressType), the
    /// [`peer_address`](AdvertisingParameters::peer_address) parameter contains the peer's identity
    /// address and type. These parameters are used to locate the corresponding local IRK in the
    /// resolving list; this IRK is used to generate the own address used in the advertisement.
    pub own_address_type: OwnAddressType,

    /// If directed advertising is performed, i.e. when `advertising_type` is set to
    /// [`ConnectableDirectedHighDutyCycle`](AdvertisingType::ConnectableDirectedHighDutyCycle) or
    /// [`ConnectableDirectedLowDutyCycle`](AdvertisingType::ConnectableDirectedLowDutyCycle), then
    /// `peer_address` shall be valid.
    ///
    /// If `own_address_type` is [`PrivateFallbackPublic`](OwnAddressType) or
    /// [`PrivateFallbackRandom`](OwnAddressType), the Controller generates
    /// the peer's Resolvable Private Address using the peer's IRK corresponding to the peer's
    /// Identity Address contained in `peer_address`.
    pub peer_address: crate::BdAddrType,

    /// Bit field that indicates the advertising channels that shall be used when transmitting
    /// advertising packets. At least one channel bit shall be set in the bitfield.
    pub advertising_channel_map: Channels,

    /// This parameter shall be ignored when directed advertising is enabled.
    pub advertising_filter_policy: AdvertisingFilterPolicy,
}

impl AdvertisingParameters {
    fn copy_into_slice<VS>(&self, bytes: &mut [u8]) -> Result<(), Error<VS>> {
        assert_eq!(bytes.len(), 15);

        if self.advertising_channel_map.is_empty() {
            return Err(Error::BadChannelMap(self.advertising_channel_map));
        }

        self.advertising_interval.copy_into_slice(&mut bytes[0..5]);
        bytes[5] = self.own_address_type as u8;
        self.peer_address.copy_into_slice(&mut bytes[6..13]);
        bytes[13] = self.advertising_channel_map.bits();
        bytes[14] = self.advertising_filter_policy as u8;

        Ok(())
    }
}

/// Indicates the type of address being used in the advertising packets.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, defmt::Format)]
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
    /// [`le_set_random_address`](Hci::le_set_random_address).
    #[cfg(any(feature = "version-4-2", feature = "version-5-0"))]
    PrivateFallbackRandom = 0x03,
}

defmt::bitflags! {
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
///
/// See [`AdvertisingParameters`]($crate::host::AdvertisingParameters).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, defmt::Format)]
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

/// Parameters for the [`le_set_scan_parameters`](Hci::le_set_scan_parameters) command.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanParameters {
    /// The type of scan to perform
    pub scan_type: ScanType,

    /// Recommendation from the host on how frequently the controller should scan.  See the
    /// Bluetooth spec, Vol 6, Part B, Section 4.5.3.
    pub scan_window: ScanWindow,

    /// Indicates the type of address being used in the scan request packets.
    pub own_address_type: OwnAddressType,

    /// Indicates which advertising packets to accept.
    pub filter_policy: ScanFilterPolicy,
}

impl ScanParameters {
    fn copy_into_slice(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), 7);

        bytes[0] = self.scan_type as u8;
        self.scan_window.copy_into_slice(&mut bytes[1..5]);
        bytes[5] = self.own_address_type as u8;
        bytes[6] = self.filter_policy as u8;
    }
}

/// Types of scan to perform.
///
/// See [`ScanParameters`] and [`le_set_scan_parameters`](Hci::le_set_scan_parameters).
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
#[derive(defmt::Format)]
pub enum ScanType {
    /// Passive Scanning. No scanning PDUs shall be sent (default).
    Passive = 0x00,
    /// Active scanning. Scanning PDUs may be sent.
    Active = 0x01,
}

/// Which advertising packets to accept from a scan.
///
/// See [`ScanParameters`] and [`le_set_scan_parameters`](Hci::le_set_scan_parameters).
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
#[derive(defmt::Format)]
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

/// Parameters for the [`le_create_connection`](Hci::le_create_connection`) event.
#[derive(Clone, Debug)]
pub struct ConnectionParameters {
    /// Recommendation from the host on how frequently the Controller should scan.
    pub scan_window: ScanWindow,

    /// Determines whether the White List is used.  If the White List is not used, `peer_address`
    /// specifies the address type and address of the advertising device to connect to.
    pub initiator_filter_policy: ConnectionFilterPolicy,

    /// Indicates the type and value of the address used in the connectable advertisement sent by
    /// the peer. The Host shall not use [`PublicIdentityAddress`](PeerAddrType) or
    /// [`RandomIdentityAddress`](PeerAddrType) (both introduced in v4.2) if both the Host and the
    /// Controller support the `le_set_privacy_mode` command (introduced in v5.0). If a Controller
    /// that supports the LE Set Privacy Mode command receives the
    /// [`le_create_connection`](Hci::le_create_connection) command with `peer_address` set to
    /// either [`PublicIdentityAddress`](PeerAddrType) or [`RandomIdentityAddress`](PeerAddrType),
    /// it may use either device privacy mode or network privacy mode for that peer device.
    pub peer_address: PeerAddrType,

    /// The type of address being used in the connection request packets.
    ///
    /// If this is [`Random`](OwnAddressType::Random) and the random address for the device has not
    /// been initialized, the Controller shall return the error code
    /// [`Status::InvalidParameters`].
    ///
    /// If this is [`PrivateFallbackRemote`](OwnAddressType), `initiator_filter_policy` is
    /// [`UseAddress`](ConnectionFilterPolicy::UseAddress), the controller's resolving list did not
    /// contain a matching entry, and the random address for the device has not been initialized,
    /// the Controller shall return the error code [`Status::InvalidParameters`].
    ///
    /// If this is set [`PrivateFallbackRandom`](`OwnAddressType`), `initiator_filter_policy` is
    /// [`WhiteList`](ConnectionFilterPolicy::WhiteList), and the random address for the device has
    /// not been initialized, the Controller shall return the error code
    /// [`Status::InvalidParameters`].
    pub own_address_type: OwnAddressType,

    /// Defines the minimum and maximum allowed connection interval, latency, and supervision
    /// timeout.
    pub conn_interval: ConnectionInterval,

    /// Informative parameters providing the Controller with the expected minimum and maximum length
    /// of the connection events.
    pub expected_connection_length: ExpectedConnectionLength,
}

impl ConnectionParameters {
    fn copy_into_slice(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), 25);

        self.scan_window.copy_into_slice(&mut bytes[0..4]);
        bytes[4] = self.initiator_filter_policy as u8;
        match self.initiator_filter_policy {
            ConnectionFilterPolicy::UseAddress => {
                self.peer_address.copy_into_slice(&mut bytes[5..12]);
            }
            ConnectionFilterPolicy::WhiteList => {
                bytes[5..12].copy_from_slice(&[0; 7]);
            }
        }
        bytes[12] = self.own_address_type as u8;
        self.conn_interval.copy_into_slice(&mut bytes[13..21]);
        self.expected_connection_length
            .copy_into_slice(&mut bytes[21..25]);
    }
}

/// Possible values for the initiator filter policy in the
/// [`le_create_connection`](Hci::le_create_connection) command.
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
#[derive(defmt::Format)]
pub enum ConnectionFilterPolicy {
    /// White List is not used to determine which advertiser to connect to.  `peer_address` shall be
    /// used in the connection complete event.
    UseAddress = 0x00,

    /// White List is used to determine which advertiser to connect to. `peer_address` shall be
    /// ignored in the connection complete event.
    WhiteList = 0x01,
}

/// Possible values for the peer address in the [`le_create_connection`](Hci::le_create_connection)
/// command.
#[derive(Copy, Clone, Debug, defmt::Format)]
pub enum PeerAddrType {
    /// Public Device Address
    PublicDeviceAddress(crate::BdAddr),
    /// Random Device Address
    RandomDeviceAddress(crate::BdAddr),
    /// Public Identity Address (Corresponds to peer's Resolvable Private Address). This value shall
    /// only be used by the Host if either the Host or the Controller does not support the LE Set
    /// Privacy Mode command.
    #[cfg(any(feature = "version-4-2", feature = "version-5-0"))]
    PublicIdentityAddress(crate::BdAddr),
    /// Random (static) Identity Address (Corresponds to peer’s Resolvable Private Address). This
    /// value shall only be used by a Host if either the Host or the Controller does not support the
    /// LE Set Privacy Mode command.
    #[cfg(any(feature = "version-4-2", feature = "version-5-0"))]
    RandomIdentityAddress(crate::BdAddr),
}

impl PeerAddrType {
    /// Serialize the peer address into the given byte buffer.
    ///
    /// # Panics
    ///
    /// `bytes` must be 7 bytes long.
    #[cfg(not(any(feature = "version-4-2", feature = "version-5-0")))]
    pub fn copy_into_slice(&self, bytes: &mut [u8]) {
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
        }
    }

    /// Serialize the peer address into the given byte buffer.
    ///
    /// # Panics
    ///
    /// `bytes` must be 7 bytes long.
    #[cfg(any(feature = "version-4-2", feature = "version-5-0"))]
    pub fn copy_into_slice(&self, bytes: &mut [u8]) {
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

/// Parameters for the [`le_connection_update`](Hci::le_connection_update) command.
///
/// See the Bluetooth spec, Vol 2, Part E, Section 7.8.18.
pub struct ConnectionUpdateParameters {
    /// Handle for identifying a connection.
    pub conn_handle: ConnectionHandle,

    /// Defines the connection interval, latency, and supervision timeout.
    pub conn_interval: ConnectionInterval,

    /// Information parameters providing the Controller with a hint about the expected minimum and
    /// maximum length of the connection events.
    pub expected_connection_length: ExpectedConnectionLength,
}

impl ConnectionUpdateParameters {
    fn copy_into_slice(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), 14);

        LittleEndian::write_u16(&mut bytes[0..], self.conn_handle.0);
        self.conn_interval.copy_into_slice(&mut bytes[2..10]);
        self.expected_connection_length
            .copy_into_slice(&mut bytes[10..14]);
    }
}

/// Parameters for the [`le_encrypt`](Hci::le_encrypt) command.
#[derive(Clone, Debug)]
pub struct AesParameters {
    /// Key for the encryption of the data given in the command.
    ///
    /// The most significant (last) octet of the key corresponds to `key[0]` using the notation
    /// specified in FIPS 197.
    pub key: EncryptionKey,

    /// Data block that is requested to be encrypted.
    ///
    /// The most significant (last) octet of the PlainText_Data corresponds to `in[0]` using the
    /// notation specified in FIPS 197.
    pub plaintext_data: PlaintextBlock,
}

/// Newtype for the encryption key.
///
/// See [`AesParameters`]
#[derive(Clone, PartialEq, defmt::Format)]
pub struct EncryptionKey(pub [u8; 16]);

impl Debug for EncryptionKey {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "AES-128 Key ({:X?})", self.0)
    }
}

/// Newtype for the plaintext data.
///
/// See [`AesParameters`].
#[derive(Clone)]
pub struct PlaintextBlock(pub [u8; 16]);

impl Debug for PlaintextBlock {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "AES-128 Plaintext (REDACTED)")
    }
}

/// Parameters for the [`le_start_encryption`](Hci::le_start_encryption) command.
pub struct EncryptionParameters {
    /// ID for the connection.
    pub conn_handle: ConnectionHandle,

    /// Random value distrubuted by the peripheral during pairing
    pub random_number: u64,

    /// Encrypted diversifier distrubuted by the peripheral during pairing
    pub encrypted_diversifier: u16,

    /// Encryption key, distributed by the host.
    pub long_term_key: EncryptionKey,
}

/// Possible values of the `payload` parameter for the
/// [`le_transmitter_test`](Hci::le_transmitter_test) command.
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
#[derive(defmt::Format)]
pub enum TestPacketPayload {
    /// Pseudo-Random bit sequence 9
    PrbS9 = 0x00,
    /// Pattern of alternating bits `11110000
    Nibbles10 = 0x01,
    /// Pattern of alternating bits `10101010'
    Bits10 = 0x02,
    /// Pseudo-Random bit sequence 15
    PrbS15 = 0x03,
    /// Pattern of All `1' bits
    All1 = 0x04,
    /// Pattern of All `0' bits
    All0 = 0x05,
    /// Pattern of alternating bits `00001111
    Nibbles01 = 0x06,
    /// Pattern of alternating bits `0101'
    Bits01 = 0x07,
}
