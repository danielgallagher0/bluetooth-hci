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

    /// Writes the Read Local Version Information command to the controller.
    ///
    /// Defined in Bluetooth Specification Vol 2, Part E, Section 7.4.1.
    ///
    /// # Generated events
    ///
    /// > When the Read_Local_Version_Information command has completed, a Command Complete event
    /// > shall be generated.
    ///
    /// The [`::event::Event::CommandComplete`] event contains
    /// [`::event::command::LocalVersionInfo`].
    fn read_local_version_information(&mut self) -> nb::Result<(), E>;
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
        let mut header = [0; MAX_HEADER_LENGTH];
        Header::new(::opcode::DISCONNECT, params.len()).into_bytes(&mut header);

        self.write(&header[..Header::HEADER_LENGTH], &params)
            .map_err(rewrap_as_comm)
    }

    fn read_remote_version_information(
        &mut self,
        conn_handle: ::ConnectionHandle,
    ) -> nb::Result<(), E> {
        let mut params = [0; 2];
        LittleEndian::write_u16(&mut params, conn_handle.0);
        let mut header = [0; MAX_HEADER_LENGTH];
        Header::new(::opcode::READ_REMOTE_VERSION_INFO, params.len()).into_bytes(&mut header);

        self.write(&header[..Header::HEADER_LENGTH], &params)
    }

    fn read_local_version_information(&mut self) -> nb::Result<(), E> {
        let params = [];
        let mut header = [0; MAX_HEADER_LENGTH];
        Header::new(::opcode::LOCAL_VERSION_INFO, params.len()).into_bytes(&mut header);
        self.write(&header[..Header::HEADER_LENGTH], &params)
    }
}
