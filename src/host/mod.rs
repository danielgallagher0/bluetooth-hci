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

impl<E, T, Header> Hci<E, Header> for T
where
    T: ::Controller<Error = E>,
    Header: HciHeader,
{
    fn read_local_version_information(&mut self) -> nb::Result<(), E> {
        let params = [];
        let mut header = [0; MAX_HEADER_LENGTH];
        Header::new(::opcode::LOCAL_VERSION_INFO, params.len()).into_bytes(&mut header);
        self.write(&header, &params)
    }
}
