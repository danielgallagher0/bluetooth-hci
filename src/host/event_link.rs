//! Implementation of the HCI that only supports reading events from the controller.
//!
//! This was originally written just based on wording from the Bluetooth spec (version 5.0, Vol 4,
//! Part A, section 2), emphasis added:
//!
//! > Therefore, *if* the HCI packets are sent via a common physical interface, a HCI
//! > packet indicator has to be added according to Table 2.1 below.
//!
//! However, there don't seem to be any implementations where the HCI packets are _not_ sent "via a
//! common physical interface", so this module may be unnecessary.

extern crate nb;

/// Potential errors from reading events from the controller.
#[derive(Copy, Clone, Debug)]
pub enum Error<E, VError> {
    /// There was an error deserializing an event. Contains the underlying error.
    BLE(::event::Error<VError>),
    /// There was a communication error. Contains the underlying error.
    Comm(E),
}

/// Dummy struct used to specialize [`super::Hci`]. Since the [`Hci`] does not support sending
/// commands, we do not need a real header struct.
pub struct NoCommands;

/// Trait for reading events from the controller. Since this trait should only be used when events
/// are sent by a different physical link than commands, it does not need to implement
/// [`::host::Hci`].
///
/// Must be specialized for communication errors (`E`), vendor-specific events (`Vendor`), and
/// vendor-specific errors (`VE`).
///
/// Peeks ahead 2 bytes into the stream to read the length of the parameters for the next event.
///
/// # Errors
///
/// - Returns `nb::Error::WouldBlock` if the controller does not have enough bytes to read an
///   event.
///
/// - Returns `nb::Error::Other(Error::BLE(e))` if there is an error deserializing the packet (such
///   as a mismatch between the packet length and the expected length of the event). See
///   [`::event::Error`] for possible values of `e`.
///
/// - Returns `nb::Error::Other(Error::Comm(e))` if there is an error reading from the controller.
pub trait Hci<E, Vendor, VE> {
    /// Reads and returns an event from the controller. Consumes exactly enough bytes to read the
    /// next event including its header.
    ///
    /// # Errors
    ///
    /// - Returns `nb::Error::WouldBlock` if the controller does not have enough bytes available to
    ///   read the full event right now.
    ///
    /// - Returns `nb::Error::Other(Error::BLE(e))` if there is an error deserializing the packet
    ///   (such as a mismatch between the packet length and the expected length of the event). See
    ///   [`::event::Error`] for possible values of `e`.
    ///
    /// - Returns `nb::Error::Other(Error::Comm(e))` if there is an error reading from the
    ///   controller.
    fn read(&mut self) -> nb::Result<::Event<Vendor>, Error<E, VE>>
    where
        Vendor: ::event::VendorEvent<Error = VE>;
}

impl super::HciHeader for NoCommands {
    const HEADER_LENGTH: usize = 3;

    fn new(_opcode: ::opcode::Opcode, _param_len: usize) -> NoCommands {
        NoCommands
    }

    fn into_bytes(&self, _buffer: &mut [u8]) {}
}

fn rewrap_error<E, VE>(e: nb::Error<E>) -> nb::Error<Error<E, VE>> {
    match e {
        nb::Error::WouldBlock => nb::Error::WouldBlock,
        nb::Error::Other(err) => nb::Error::Other(Error::Comm(err)),
    }
}

impl<E, Vendor, VE, T> Hci<E, Vendor, VE> for T
where
    T: ::Controller<Error = E>,
{
    fn read(&mut self) -> nb::Result<::Event<Vendor>, Error<E, VE>>
    where
        Vendor: ::event::VendorEvent<Error = VE>,
    {
        const MAX_EVENT_LENGTH: usize = 255;
        const EVENT_HEADER_LENGTH: usize = 2;
        const PARAM_LEN_BYTE: usize = 1;

        let param_len = self.peek(PARAM_LEN_BYTE).map_err(rewrap_error)? as usize;

        let mut buf = [0; MAX_EVENT_LENGTH + EVENT_HEADER_LENGTH];
        self.read_into(&mut buf[..EVENT_HEADER_LENGTH + param_len])
            .map_err(rewrap_error)?;

        ::Event::new(::event::Packet(&buf[..EVENT_HEADER_LENGTH + param_len]))
            .map_err(|e| nb::Error::Other(Error::BLE(e)))
    }
}
