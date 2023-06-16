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

/// Potential errors from reading events from the controller.
#[derive(Copy, Clone, Debug)]
pub enum Error<E, VError> {
    /// There was an error deserializing an event. Contains the underlying error.
    BLE(crate::event::Error<VError>),
    /// There was a communication error. Contains the underlying error.
    Comm(E),
}

/// Dummy struct used to specialize [`super::Hci`]. Since the [`Hci`] does not support sending
/// commands, we do not need a real header struct.
pub struct NoCommands;

/// Trait for reading events from the controller. Since this trait should only be used when events
/// are sent by a different physical link than commands, it does not need to implement
/// [`crate::host::Hci`].
///
/// Must be specialized for communication errors (`E`), vendor-specific events (`Vendor`), and
/// vendor-specific errors (`VE`).
///
/// Peeks ahead 2 bytes into the stream to read the length of the parameters for the next event.
///
/// # Errors
///
/// - Returns [`Error::BLE`] if there is an error deserializing the packet
///   (such as a mismatch between the packet length and the expected length of the event). See
///   [`crate::event::Error`] for possible values of `e`.
/// - Returns [`Error::Comm`] if there is an error reading from the
///   controller.
pub trait Hci<E, Vendor, VE> {
    /// Reads and returns an event from the controller. Consumes exactly enough bytes to read the
    /// next event including its header.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::BLE`] if there is an error deserializing the
    ///   packet (such as a mismatch between the packet length and the expected length of the
    ///   event). See [`crate::event::Error`] for possible values of `e`.
    /// - Returns [`Error::Comm`] if there is an error reading from the
    ///   controller.
    async fn read(&mut self) -> Result<crate::Event<Vendor>, Error<E, VE>>
    where
        Vendor: crate::event::VendorEvent<Error = VE>;
}

impl super::HciHeader for NoCommands {
    const HEADER_LENGTH: usize = 3;

    fn new(_opcode: crate::opcode::Opcode, _param_len: usize) -> NoCommands {
        NoCommands
    }

    fn copy_into_slice(&self, _buffer: &mut [u8]) {}
}

fn rewrap_as_comm<E, VE>(e: E) -> Error<E, VE> {
    Error::Comm(e)
}

impl<E, Vendor, VE, T> Hci<E, Vendor, VE> for T
where
    T: crate::Controller<Error = E, Header = NoCommands>,
{
    async fn read(&mut self) -> Result<crate::Event<Vendor>, Error<E, VE>>
    where
        Vendor: crate::event::VendorEvent<Error = VE>,
    {
        const MAX_EVENT_LENGTH: usize = 255;
        const EVENT_HEADER_LENGTH: usize = 2;
        const PARAM_LEN_BYTE: usize = 1;

        let param_len = self.peek(PARAM_LEN_BYTE).await.map_err(rewrap_as_comm)? as usize;

        let mut buf = [0; MAX_EVENT_LENGTH + EVENT_HEADER_LENGTH];
        self.read_into(&mut buf[..EVENT_HEADER_LENGTH + param_len])
            .await
            .map_err(rewrap_as_comm)?;

        crate::Event::new(crate::event::Packet(
            &buf[..EVENT_HEADER_LENGTH + param_len],
        ))
        .map_err(|e| Error::BLE(e))
    }
}
