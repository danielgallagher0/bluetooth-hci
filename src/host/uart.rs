//! Implementation of the HCI that includes the packet ID byte in the header.

use byteorder::{ByteOrder, LittleEndian};

const PACKET_TYPE_HCI_COMMAND: u8 = 0x01;
// const PACKET_TYPE_ACL_DATA: u8 = 0x02;
// const PACKET_TYPE_SYNC_DATA: u8 = 0x03;
const PACKET_TYPE_HCI_EVENT: u8 = 0x04;

/// Potential errors from reading or writing packets to the controller.
///
/// Must be specialized both for communication errors (`E`) and vendor-specific errors (`VE`).
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error<VE> {
    /// The host expected the controller to begin a packet, but the next byte is not a valid packet
    /// type byte. Contains the value of the byte.
    BadPacketType(u8),
    /// There was an error deserializing an event. Contains the underlying error.
    BLE(crate::event::Error<VE>),
}

/// Packet types that may be read from the controller.
#[derive(Clone, Debug)]
pub enum Packet<Vendor>
where
    Vendor: crate::event::VendorEvent,
{
    // AclData(AclData),
    // SyncData(SyncData),
    /// The HCI Event Packet is used by the Controller to notify the Host when events
    /// occur. The event is specialized to support vendor-specific events.
    Event(crate::Event<Vendor>),
}

/// Header for HCI Commands.
pub struct CommandHeader {
    opcode: crate::opcode::Opcode,
    param_len: u8,
}

/// Trait for reading packets from the controller.
///
/// Implementors must also implement [`crate::host::HostHci`], which provides all of the functions to
/// write commands to the controller. This trait adds the ability to read packets back from the
/// controller.
///
/// Must be specialized for communication errors (`E`), vendor-specific events (`Vendor`), and
/// vendor-specific errors (`VE`).
pub trait UartHci<VendorEvent, VE>: super::HostHci {
    /// Reads and returns a packet from the controller. Consumes exactly enough bytes to read the
    /// next packet including its header.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::BadPacketType`] if the next byte is not a valid
    ///   packet type.
    /// - Returns [`Error::BLE`] if there is an error deserializing the
    ///   packet (such as a mismatch between the packet length and the expected length of the
    ///   event). See [`crate::event::Error`] for possible values of `e`.
    /// - Returns [`Error::Comm`] if there is an error reading from the
    ///   controller.
    async fn read(&mut self) -> Result<Packet<VendorEvent>, Error<VE>>
    where
        VendorEvent: crate::event::VendorEvent<Error = VE>;
}

impl super::HciHeader for CommandHeader {
    const HEADER_LENGTH: usize = 4;

    fn new(opcode: crate::opcode::Opcode, param_len: usize) -> CommandHeader {
        CommandHeader {
            opcode,
            param_len: param_len as u8,
        }
    }

    fn copy_into_slice(&self, buffer: &mut [u8]) {
        buffer[0] = PACKET_TYPE_HCI_COMMAND;
        LittleEndian::write_u16(&mut buffer[1..=2], self.opcode.0);
        buffer[3] = self.param_len;
    }
}

async fn read_event<T, Vendor, VE>(controller: &mut T) -> Result<crate::Event<Vendor>, Error<VE>>
where
    T: crate::Controller,
    Vendor: crate::event::VendorEvent<Error = VE>,
{
    const MAX_EVENT_LENGTH: usize = 255;
    const PACKET_HEADER_LENGTH: usize = 1;
    const EVENT_PACKET_HEADER_LENGTH: usize = 3;
    const PARAM_LEN_BYTE: usize = 2;

    let param_len = controller.peek(PARAM_LEN_BYTE).await as usize;

    let mut buf = [0; MAX_EVENT_LENGTH + EVENT_PACKET_HEADER_LENGTH];
    controller
        .read_into(&mut buf[..EVENT_PACKET_HEADER_LENGTH + param_len])
        .await;

    crate::event::Event::new(crate::event::Packet(
        &buf[PACKET_HEADER_LENGTH..EVENT_PACKET_HEADER_LENGTH + param_len],
    ))
    .map_err(|e| Error::BLE(e))
}

impl<VendorEvent, VE, T> UartHci<VendorEvent, VE> for T
where
    T: crate::Controller,
{
    async fn read(&mut self) -> Result<Packet<VendorEvent>, Error<VE>>
    where
        VendorEvent: crate::event::VendorEvent<Error = VE>,
    {
        match self.peek(0).await {
            PACKET_TYPE_HCI_EVENT => Ok(Packet::Event(read_event(self).await?)),
            x => Err(Error::BadPacketType(x)),
        }
    }
}
