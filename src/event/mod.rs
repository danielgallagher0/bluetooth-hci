pub mod command;

use core::convert::TryInto;
use core::marker::Sized;

pub struct Packet<'a>(pub &'a [u8]);

pub const PACKET_HEADER_LENGTH: usize = 2;

#[derive(Copy, Clone, Debug)]
pub enum Error<V> {
    UnknownEvent(u8),
    BadLength(usize, usize),
    UnknownStatus(u8),
    Vendor(V),
}

#[derive(Copy, Clone, Debug)]
pub struct CommandStatus {
    pub status: ::Status,
    pub num_hci_command_packets: u8,
    pub op_code: ::opcode::OpCode,
}

impl CommandStatus {
    const LENGTH: usize = 4;

    fn new<VE>(buffer: &[u8]) -> Result<CommandStatus, Error<VE>> {
        if buffer.len() != Self::LENGTH {
            return Err(Error::BadLength(buffer.len(), Self::LENGTH));
        }

        Ok(CommandStatus {
            status: buffer[0].try_into().map_err(|e| {
                let ::StatusFromU8Error::BadValue(v) = e;
                Error::UnknownStatus(v)
            })?,
            num_hci_command_packets: buffer[1],
            op_code: ::opcode::OpCode(as_u16(buffer[2], buffer[3])),
        })
    }
}

pub trait VendorEvent {
    type Error;

    fn new(buffer: &[u8]) -> Result<Self, Error<Self::Error>>
    where
        Self: Sized;
}

#[derive(Clone, Debug)]
pub enum Event<Vendor> {
    CommandComplete(command::CommandComplete),
    CommandStatus(CommandStatus),
    Vendor(Vendor),
}

fn as_u16(lsb: u8, msb: u8) -> u16 {
    ((msb as u16) << 8) | (lsb as u16)
}

mod etype {
    pub const COMMAND_COMPLETE: u8 = 0x0E;
    pub const COMMAND_STATUS: u8 = 0x0F;
    pub const VENDOR: u8 = 0xFF;
}

pub fn parse_event<VEvent, VError>(packet: Packet) -> Result<Event<VEvent>, Error<VError>>
where
    VEvent: VendorEvent<Error = VError>,
{
    if packet.0.len() < PACKET_HEADER_LENGTH
        || packet.0.len() < PACKET_HEADER_LENGTH + packet.0[1] as usize
    {
        return Err(Error::BadLength(
            packet.0.len(),
            PACKET_HEADER_LENGTH + packet.0[1] as usize,
        ));
    }

    let event_type = packet.0[0];
    let payload = &packet.0[PACKET_HEADER_LENGTH..];
    match event_type {
        etype::COMMAND_COMPLETE => Ok(Event::CommandComplete(command::CommandComplete::new(
            payload,
        )?)),
        etype::COMMAND_STATUS => Ok(Event::CommandStatus(CommandStatus::new(payload)?)),
        etype::VENDOR => Ok(Event::Vendor(VEvent::new(payload)?)),
        _ => Err(Error::UnknownEvent(event_type)),
    }
}
