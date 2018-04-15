pub mod command;

use core::convert::TryInto;

pub struct Packet<'a>(pub &'a [u8]);

pub const PACKET_HEADER_LENGTH: usize = 2;

#[derive(Copy, Clone, Debug)]
pub enum Error {
    UnknownEvent(u8),
    BadLength(usize, usize),
    UnknownStatus(u8),
}

#[derive(Copy, Clone, Debug)]
pub struct CommandStatus {
    pub status: ::Status,
    pub num_hci_command_packets: u8,
    pub op_code: ::opcode::OpCode,
}

impl CommandStatus {
    const LENGTH: usize = 4;

    fn new(buffer: &[u8]) -> Result<CommandStatus, Error> {
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

#[derive(Clone, Debug)]
pub enum Event {
    CommandComplete(command::CommandComplete),
    CommandStatus(CommandStatus),
}

fn as_u16(lsb: u8, msb: u8) -> u16 {
    ((msb as u16) << 8) | (lsb as u16)
}

pub fn parse_event(packet: Packet) -> Result<Event, Error> {
    if packet.0.len() < PACKET_HEADER_LENGTH
        || packet.0.len() < PACKET_HEADER_LENGTH + packet.0[1] as usize
    {
        return Err(Error::BadLength(
            packet.0.len(),
            PACKET_HEADER_LENGTH + packet.0[1] as usize,
        ));
    }

    match packet.0[0] {
        0x0E => Ok(Event::CommandComplete(command::CommandComplete::new(
            &packet.0[PACKET_HEADER_LENGTH..],
        )?)),
        0x0F => Ok(Event::CommandStatus(CommandStatus::new(&packet.0[PACKET_HEADER_LENGTH..])?)),
        _ => Err(Error::UnknownEvent(packet.0[0])),
    }
}
