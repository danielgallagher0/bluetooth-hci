pub mod command;

pub struct Packet<'a>(pub &'a [u8]);

pub const PACKET_HEADER_LENGTH: usize = 2;

#[derive(Copy, Clone, Debug)]
pub enum Error {
    UnknownEvent(u8),
    BadLength,
}

#[derive(Clone, Debug)]
pub enum Event {
    CommandComplete(command::CommandComplete),
}

pub fn parse_event(packet: Packet) -> Result<Event, Error> {
    if packet.0.len() < PACKET_HEADER_LENGTH
        || packet.0.len() < PACKET_HEADER_LENGTH + packet.0[1] as usize
    {
        return Err(Error::BadLength);
    }

    match packet.0[0] {
        0x0E => Ok(Event::CommandComplete(command::CommandComplete::new(
            &packet.0[PACKET_HEADER_LENGTH..],
        )?)),
        _ => Err(Error::UnknownEvent(packet.0[0])),
    }
}
