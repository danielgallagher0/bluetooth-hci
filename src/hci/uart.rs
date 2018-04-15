extern crate nb;

#[derive(Copy, Clone, Debug)]
pub enum Error<E, VE> {
    BadPacketType(u8),
    BLE(::event::Error<VE>),
    Comm(E),
}

#[derive(Clone, Debug)]
pub enum Packet<Vendor> {
    Event(::Event<Vendor>),
}

pub struct CommandHeader {
    op_code: ::opcode::OpCode,
    param_len: u8,
}

pub trait Hci<E, Vendor, VE>: super::Hci<E, CommandHeader> {
    fn read(&mut self) -> nb::Result<Packet<Vendor>, Error<E, VE>>
    where
        Vendor: ::event::VendorEvent<Error = VE>;
}

impl super::HciHeader for CommandHeader {
    const HEADER_LENGTH: usize = 4;

    fn new(op_code: ::opcode::OpCode, param_len: usize) -> CommandHeader {
        CommandHeader {
            op_code: op_code,
            param_len: param_len as u8,
        }
    }

    // TODO(#42863): Simplify into_bytes into this form:
    // fn into_bytes(&self) -> [u8; COMMAND_PACKET_HEADER_LENGTH] {
    //     [
    //         super::PACKET_TYPE_HCI_COMMAND,
    //         super::lsb_of(self.op_code.0),
    //         super::msb_of(self.op_code.0),
    //         self.param_len,
    //     ]
    // }

    fn into_bytes(&self, buffer: &mut [u8]) {
        buffer[0] = super::PACKET_TYPE_HCI_COMMAND;
        buffer[1] = super::lsb_of(self.op_code.0);
        buffer[2] = super::msb_of(self.op_code.0);
        buffer[3] = self.param_len;
    }
}

fn rewrap_error<E, VE>(e: nb::Error<E>) -> nb::Error<Error<E, VE>> {
    match e {
        nb::Error::WouldBlock => nb::Error::WouldBlock,
        nb::Error::Other(err) => nb::Error::Other(Error::Comm(err)),
    }
}

fn read_event<E, T, Vendor, VE>(controller: &mut T) -> nb::Result<::Event<Vendor>, Error<E, VE>>
where
    T: ::Controller<Error = E>,
    Vendor: ::event::VendorEvent<Error = VE>,
{
    const MAX_EVENT_LENGTH: usize = 255;
    const PACKET_HEADER_LENGTH: usize = 1;
    const EVENT_PACKET_HEADER_LENGTH: usize = 3;
    const PARAM_LEN_BYTE: usize = 2;

    let param_len = controller.peek(PARAM_LEN_BYTE).map_err(rewrap_error)? as usize;

    let mut buf = [0; MAX_EVENT_LENGTH + EVENT_PACKET_HEADER_LENGTH];
    controller
        .read_into(&mut buf[..EVENT_PACKET_HEADER_LENGTH + param_len])
        .map_err(rewrap_error)?;

    ::event::parse_event(::event::Packet(
        &buf[PACKET_HEADER_LENGTH..EVENT_PACKET_HEADER_LENGTH + param_len],
    )).map_err(|e| nb::Error::Other(Error::BLE(e)))
}

impl<E, Vendor, VE, T> Hci<E, Vendor, VE> for T
where
    T: ::Controller<Error = E>,
{
    fn read(&mut self) -> nb::Result<Packet<Vendor>, Error<E, VE>>
    where
        Vendor: ::event::VendorEvent<Error = VE>,
    {
        match self.peek(0).map_err(rewrap_error)? {
            super::PACKET_TYPE_HCI_EVENT => Ok(Packet::Event(read_event(self)?)),
            x => Err(nb::Error::Other(Error::BadPacketType(x))),
        }
    }
}
