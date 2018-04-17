extern crate nb;

use byteorder::{ByteOrder, LittleEndian};

#[derive(Copy, Clone, Debug)]
pub enum Error<E, VError> {
    BLE(::event::Error<VError>),
    Comm(E),
}

pub struct EventHeader {
    op_code: ::opcode::OpCode,
    param_len: u8,
}

pub trait Hci<E, Vendor, VE>: super::Hci<E, EventHeader> {
    fn read(&mut self) -> nb::Result<::Event<Vendor>, Error<E, VE>>
    where
        Vendor: ::event::VendorEvent<Error = VE>;
}

impl super::HciHeader for EventHeader {
    const HEADER_LENGTH: usize = 3;

    fn new(op_code: ::opcode::OpCode, param_len: usize) -> EventHeader {
        EventHeader {
            op_code: op_code,
            param_len: param_len as u8,
        }
    }

    fn into_bytes(&self, buffer: &mut [u8]) {
        LittleEndian::write_u16(buffer, self.op_code.0);
        buffer[2] = self.param_len;
    }
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

        ::event::parse_event(::event::Packet(&buf[..EVENT_HEADER_LENGTH + param_len]))
            .map_err(|e| nb::Error::Other(Error::BLE(e)))
    }
}
