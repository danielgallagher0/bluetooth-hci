extern crate nb;

#[derive(Copy, Clone, Debug)]
pub enum Error<E> {
    BLE(::event::Error),
    Comm(E),
}

pub struct EventHeader {
    op_code: ::opcode::OpCode,
    param_len: u8,
}

pub trait Hci<E>: super::Hci<E, EventHeader> {
    fn read(&mut self) -> nb::Result<::Event, Error<E>>;
}

impl super::HciHeader for EventHeader {
    const HEADER_LENGTH: usize = 3;

    fn new(op_code: ::opcode::OpCode, param_len: usize) -> EventHeader {
        EventHeader {
            op_code: op_code,
            param_len: param_len as u8,
        }
    }

    // TODO(#42863): Simplify into_bytes into this form:
    // fn into_bytes(&self) -> [u8; HEADER_LENGTH] {
    //     [
    //         super::lsb_of(self.op_code.0),
    //         super::msb_of(self.op_code.0),
    //         self.param_len,
    //     ]
    // }

    fn into_bytes(&self, buffer: &mut [u8]) {
        buffer[0] = super::lsb_of(self.op_code.0);
        buffer[1] = super::msb_of(self.op_code.0);
        buffer[2] = self.param_len;
    }
}

fn rewrap_error<E>(e: nb::Error<E>) -> nb::Error<Error<E>> {
    match e {
        nb::Error::WouldBlock => nb::Error::WouldBlock,
        nb::Error::Other(err) => nb::Error::Other(Error::Comm(err)),
    }
}

impl<E, T> Hci<E> for T
where
    T: ::Controller<Error = E>,
{
    fn read(&mut self) -> nb::Result<::Event, Error<E>> {
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
