extern crate nb;

pub mod cmd_link;
pub mod event_link;
pub mod uart;

const PACKET_TYPE_HCI_COMMAND: u8 = 0x01;
const PACKET_TYPE_HCI_EVENT: u8 = 0x04;

const MAX_HEADER_LENGTH: usize = 5;

pub trait HciHeader {
    const HEADER_LENGTH: usize;

    fn new(op_code: ::opcode::OpCode, param_len: usize) -> Self;

    // TODO(#42863): Simplify into_bytes into this form:
    // fn into_bytes(&self) -> [u8; HEADER_LENGTH];
    fn into_bytes(&self, buf: &mut [u8]);
}

pub trait Hci<E, Header> {
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
        self.write(&header, &params[..Header::HEADER_LENGTH])
    }
}
