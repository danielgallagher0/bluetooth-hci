extern crate nb;

const PACKET_TYPE_HCI_COMMAND: u8 = 0x01;
const PACKET_TYPE_HCI_EVENT: u8 = 0x04;

fn lsb_of(s: u16) -> u8 {
    (s & 0xFF) as u8
}

fn msb_of(s: u16) -> u8 {
    (s >> 8) as u8
}

pub mod uart {
    extern crate nb;

    #[derive(Copy, Clone, Debug)]
    pub enum Error<E> {
        BadPacketType(u8),
        BLE(::event::Error),
        Comm(E),
    }

    #[derive(Clone, Debug)]
    pub enum Packet {
        Event(::Event),
    }

    struct CommandHeader {
        op_code: u16,
        param_len: u8,
    }

    pub trait Hci<E> {
        fn read_local_version_information(&mut self) -> nb::Result<(), Error<E>>;
        fn read(&mut self) -> nb::Result<Packet, Error<E>>;
    }

    const COMMAND_PACKET_HEADER_LENGTH: usize = 4;
    impl CommandHeader {
        fn new(op_code: u16, param_len: usize) -> CommandHeader {
            CommandHeader {
                op_code: op_code,
                param_len: param_len as u8,
            }
        }

        fn into_bytes(&self) -> [u8; COMMAND_PACKET_HEADER_LENGTH] {
            [
                super::PACKET_TYPE_HCI_COMMAND,
                super::lsb_of(self.op_code),
                super::msb_of(self.op_code),
                self.param_len,
            ]
        }
    }

    fn read_event<E, T>(controller: &mut T) -> nb::Result<::Event, Error<E>>
    where
        T: ::Controller<Error = Error<E>>,
    {
        const MAX_EVENT_LENGTH: usize = 255;
        const PACKET_HEADER_LENGTH: usize = 1;
        const EVENT_PACKET_HEADER_LENGTH: usize = 3;
        const PARAM_LEN_BYTE: usize = 2;
        let param_len = controller.peek(PARAM_LEN_BYTE)? as usize;

        let mut buf = [0; MAX_EVENT_LENGTH + EVENT_PACKET_HEADER_LENGTH];
        controller.read_into(&mut buf[..EVENT_PACKET_HEADER_LENGTH + param_len])?;

        ::event::parse_event(::event::Packet(
            &buf[PACKET_HEADER_LENGTH..EVENT_PACKET_HEADER_LENGTH + param_len],
        )).map_err(|e| nb::Error::Other(Error::BLE(e)))
    }

    impl<E, T> Hci<E> for T
    where
        T: ::Controller<Error = Error<E>>,
    {
        fn read(&mut self) -> nb::Result<Packet, Error<E>> {
            match self.peek(0)? {
                super::PACKET_TYPE_HCI_EVENT => Ok(Packet::Event(read_event(self)?)),
                x => Err(nb::Error::Other(Error::BadPacketType(x))),
            }
        }

        fn read_local_version_information(&mut self) -> nb::Result<(), Error<E>> {
            let params = [];
            self.write(
                &CommandHeader::new(::opcode::LOCAL_VERSION_INFO, params.len()).into_bytes(),
                &params,
            )
        }
    }
}
