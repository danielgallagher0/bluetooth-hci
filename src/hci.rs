extern crate nb;

#[repr(u16)]
#[derive(Copy, Clone, Debug)]
enum InfoParam {
    ReadLocalVersion = 0x0001,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
enum OpCode {
    InfoParam(InfoParam),
}

const fn pack_opcode(ogf: u16, ocf: u16) -> u16 {
    (ogf << 10) | (ocf & 0x03ff)
}

const LOCAL_VERSION_INFO_OPCODE: u16 = pack_opcode(0x0004, 0x0001);

impl OpCode {
    fn pack(self) -> u16 {
        match self {
            OpCode::InfoParam(ocf) => pack_opcode(0x04, ocf as u16),
        }
    }
}

struct Header {
    op_code: u16,
    param_len: u8,
}

impl Header {
    fn new(op_code: u16, plen: usize) -> Header {
        Header {
            op_code: op_code,
            param_len: plen as u8,
        }
    }

    fn into_bytes(self) -> [u8; 3] {
        [
            (self.op_code >> 8) as u8,
            (self.op_code & 0xFF) as u8,
            self.param_len,
        ]
    }
}

fn send_command<E>(
    controller: &mut ::Controller<Error = E>,
    op: OpCode,
    param: &[u8],
) -> nb::Result<(), E> {
    controller.write(&Header::new(op.pack(), param.len()).into_bytes(), param)
}

pub fn read_local_version_information<E>(
    controller: &mut ::Controller<Error = E>,
) -> nb::Result<(), E> {
    send_command(
        controller,
        OpCode::InfoParam(InfoParam::ReadLocalVersion),
        &[],
    )
}

pub struct EventPacket<'a>(pub &'a [u8]);

pub const EVENT_PACKET_HEADER_LENGTH: usize = 2;

#[derive(Copy, Clone, Debug)]
pub enum EventError {
    UnknownEvent(u8),
    BadLength,
}

fn parse_local_version_info(bytes: &[u8]) -> Result<::LocalVersionInfo, EventError> {
    if bytes.len() < 8 {
        return Err(EventError::BadLength);
    }

    Ok(::LocalVersionInfo {
        hci_version: bytes[0],
        hci_revision: ((bytes[1] as u16) << 8) | bytes[2] as u16,
        lmp_version: bytes[3],
        manufacturer_name: ((bytes[4] as u16) << 8) | bytes[5] as u16,
        lmp_subversion: ((bytes[6] as u16) << 8) | bytes[7] as u16,
    })
}

fn parse_command_complete(bytes: &[u8]) -> Result<::CommandComplete, EventError> {
    if bytes.len() < 3 {
        return Err(EventError::BadLength);
    }

    let params = match (bytes[1] as u16) << 8 | bytes[2] as u16 {
        LOCAL_VERSION_INFO_OPCODE => {
            ::ReturnParameters::ReadLocalVersion(parse_local_version_info(&bytes[3..])?)
        }
        _ => ::ReturnParameters::None,
    };
    Ok(::CommandComplete {
        num_hci_command_packets: bytes[0],
        return_params: params,
    })
}

pub fn parse_event(packet: EventPacket) -> Result<::Event, EventError> {
    if packet.0.len() < EVENT_PACKET_HEADER_LENGTH
        || packet.0.len() < EVENT_PACKET_HEADER_LENGTH + packet.0[1] as usize
    {
        return Err(EventError::BadLength);
    }

    match packet.0[0] {
        0x0E => Ok(::Event::CommandComplete(parse_command_complete(
            &packet.0[EVENT_PACKET_HEADER_LENGTH..],
        )?)),
        _ => Err(EventError::UnknownEvent(packet.0[0])),
    }
}
