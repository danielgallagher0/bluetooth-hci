extern crate nb;

struct Header {
    op_code: u16,
    param_len: u8,
}

fn lsb_of(s: u16) -> u8 {
    (s & 0xFF) as u8
}

fn msb_of(s: u16) -> u8 {
    (s >> 8) as u8
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
            lsb_of(self.op_code),
            msb_of(self.op_code),
            self.param_len,
        ]
    }
}

fn send_command<E>(
    controller: &mut ::Controller<Error = E>,
    op: u16,
    param: &[u8],
) -> nb::Result<(), E> {
    controller.write(&Header::new(op, param.len()).into_bytes(), param)
}

pub fn read_local_version_information<E>(
    controller: &mut ::Controller<Error = E>,
) -> nb::Result<(), E> {
    send_command(controller, ::opcode::LOCAL_VERSION_INFO, &[])
}
