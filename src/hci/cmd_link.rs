use byteorder::{ByteOrder, LittleEndian};

pub struct Header {
    op_code: ::opcode::OpCode,
    param_len: u8,
}

impl super::HciHeader for Header {
    const HEADER_LENGTH: usize = 3;

    fn new(op_code: ::opcode::OpCode, param_len: usize) -> Header {
        Header {
            op_code: op_code,
            param_len: param_len as u8,
        }
    }

    fn into_bytes(&self, buffer: &mut [u8]) {
        LittleEndian::write_u16(buffer, self.op_code.0);
        buffer[2] = self.param_len;
    }
}
