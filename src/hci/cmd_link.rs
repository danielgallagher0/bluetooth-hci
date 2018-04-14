extern crate nb;

pub struct Header {
    op_code: u16,
    param_len: u8,
}

impl super::HciHeader for Header {
    const HEADER_LENGTH: usize = 3;

    fn new(op_code: u16, param_len: usize) -> Header {
        Header {
            op_code: op_code,
            param_len: param_len as u8,
        }
    }

    // TODO(#42863): Simplify into_bytes into this form:
    // fn into_bytes(&self) -> [u8; HEADER_LENGTH] {
    //     [
    //         super::lsb_of(self.op_code),
    //         super::msb_of(self.op_code),
    //         self.param_len,
    //     ]
    // }

    fn into_bytes(&self, buffer: &mut [u8]) {
        buffer[0] = super::lsb_of(self.op_code);
        buffer[1] = super::msb_of(self.op_code);
        buffer[2] = self.param_len;
    }
}
