//! Implementation of the HCI that includes the packet ID byte in the header.
//!
//! This was originally written just based on wording from the Bluetooth spec (version 5.0, Vol 4,
//! Part A, section 2), emphasis added:
//!
//! > Therefore, *if* the HCI packets are sent via a common physical interface, a HCI
//! > packet indicator has to be added according to Table 2.1 below.
//!
//! However, there don't seem to be any implementations where the HCI packets are _not_ sent "via a
//! common physical interface", so this module may be unnecessary.

use byteorder::{ByteOrder, LittleEndian};

/// Header for HCI Commands.
pub struct Header {
    opcode: crate::opcode::Opcode,
    param_len: u8,
}

impl super::HciHeader for Header {
    const HEADER_LENGTH: usize = 3;

    fn new(opcode: crate::opcode::Opcode, param_len: usize) -> Header {
        Header {
            opcode: opcode,
            param_len: param_len as u8,
        }
    }

    fn into_bytes(&self, buffer: &mut [u8]) {
        LittleEndian::write_u16(buffer, self.opcode.0);
        buffer[2] = self.param_len;
    }
}
