#![allow(dead_code)]

extern crate stm32wb_hci as hci;
use hci::{host::HciHeader, vendor::stm32wb::CommandHeader, Opcode};

pub struct RecordingSink {
    pub written_data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct RecordingSinkError;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VendorError;

pub struct MockVendor;
impl hci::Vendor for MockVendor {}

impl hci::Controller for RecordingSink {
    async fn controller_write(&mut self, opcode: Opcode, payload: &[u8]) {
        const HEADER_LEN: usize = 4;

        self.written_data.resize(HEADER_LEN + payload.len(), 0);
        {
            let (h, p) = self.written_data.split_at_mut(HEADER_LEN);

            CommandHeader::new(opcode, payload.len()).copy_into_slice(h);

            p.copy_from_slice(payload);
        }
    }

    async fn controller_read_into(&self, _buf: &mut [u8]) {}
}

impl RecordingSink {
    pub fn new() -> RecordingSink {
        RecordingSink {
            written_data: Vec::new(),
        }
    }
}
