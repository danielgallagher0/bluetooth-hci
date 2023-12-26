#![allow(dead_code)]

extern crate stm32wb_hci as hci;
use hci::{
    host::HciHeader,
    vendor::stm32wb::{event::VendorStatus, CommandHeader},
    Opcode,
};

pub struct RecordingSink {
    pub written_data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct RecordingSinkError;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VendorEvent;
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VendorError;
#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VendorReturnParameters;

pub struct MockVendor;
impl hci::Vendor for MockVendor {
    type Status = VendorStatus;
    type Event = VendorEvent;
}

impl hci::event::VendorEvent for VendorEvent {
    type Error = VendorError;
    type ReturnParameters = VendorReturnParameters;
    type Status = VendorStatus;

    fn new(_buffer: &[u8]) -> Result<Self, hci::event::Error<Self::Error>> {
        Err(hci::event::Error::Vendor(VendorError))
    }
}

impl hci::event::VendorReturnParameters for VendorReturnParameters {
    type Error = VendorError;

    fn new(_buffer: &[u8]) -> Result<Self, hci::event::Error<Self::Error>> {
        Err(hci::event::Error::Vendor(VendorError))
    }
}

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
