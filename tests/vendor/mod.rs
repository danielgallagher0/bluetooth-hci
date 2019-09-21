#![allow(dead_code)]

extern crate bluetooth_hci as hci;
extern crate nb;

use hci::host::*;
use std;

pub struct RecordingSink {
    pub written_data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct RecordingSinkError;

#[derive(Debug)]
pub struct VendorEvent;
#[derive(Debug)]
pub struct VendorError;
#[derive(Clone, Debug)]
pub struct VendorReturnParameters;
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum VendorStatus {
    FourFive,
    FiveZero,
}

pub struct MockVendor;
impl hci::Vendor for MockVendor {
    type Status = VendorStatus;
    type Event = VendorEvent;
}

impl std::convert::TryFrom<u8> for VendorStatus {
    type Error = hci::BadStatusError;

    fn try_from(value: u8) -> Result<VendorStatus, Self::Error> {
        match value {
            0x45 => Ok(VendorStatus::FourFive),
            0x50 => Ok(VendorStatus::FiveZero),
            _ => Err(hci::BadStatusError::BadValue(value)),
        }
    }
}

impl std::convert::Into<u8> for VendorStatus {
    fn into(self) -> u8 {
        match self {
            VendorStatus::FourFive => 0x45,
            VendorStatus::FiveZero => 0x50,
        }
    }
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
    type Error = RecordingSinkError;
    type Header = uart::CommandHeader;
    type Vendor = MockVendor;

    fn write(&mut self, header: &[u8], payload: &[u8]) -> nb::Result<(), Self::Error> {
        self.written_data.resize(header.len() + payload.len(), 0);
        {
            let (h, p) = self.written_data.split_at_mut(header.len());
            h.copy_from_slice(header);
            p.copy_from_slice(payload);
        }
        Ok(())
    }

    fn read_into(&mut self, _buffer: &mut [u8]) -> nb::Result<(), Self::Error> {
        Err(nb::Error::Other(RecordingSinkError {}))
    }

    fn peek(&mut self, _n: usize) -> nb::Result<u8, Self::Error> {
        Err(nb::Error::Other(RecordingSinkError {}))
    }
}

impl RecordingSink {
    pub fn new() -> RecordingSink {
        RecordingSink {
            written_data: Vec::new(),
        }
    }

    pub fn as_controller(&mut self) -> &mut dyn Hci<RecordingSinkError, VS = VendorStatus> {
        self as &mut dyn Hci<RecordingSinkError, VS = VendorStatus>
    }
}
