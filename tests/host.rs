extern crate bluetooth_hci as hci;
extern crate nb;

use hci::host::*;

struct RecordingSink {
    written_data: Vec<u8>,
}

#[derive(Debug, PartialEq)]
struct RecordingSinkError;

impl hci::Controller for RecordingSink {
    type Error = RecordingSinkError;

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
    fn new() -> RecordingSink {
        RecordingSink {
            written_data: Vec::new(),
        }
    }

    fn as_controller(&mut self) -> &mut Hci<RecordingSinkError, uart::CommandHeader> {
        self as &mut Hci<RecordingSinkError, uart::CommandHeader>
    }
}

#[test]
fn disconnect() {
    let mut sink = RecordingSink::new();
    sink.as_controller()
        .disconnect(hci::ConnectionHandle(0x0201), hci::Status::AuthFailure)
        .unwrap();
    assert_eq!(sink.written_data, [1, 0x06, 0x04, 3, 0x01, 0x02, 0x05]);
}

#[test]
fn disconnect_bad_reason() {
    let mut sink = RecordingSink::new();
    let err = sink
        .as_controller()
        .disconnect(hci::ConnectionHandle(0x0201), hci::Status::UnknownCommand)
        .err()
        .unwrap();
    assert_eq!(
        err,
        nb::Error::Other(Error::BadDisconnectionReason(hci::Status::UnknownCommand))
    );
    assert_eq!(sink.written_data, []);
}

#[test]
fn read_remote_version_information() {
    let mut sink = RecordingSink::new();
    sink.as_controller()
        .read_remote_version_information(hci::ConnectionHandle(0x0201))
        .unwrap();
    assert_eq!(sink.written_data, [1, 0x1D, 0x04, 2, 0x01, 0x02]);
}

#[test]
fn set_event_mask() {
    let mut sink = RecordingSink::new();
    sink.as_controller()
        .set_event_mask(EventFlags::INQUIRY_COMPLETE | EventFlags::AUTHENTICATION_COMPLETE)
        .unwrap();
    assert_eq!(
        sink.written_data,
        [1, 0x01, 0x0C, 8, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
}

#[test]
fn reset() {
    let mut sink = RecordingSink::new();
    sink.as_controller().reset().unwrap();
    assert_eq!(sink.written_data, [1, 0x03, 0x0C, 0]);
}

#[test]
fn read_tx_power_level() {
    let mut sink = RecordingSink::new();
    sink.as_controller()
        .read_tx_power_level(hci::ConnectionHandle(0x0201), TxPowerLevel::Current)
        .unwrap();
    assert_eq!(sink.written_data, [1, 0x2D, 0x0C, 3, 0x01, 0x02, 0x00])
}

#[test]
fn read_local_version_information() {
    let mut sink = RecordingSink::new();
    sink.as_controller()
        .read_local_version_information()
        .unwrap();
    assert_eq!(sink.written_data, [1, 0x01, 0x10, 0])
}

#[test]
fn read_local_supported_commands() {
    let mut sink = RecordingSink::new();
    sink.as_controller()
        .read_local_supported_commands()
        .unwrap();
    assert_eq!(sink.written_data, [1, 0x02, 0x10, 0]);
}

#[test]
fn read_local_supported_features() {
    let mut sink = RecordingSink::new();
    sink.as_controller()
        .read_local_supported_features()
        .unwrap();
    assert_eq!(sink.written_data, [1, 0x03, 0x10, 0]);
}

#[test]
fn read_bd_addr() {
    let mut sink = RecordingSink::new();
    sink.as_controller().read_bd_addr().unwrap();
    assert_eq!(sink.written_data, [1, 0x09, 0x10, 0]);
}

#[test]
fn read_rssi() {
    let mut sink = RecordingSink::new();
    sink.as_controller()
        .read_rssi(hci::ConnectionHandle(0x0201))
        .unwrap();
    assert_eq!(sink.written_data, [1, 0x05, 0x14, 2, 0x01, 0x02]);
}

#[test]
fn le_set_event_mask() {
    let mut sink = RecordingSink::new();
    sink.as_controller()
        .le_set_event_mask(
            LeEventFlags::CONNECTION_COMPLETE | LeEventFlags::REMOTE_CONNECTION_PARAMETER_REQUEST,
        )
        .unwrap();
    assert_eq!(
        sink.written_data,
        [1, 0x01, 0x20, 8, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
}

#[test]
fn le_read_buffer_size() {
    let mut sink = RecordingSink::new();
    sink.as_controller().le_read_buffer_size().unwrap();
    assert_eq!(sink.written_data, [1, 0x02, 0x20, 0]);
}

#[test]
fn le_read_local_supported_features() {
    let mut sink = RecordingSink::new();
    sink.as_controller()
        .le_read_local_supported_features()
        .unwrap();
    assert_eq!(sink.written_data, [1, 0x03, 0x20, 0]);
}

#[test]
fn le_set_random_address() {
    let mut sink = RecordingSink::new();
    sink.as_controller()
        .le_set_random_address(hci::BdAddr([0x01, 0x02, 0x04, 0x08, 0x10, 0x20]))
        .unwrap();
    assert_eq!(
        sink.written_data,
        [1, 0x05, 0x20, 6, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20]
    );
}

#[test]
fn le_set_random_address_invalid_addr_type() {
    let mut sink = RecordingSink::new();
    for bd_addr in [
        // The most significant bits of the BD ADDR must be either 11 (static address) or 00
        // (non-resolvable private address), or 10 (resolvable private address).  An MSB of 01 is
        // not valid.
        hci::BdAddr([0x01, 0x02, 0x04, 0x08, 0x10, 0b01000000]),
        // The random part of a static address must contain at least one 0.
        hci::BdAddr([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        // The random part of a static address must contain at least one 1.
        hci::BdAddr([0x00, 0x00, 0x00, 0x00, 0x00, 0b11000000]),
        // The random part of a non-resolvable private address must contain at least one 0.
        hci::BdAddr([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0b00111111]),
        // The random part of a non-resolvable private address must contain at least one 1.
        hci::BdAddr([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        // The random part of a resolvable private address must contain at least one 0.  The first 3
        // bytes are a hash, which can have any value.
        hci::BdAddr([0x01, 0x02, 0x04, 0xFF, 0xFF, 0b10111111]),
        // The random part of a resolvable private address must contain at least one 1.  The first 3
        // bytes are a hash, which can have any value.
        hci::BdAddr([0x01, 0x02, 0x04, 0x00, 0x00, 0b10000000]),
    ].iter()
    {
        let err = sink
            .as_controller()
            .le_set_random_address(*bd_addr)
            .err()
            .unwrap();
        assert_eq!(err, nb::Error::Other(Error::BadRandomAddress(*bd_addr)));
    }
    assert_eq!(sink.written_data, []);
}
