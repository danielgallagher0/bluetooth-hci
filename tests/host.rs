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
