extern crate bluetooth_hci as hci;
//extern crate byteorder;

//use byteorder::{ByteOrder, LittleEndian};
use hci::event::*;

#[derive(Debug)]
struct VendorEvent;
#[derive(Debug)]
struct VendorError;

impl hci::event::VendorEvent for VendorEvent {
    type Error = VendorError;

    fn new(_buffer: &[u8]) -> Result<Self, hci::event::Error<Self::Error>> {
        Err(hci::event::Error::Vendor(VendorError))
    }
}

type TestEvent = Event<VendorEvent>;

#[test]
fn connection_complete() {
    let buffer = [
        0x03, 11, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::ConnectionComplete(event)) => {
            assert_eq!(event.status, hci::Status::Success);
            assert_eq!(event.conn_handle, hci::ConnectionHandle(0x0201));
            assert_eq!(
                event.bdaddr,
                hci::BdAddr([0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
            );
            assert_eq!(event.link_type, LinkType::Sco);
            assert_eq!(event.encryption_enabled, false);
        }
        other => panic!("Did not get connection complete event: {:?}", other),
    }
}

#[test]
fn connection_complete_failed_bad_link_type() {
    let buffer = [
        0x03, 11, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x02, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadLinkType(0x02)) => (),
        other => panic!("Did not get bad connection link type: {:?}", other),
    }
}

#[test]
fn connection_complete_failed_encryption_enabled() {
    let buffer = [
        0x03, 11, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadEncryptionEnabledValue(0x02)) => (),
        other => panic!("Did not get bad connection link type: {:?}", other),
    }
}
