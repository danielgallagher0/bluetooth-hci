extern crate bluetooth_hci as hci;

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
fn connection_complete_failed_bad_status() {
    let buffer = [
        0x03, 11, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadStatus(0x80)) => (),
        other => panic!("Did not get bad status: {:?}", other),
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

#[test]
fn disconnection_complete() {
    let buffer = [0x05, 4, 0, 0x01, 0x02, 0];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::DisconnectionComplete(event)) => {
            assert_eq!(event.status, hci::Status::Success);
            assert_eq!(event.conn_handle, hci::ConnectionHandle(0x0201));
            assert_eq!(event.reason, hci::Status::Success);
        }
        other => panic!("Did not get disconnection complete event: {:?}", other),
    }
}

#[test]
fn disconnection_complete_failed_bad_status() {
    let buffer = [0x05, 4, 0x80, 0x01, 0x02, 0];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadStatus(0x80)) => (),
        other => panic!("Did not get bad status: {:?}", other),
    }
}

#[test]
fn disconnection_complete_failed_bad_reason() {
    let buffer = [0x05, 4, 0, 0x01, 0x02, 0x80];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadReason(0x80)) => (),
        other => panic!("Did not get bad reason: {:?}", other),
    }
}

#[test]
fn encryption_change() {
    let buffer = [0x08, 4, 0x00, 0x01, 0x02, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::EncryptionChange(event)) => {
            assert_eq!(event.status, hci::Status::Success);
            assert_eq!(event.conn_handle, hci::ConnectionHandle(0x0201));
            assert_eq!(event.encryption, Encryption::Off);
        }
        other => panic!("Did not get encryption change event: {:?}", other),
    }
}

#[test]
fn encryption_change_failed_bad_status() {
    let buffer = [0x08, 4, 0x80, 0x01, 0x02, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadStatus(0x80)) => (),
        other => panic!("Did not get bad status: {:?}", other),
    }
}

#[test]
fn encryption_change_failed_bad_encryption() {
    let buffer = [0x08, 4, 0x00, 0x01, 0x02, 0x03];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadEncryptionType(0x03)) => (),
        other => panic!("Did not get bad encryption type: {:?}", other),
    }
}

#[test]
fn read_remote_version_complete() {
    let buffer = [0x0C, 8, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::ReadRemoteVersionInformationComplete(event)) => {
            assert_eq!(event.status, hci::Status::Success);
            assert_eq!(event.conn_handle, hci::ConnectionHandle(0x0201));
            assert_eq!(event.version, 0x03);
            assert_eq!(event.mfgr_name, 0x0504);
            assert_eq!(event.subversion, 0x0706);
        }
        other => panic!("Did not get read remote version info event: {:?}", other),
    }
}

#[test]
fn read_remote_version_complete_failed_bad_status() {
    let buffer = [0x0C, 8, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadStatus(0x80)) => (),
        other => panic!("Did not get bad status: {:?}", other),
    }
}
