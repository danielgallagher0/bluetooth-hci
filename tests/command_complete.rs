extern crate bluetooth_hci as hci;

use hci::event::command::ReturnParameters;
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
fn command_complete_failed() {
    let buffer = [0x0E, 3, 1, 0x67, 0x43];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::UnknownOpcode(opcode)) => assert_eq!(opcode.0, 0x4367),
        other => panic!("Did not get unknown opcode: {:?}", other),
    }
}

#[test]
fn unsolicited_command_complete() {
    let buffer = [0x0E, 3, 1, 0x00, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::Spontaneous => (),
                other => panic!("Got return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn read_local_version_complete() {
    let buffer = [
        0x0E, 12, 0x01, 0x01, 0x10, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::ReadLocalVersionInformation(local_version_info) => {
                    assert_eq!(local_version_info.status, ::hci::Status::Success);
                    assert_eq!(local_version_info.hci_version, 2);
                    assert_eq!(local_version_info.hci_revision, 0x0403);
                    assert_eq!(local_version_info.lmp_version, 5);
                    assert_eq!(local_version_info.manufacturer_name, 0x0706);
                    assert_eq!(local_version_info.lmp_subversion, 0x0908);
                }
                other => panic!(
                    "Did not get Read Local Version Info return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}
