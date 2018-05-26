extern crate bluetooth_hci as hci;

use hci::event::*;
use std::time::Duration;

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

// The Command Complete event has its own set of tests in command_complete.rs

#[test]
fn command_status() {
    let buffer = [0x0F, 4, 0, 8, 0x01, 0x02];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandStatus(event)) => {
            assert_eq!(event.num_hci_command_packets, 8);
            assert_eq!(event.status, hci::Status::Success);
            assert_eq!(event.opcode, hci::Opcode(0x0201));
        }
        other => panic!("Did not get command status: {:?}", other),
    }
}

#[test]
fn hardware_error() {
    let buffer = [0x10, 1, 0x12];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::HardwareError(event)) => {
            assert_eq!(event.code, 0x12);
        }
        other => panic!("Did not get hardware error: {:?}", other),
    }
}

#[test]
fn number_of_completed_packets() {
    let buffer = [0x13, 9, 2, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::NumberOfCompletedPackets(event)) => {
            let expected_conn_handles =
                [hci::ConnectionHandle(0x0201), hci::ConnectionHandle(0x0605)];
            let expected_num_packets = [0x0403, 0x0807];
            for (actual, (conn_handle, num_packets)) in event.iter().zip(
                expected_conn_handles
                    .iter()
                    .zip(expected_num_packets.iter()),
            ) {
                assert_eq!(actual.conn_handle, *conn_handle);
                assert_eq!(actual.num_completed_packets, *num_packets);
            }
        }
        other => panic!("Did not get number of completed packets: {:?}", other),
    }
}

#[test]
fn data_buffer_overflow() {
    let buffer = [0x1A, 1, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::DataBufferOverflow(event)) => {
            assert_eq!(event.link_type, LinkType::Sco);
        }
        other => panic!("Did not get data buffer overflow: {:?}", other),
    }
}

#[test]
fn data_buffer_overflow_failed_bad_link_type() {
    let buffer = [0x1A, 1, 0x02];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadLinkType(link_type)) => assert_eq!(link_type, 0x02),
        other => panic!("Did not get bad link type: {:?}", other),
    }
}

#[test]
fn encryption_key_refresh_complete() {
    let buffer = [0x30, 3, 0, 0x01, 0x02];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::EncryptionKeyRefreshComplete(event)) => {
            assert_eq!(event.status, hci::Status::Success);
            assert_eq!(event.conn_handle, hci::ConnectionHandle(0x0201));
        }
        other => panic!("Did not get encryption key refresh complete: {:?}", other),
    }
}

#[test]
fn le_connection_complete() {
    let buffer = [
        0x3E, 19, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::LeConnectionComplete(event)) => {
            assert_eq!(event.status, hci::Status::Success);
            assert_eq!(event.conn_handle, hci::ConnectionHandle(0x0201));
            assert_eq!(event.role, ConnectionRole::Central);
            assert_eq!(
                event.peer_bdaddr,
                hci::BdAddrType::Public(hci::BdAddr([0x03, 0x04, 0x05, 0x06, 0x07, 0x08]))
            );

            // Connection interval time = value * 1.25 ms
            assert_eq!(event.conn_interval, Duration::from_millis(0x0A09 * 5 / 4));
            assert_eq!(event.conn_latency, 0x0C0B);

            // Supervision timeout = value * 10 ms
            assert_eq!(
                event.supervision_timeout,
                Duration::from_millis(0x0E0D * 10)
            );
            assert_eq!(event.central_clock_accuracy, CentralClockAccuracy::Ppm500);
        }
        other => panic!("Did not get LE connection complete: {:?}", other),
    }
}

#[test]
fn le_connection_complete_failed_bad_role() {
    let buffer = [
        0x3E, 19, 0x01, 0x00, 0x01, 0x02, 0x02, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadLeConnectionRole(code)) => assert_eq!(code, 0x02),
        other => panic!("Did not get bad LE connection role: {:?}", other),
    }
}

#[test]
fn le_connection_complete_failed_bad_address_type() {
    let buffer = [
        0x3E, 19, 0x01, 0x00, 0x01, 0x02, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadLeAddressType(code)) => assert_eq!(code, 0x02),
        other => panic!("Did not get bad address type: {:?}", other),
    }
}

#[test]
fn le_connection_complete_failed_bad_central_clock_accuracy() {
    let buffer = [
        0x3E, 19, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x08,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadLeCentralClockAccuracy(code)) => assert_eq!(code, 0x08),
        other => panic!("Did not get bad LE central clock accuracy: {:?}", other),
    }
}

#[test]
fn le_advertising_report() {
    let buffer = [
        0x3E, 27, 0x02, 2, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 2, 0x07, 0x08, 0x09, 1, 1,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 3, 0x10, 0x11, 0x12, 0x13,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::LeAdvertisingReport(event)) => {
            let mut iter = event.iter();
            let report = iter.next().unwrap();
            assert_eq!(report.event_type, AdvertisementEvent::Advertisement);
            assert_eq!(
                report.address,
                hci::BdAddrType::Public(hci::BdAddr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]))
            );
            assert_eq!(report.data, [0x07, 0x08]);
            assert_eq!(report.rssi, Some(0x09));

            let report = iter.next().unwrap();
            assert_eq!(report.event_type, AdvertisementEvent::DirectAdvertisement);
            assert_eq!(
                report.address,
                hci::BdAddrType::Random(hci::BdAddr([0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]))
            );
            assert_eq!(report.data, [0x10, 0x11, 0x12]);
            assert_eq!(report.rssi, Some(0x13));
        }
        other => panic!("Did not get advertising report: {:?}", other),
    }
}

#[test]
fn le_advertising_report_failed_incomplete() {
    let buffer = [
        0x3E, 27, 0x02, 2, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 2, 0x07, 0x08, 0x09, 1, 1,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 4, 0x10, 0x11, 0x12, 0x13,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::LeAdvertisementReportIncomplete) => (),
        other => panic!("Did not get incomplete advertising report: {:?}", other),
    }
}

#[test]
fn le_advertising_report_failed_bad_advertisement_type() {
    let buffer = [
        0x3E, 14, 0x02, 1, 5, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 2, 0x07, 0x08, 0x09,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadLeAdvertisementType(code)) => assert_eq!(code, 5),
        other => panic!("Did not get bad advertisement type: {:?}", other),
    }
}

#[test]
fn le_advertising_report_failed_bad_addr_type() {
    let buffer = [
        0x3E, 14, 0x02, 1, 1, 4, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 2, 0x07, 0x08, 0x09,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadLeAddressType(code)) => assert_eq!(code, 4),
        other => panic!("Did not get bad LE Address type: {:?}", other),
    }
}

#[test]
fn le_connection_update_complete() {
    let buffer = [
        0x3E, 10, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::LeConnectionUpdateComplete(event)) => {
            assert_eq!(event.status, hci::Status::Success);
            assert_eq!(event.conn_handle, hci::ConnectionHandle(0x0201));
            assert_eq!(event.conn_interval, Duration::from_millis(5 * 0x0403 / 4));
            assert_eq!(event.conn_latency, 0x0605);
            assert_eq!(
                event.supervision_timeout,
                Duration::from_millis(10 * 0x0807)
            );
        }
        other => panic!(
            "Did not get LE connection update complete event: {:?}",
            other
        ),
    }
}

#[cfg(feature = "version-4-1")]
#[test]
fn le_read_remote_used_features_complete() {
    let buffer = [
        0x3E, 12, 0x04, 0x00, 0x01, 0x02, 0b00010101, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::LeReadRemoteUsedFeaturesComplete(event)) => {
            assert_eq!(event.status, ::hci::Status::Success);
            assert_eq!(event.conn_handle, ::hci::ConnectionHandle(0x0201));
            assert_eq!(
                event.features,
                ::hci::LinkLayerFeature::LE_ENCRYPTION
                    | ::hci::LinkLayerFeature::EXTENDED_REJECT_INDICATION
                    | ::hci::LinkLayerFeature::LE_PING
            );
        }
        other => panic!(
            "Did not get LE Read Remote Used Features Complete: {:?}",
            other
        ),
    }
}

#[cfg(feature = "version-4-1")]
#[test]
fn le_read_remote_used_features_complete_failed_bad_flag() {
    let buffer = [
        0x3E, 12, 0x04, 0x00, 0x01, 0x02, 0b00100000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadRemoteUsedFeatureFlag(flags)) => assert_eq!(flags, 0x0000_0000_0000_0020),
        other => panic!(
            "Did not get LE Read Remote Used Features Complete: {:?}",
            other
        ),
    }
}

#[cfg(feature = "version-4-2")]
#[test]
fn le_read_remote_used_features_complete() {
    let buffer = [
        0x3E, 12, 0x04, 0x00, 0x01, 0x02, 0b00100000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::LeReadRemoteUsedFeaturesComplete(event)) => {
            assert_eq!(event.status, ::hci::Status::Success);
            assert_eq!(event.conn_handle, ::hci::ConnectionHandle(0x0201));
            assert_eq!(
                event.features,
                ::hci::LinkLayerFeature::LE_DATA_PACKET_LENGTH_EXTENSION
            );
        }
        other => panic!(
            "Did not get LE Read Remote Used Features Complete: {:?}",
            other
        ),
    }
}

#[cfg(feature = "version-4-2")]
#[test]
fn le_read_remote_used_features_complete_failed_bad_flag() {
    let buffer = [
        0x3E, 12, 0x04, 0x00, 0x01, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadRemoteUsedFeatureFlag(flags)) => assert_eq!(flags, 0x0000_0000_0000_0100),
        other => panic!(
            "Did not get LE Read Remote Used Features Complete: {:?}",
            other
        ),
    }
}

#[cfg(feature = "version-5-0")]
#[test]
fn le_read_remote_used_features_complete() {
    let buffer = [
        0x3E, 12, 0x04, 0x00, 0x01, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::LeReadRemoteUsedFeaturesComplete(event)) => {
            assert_eq!(event.status, ::hci::Status::Success);
            assert_eq!(event.conn_handle, ::hci::ConnectionHandle(0x0201));
            assert_eq!(event.features, ::hci::LinkLayerFeature::LE_2M_PHY);
        }
        other => panic!(
            "Did not get LE Read Remote Used Features Complete: {:?}",
            other
        ),
    }
}

#[cfg(feature = "version-5-0")]
#[test]
fn le_read_remote_used_features_complete_failed_bad_flag() {
    let buffer = [
        0x3E, 12, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadRemoteUsedFeatureFlag(flags)) => assert_eq!(flags, 0x0000_0000_0002_0000),
        other => panic!(
            "Did not get LE Read Remote Used Features Complete: {:?}",
            other
        ),
    }
}
