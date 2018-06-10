extern crate bluetooth_hci as hci;

use hci::event::command::*;
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
fn set_event_mask() {
    let buffer = [0x0E, 4, 8, 0x01, 0x0C, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 8);
            match event.return_params {
                ReturnParameters::SetEventMask(status) => {
                    assert_eq!(status, hci::Status::Success);
                }
                other => panic!("Got return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn reset() {
    let buffer = [0x0E, 4, 8, 0x03, 0x0C, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 8);
            match event.return_params {
                ReturnParameters::Reset(status) => {
                    assert_eq!(status, hci::Status::Success);
                }
                other => panic!("Got return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn read_tx_power_level() {
    let buffer = [0x0E, 7, 6, 0x2D, 0x0C, 0x00, 0x01, 0x02, 0x03];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 6);
            match event.return_params {
                ReturnParameters::ReadTxPowerLevel(params) => {
                    assert_eq!(params.status, hci::Status::Success);
                    assert_eq!(params.conn_handle, hci::ConnectionHandle(0x0201));
                    assert_eq!(params.tx_power_level_dbm, 0x03);
                }
                other => panic!("Got return parameters: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn read_local_version_information() {
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

#[cfg(feature = "version-4-1")]
#[test]
fn read_local_supported_commands() {
    let buffer = [
        0x0E, 68, 1, 0x02, 0x10, 0x00, 0x01, 0x02, 0x04, 0x00, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02,
        0x04, 0x08, 0x10, 0x00, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01,
        0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::ReadLocalSupportedCommands(params) => {
                    assert_eq!(params.status, ::hci::Status::Success);
                    assert_eq!(
                        params.supported_commands,
                        CommandFlags::INQUIRY
                            | CommandFlags::REJECT_CONNECTION_REQUEST
                            | CommandFlags::MASTER_LINK_KEY
                            | CommandFlags::PARK_STATE
                            | CommandFlags::FLOW_SPECIFICATION
                            | CommandFlags::WRITE_STORED_LINK_KEY
                            | CommandFlags::WRITE_SCAN_ENABLE
                            | CommandFlags::READ_PAGE_SCAN_ACTIVITY
                            | CommandFlags::WRITE_CLASS_OF_DEVICE
                            | CommandFlags::READ_TRANSMIT_POWER_LEVEL
                            | CommandFlags::READ_CURRENT_IAC_LAP
                            | CommandFlags::READ_INQUIRY_SCAN_TYPE
                            | CommandFlags::READ_LOCAL_EXTENDED_FEATURES
                            | CommandFlags::READ_CLOCK
                            | CommandFlags::READ_LOOPBACK_MODE
                            | CommandFlags::WRITE_EXTENDED_INQUIRY_RESPONSE
                            | CommandFlags::READ_DEFAULT_ERRONEOUS_DATA_REPORTING
                            | CommandFlags::USER_PASSKEY_REQUEST_NEGATIVE_REPLY
                            | CommandFlags::READ_ENCRYPTION_KEY_SIZE
                            | CommandFlags::DISCONNECT_LOGICAL_LINK
                            | CommandFlags::READ_LOCAL_AMP_ASSOC
                            | CommandFlags::AMP_TEST
                            | CommandFlags::READ_ENHANCED_TRANSMIT_POWER_LEVEL
                            | CommandFlags::LE_READ_BUFFER_SIZE
                            | CommandFlags::LE_SET_SCAN_PARAMETERS
                            | CommandFlags::LE_SET_HOST_CHANNEL_CLASSIFICATION
                            | CommandFlags::LE_RECEIVER_TEST
                            | CommandFlags::READ_LOCAL_SUPPORTED_CODECS
                            | CommandFlags::TRUNCATED_PAGE
                            | CommandFlags::READ_SYNCHRONIZATION_TRAIN_PARAMETERS
                            | CommandFlags::WRITE_SYNCHRONIZATION_TRAIN_PARAMETERS
                            | CommandFlags::WRITE_EXTENDED_PAGE_TIMEOUT
                    );
                    assert!(params.supported_commands.is_set(CommandFlags::INQUIRY));
                    assert!(
                        params.supported_commands.contains(
                            CommandFlags::INQUIRY | CommandFlags::REJECT_CONNECTION_REQUEST
                        )
                    );
                }
                other => panic!(
                    "Did not get Read Supported Commands return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[cfg(feature = "version-4-1")]
#[test]
fn read_local_supported_commands_failed_bad_command_flag() {
    let buffer = [
        0x0E, 68, 1, 0x02, 0x10, 0x00, 0x01, 0x02, 0x04, 0x00, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02,
        0x04, 0x08, 0x10, 0x00, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01,
        0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadCommandFlag(octet, value)) => {
            assert_eq!(octet, 33);
            assert_eq!(value, 0x42);
        }
        other => panic!("Did not get Bad Command Flag: {:?}", other),
    }
}

#[cfg(feature = "version-4-2")]
#[test]
fn read_local_supported_commands() {
    let buffer = [
        0x0E, 68, 1, 0x02, 0x10, 0x00, 0x01, 0x02, 0x04, 0x00, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02,
        0x04, 0x08, 0x10, 0x00, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01,
        0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::ReadLocalSupportedCommands(params) => {
                    assert_eq!(params.status, ::hci::Status::Success);
                    assert_eq!(
                        params.supported_commands,
                        CommandFlags::INQUIRY
                            | CommandFlags::REJECT_CONNECTION_REQUEST
                            | CommandFlags::MASTER_LINK_KEY
                            | CommandFlags::PARK_STATE
                            | CommandFlags::FLOW_SPECIFICATION
                            | CommandFlags::WRITE_STORED_LINK_KEY
                            | CommandFlags::WRITE_SCAN_ENABLE
                            | CommandFlags::READ_PAGE_SCAN_ACTIVITY
                            | CommandFlags::WRITE_CLASS_OF_DEVICE
                            | CommandFlags::READ_TRANSMIT_POWER_LEVEL
                            | CommandFlags::READ_CURRENT_IAC_LAP
                            | CommandFlags::READ_INQUIRY_SCAN_TYPE
                            | CommandFlags::READ_LOCAL_EXTENDED_FEATURES
                            | CommandFlags::READ_CLOCK
                            | CommandFlags::READ_LOOPBACK_MODE
                            | CommandFlags::WRITE_EXTENDED_INQUIRY_RESPONSE
                            | CommandFlags::READ_DEFAULT_ERRONEOUS_DATA_REPORTING
                            | CommandFlags::USER_PASSKEY_REQUEST_NEGATIVE_REPLY
                            | CommandFlags::READ_ENCRYPTION_KEY_SIZE
                            | CommandFlags::DISCONNECT_LOGICAL_LINK
                            | CommandFlags::READ_LOCAL_AMP_ASSOC
                            | CommandFlags::AMP_TEST
                            | CommandFlags::READ_ENHANCED_TRANSMIT_POWER_LEVEL
                            | CommandFlags::LE_READ_BUFFER_SIZE
                            | CommandFlags::LE_SET_SCAN_PARAMETERS
                            | CommandFlags::LE_SET_HOST_CHANNEL_CLASSIFICATION
                            | CommandFlags::LE_RECEIVER_TEST
                            | CommandFlags::READ_LOCAL_SUPPORTED_CODECS
                            | CommandFlags::TRUNCATED_PAGE
                            | CommandFlags::READ_SYNCHRONIZATION_TRAIN_PARAMETERS
                            | CommandFlags::WRITE_SYNCHRONIZATION_TRAIN_PARAMETERS
                            | CommandFlags::WRITE_EXTENDED_PAGE_TIMEOUT
                            | CommandFlags::LE_GENERATE_DH_KEY
                            | CommandFlags::LE_READ_MAXIMUM_DATA_LENGTH
                    );
                    assert!(params.supported_commands.is_set(CommandFlags::INQUIRY));
                    assert!(
                        params.supported_commands.contains(
                            CommandFlags::INQUIRY | CommandFlags::REJECT_CONNECTION_REQUEST
                        )
                    );
                }
                other => panic!(
                    "Did not get Read Supported Commands return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[cfg(feature = "version-4-2")]
#[test]
fn read_local_supported_commands_failed_bad_command_flag() {
    let buffer = [
        0x0E, 68, 1, 0x02, 0x10, 0x00, 0x01, 0x02, 0x04, 0x00, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02,
        0x04, 0x08, 0x10, 0x00, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01,
        0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadCommandFlag(octet, value)) => {
            assert_eq!(octet, 35);
            assert_eq!(value, 0x10);
        }
        other => panic!("Did not get Bad Command Flag: {:?}", other),
    }
}

#[cfg(feature = "version-5-0")]
#[test]
fn read_local_supported_commands() {
    let buffer = [
        0x0E, 68, 1, 0x02, 0x10, 0x00, 0x01, 0x02, 0x04, 0x00, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02,
        0x04, 0x08, 0x10, 0x00, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01,
        0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::ReadLocalSupportedCommands(params) => {
                    assert_eq!(params.status, ::hci::Status::Success);
                    assert_eq!(
                        params.supported_commands,
                        CommandFlags::INQUIRY
                            | CommandFlags::REJECT_CONNECTION_REQUEST
                            | CommandFlags::MASTER_LINK_KEY
                            | CommandFlags::PARK_STATE
                            | CommandFlags::FLOW_SPECIFICATION
                            | CommandFlags::WRITE_STORED_LINK_KEY
                            | CommandFlags::WRITE_SCAN_ENABLE
                            | CommandFlags::READ_PAGE_SCAN_ACTIVITY
                            | CommandFlags::WRITE_CLASS_OF_DEVICE
                            | CommandFlags::READ_TRANSMIT_POWER_LEVEL
                            | CommandFlags::READ_CURRENT_IAC_LAP
                            | CommandFlags::READ_INQUIRY_SCAN_TYPE
                            | CommandFlags::READ_LOCAL_EXTENDED_FEATURES
                            | CommandFlags::READ_CLOCK
                            | CommandFlags::READ_LOOPBACK_MODE
                            | CommandFlags::WRITE_EXTENDED_INQUIRY_RESPONSE
                            | CommandFlags::READ_DEFAULT_ERRONEOUS_DATA_REPORTING
                            | CommandFlags::USER_PASSKEY_REQUEST_NEGATIVE_REPLY
                            | CommandFlags::READ_ENCRYPTION_KEY_SIZE
                            | CommandFlags::DISCONNECT_LOGICAL_LINK
                            | CommandFlags::READ_LOCAL_AMP_ASSOC
                            | CommandFlags::AMP_TEST
                            | CommandFlags::READ_ENHANCED_TRANSMIT_POWER_LEVEL
                            | CommandFlags::LE_READ_BUFFER_SIZE
                            | CommandFlags::LE_SET_SCAN_PARAMETERS
                            | CommandFlags::LE_SET_HOST_CHANNEL_CLASSIFICATION
                            | CommandFlags::LE_RECEIVER_TEST
                            | CommandFlags::READ_LOCAL_SUPPORTED_CODECS
                            | CommandFlags::TRUNCATED_PAGE
                            | CommandFlags::READ_SYNCHRONIZATION_TRAIN_PARAMETERS
                            | CommandFlags::WRITE_SYNCHRONIZATION_TRAIN_PARAMETERS
                            | CommandFlags::WRITE_EXTENDED_PAGE_TIMEOUT
                            | CommandFlags::LE_GENERATE_DH_KEY
                            | CommandFlags::LE_READ_MAXIMUM_DATA_LENGTH
                            | CommandFlags::LE_SET_EXTENDED_SCAN_RESPONSE_DATA_COMMAND
                            | CommandFlags::LE_SET_EXTENDED_SCAN_PARAMETERS_COMMAND
                            | CommandFlags::LE_READ_PERIODIC_ADVERTISER_LIST_SIZE_COMMAND
                    );
                    assert!(params.supported_commands.is_set(CommandFlags::INQUIRY));
                    assert!(
                        params.supported_commands.contains(
                            CommandFlags::INQUIRY | CommandFlags::REJECT_CONNECTION_REQUEST
                        )
                    );
                }
                other => panic!(
                    "Did not get Read Supported Commands return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[cfg(feature = "version-5-0")]
#[test]
fn read_local_supported_commands_failed_bad_command_flag() {
    let buffer = [
        0x0E, 68, 1, 0x02, 0x10, 0x00, 0x01, 0x02, 0x04, 0x00, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02,
        0x04, 0x08, 0x10, 0x00, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01,
        0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Err(Error::BadCommandFlag(octet, value)) => {
            assert_eq!(octet, 39);
            assert_eq!(value, 0x80);
        }
        other => panic!("Did not get Bad Command Flag: {:?}", other),
    }
}

#[test]
fn read_local_supported_features() {
    let buffer = [
        0x0E, 12, 1, 0x03, 0x10, 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::ReadLocalSupportedFeatures(params) => {
                    assert_eq!(params.status, ::hci::Status::Success);
                    assert_eq!(
                        params.supported_features,
                        LmpFeatures::THREE_SLOT_PACKETS
                            | LmpFeatures::POWER_CONTROL_REQUESTS
                            | LmpFeatures::POWER_CONTROL
                            | LmpFeatures::ENHANCED_INQUIRY_SCAN
                            | LmpFeatures::AFH_CLASSIFICATION_PERIPHERAL
                            | LmpFeatures::ENHANCED_DATA_RATE_ESCO_2_MB_PER_S_MODE
                            | LmpFeatures::NON_FLUSHABLE_PACKET_BOUNDARY_FLAG
                            | LmpFeatures::EXTENDED_FEATURES
                    );
                }
                other => panic!(
                    "Did not get Read Supported Features return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn read_bd_addr() {
    let buffer = [
        0x0E, 10, 1, 0x09, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::ReadBdAddr(params) => {
                    assert_eq!(params.status, ::hci::Status::Success);
                    assert_eq!(
                        params.bd_addr,
                        ::hci::BdAddr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
                    );
                }
                other => panic!("Did not get Read BDADDR return params: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn read_rssi() {
    let buffer = [0x0E, 7, 1, 0x05, 0x14, 0x00, 0x01, 0x02, 0x03];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::ReadRssi(params) => {
                    assert_eq!(params.status, ::hci::Status::Success);
                    assert_eq!(params.conn_handle, ::hci::ConnectionHandle(0x0201));
                    assert_eq!(params.rssi, 0x03);
                }
                other => panic!("Did not get Read RSSI return params: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn le_set_event_mask() {
    let buffer = [0x0E, 4, 2, 0x01, 0x20, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 2);
            match event.return_params {
                ReturnParameters::LeSetEventMask(status) => {
                    assert_eq!(status, ::hci::Status::Success)
                }
                other => panic!("Did not get LE Set Event Mask return params: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn le_read_buffer_size() {
    let buffer = [0x0E, 7, 2, 0x02, 0x20, 0x00, 0x01, 0x02, 0x03];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 2);
            match event.return_params {
                ReturnParameters::LeReadBufferSize(event) => {
                    assert_eq!(event.status, ::hci::Status::Success);
                    assert_eq!(event.data_packet_length, 0x0201);
                    assert_eq!(event.data_packet_count, 0x03);
                }
                other => panic!("Did not get LE Read Buffer Size return params: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[cfg(feature = "version-4-1")]
#[test]
fn le_read_local_supported_features() {
    let buffer = [
        0x0E, 12, 1, 0x03, 0x20, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeReadLocalSupportedFeatures(event) => {
                    assert_eq!(event.status, ::hci::Status::Success);
                    assert_eq!(
                        event.supported_features,
                        LeFeatures::ENCRYPTION | LeFeatures::PING
                    );
                }
                other => panic!("Did not get LE Read Buffer Size return params: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[cfg(feature = "version-4-2")]
#[test]
fn le_read_local_supported_features() {
    let buffer = [
        0x0E, 12, 1, 0x03, 0x20, 0x00, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeReadLocalSupportedFeatures(event) => {
                    assert_eq!(event.status, ::hci::Status::Success);
                    assert_eq!(
                        event.supported_features,
                        LeFeatures::ENCRYPTION | LeFeatures::EXTENDED_SCANNER_FILTER_POLICIES
                    );
                }
                other => panic!("Did not get LE Read Buffer Size return params: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[cfg(feature = "version-5-0")]
#[test]
fn le_read_local_supported_features() {
    let buffer = [
        0x0E, 12, 1, 0x03, 0x20, 0x00, 0x04, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeReadLocalSupportedFeatures(event) => {
                    assert_eq!(event.status, ::hci::Status::Success);
                    assert_eq!(
                        event.supported_features,
                        LeFeatures::EXTENDED_REJECT_INDICATION
                            | LeFeatures::STABLE_MODULATION_INDEX_TX
                            | LeFeatures::MINIMUM_NUMBER_OF_USED_CHANNELS_PROCEDURE
                    );
                }
                other => panic!("Did not get LE Read Buffer Size return params: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn le_set_random_address() {
    let buffer = [0x0E, 4, 1, 0x05, 0x20, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeSetRandomAddress(status) => {
                    assert_eq!(status, ::hci::Status::Success);
                }
                other => panic!(
                    "Did not get LE Set Random Address return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn le_set_advertising_parameters() {
    let buffer = [0x0E, 4, 1, 0x06, 0x20, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeSetAdvertisingParameters(status) => {
                    assert_eq!(status, ::hci::Status::Success);
                }
                other => panic!(
                    "Did not get LE Set Advertising Parameters return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn le_read_advertising_channel_tx_power() {
    let buffer = [0x0E, 5, 1, 0x07, 0x20, 0x00, 0x01];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeReadAdvertisingChannelTxPower(params) => {
                    assert_eq!(params.status, ::hci::Status::Success);
                    assert_eq!(params.power, 0x01);
                }
                other => panic!(
                    "Did not get LE Read Advertising Channel TX Power return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn le_set_advertising_data() {
    let buffer = [0x0E, 4, 1, 0x08, 0x20, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeSetAdvertisingData(status) => {
                    assert_eq!(status, ::hci::Status::Success);
                }
                other => panic!(
                    "Did not get LE Set Advertising Data return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn le_set_scan_response_data() {
    let buffer = [0x0E, 4, 1, 0x09, 0x20, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeSetScanResponseData(status) => {
                    assert_eq!(status, ::hci::Status::Success);
                }
                other => panic!(
                    "Did not get LE Set Scan Response Data return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[cfg(any(feature = "version-4-1", feature = "version-4-2"))]
#[test]
fn le_set_advertise_enable() {
    let buffer = [0x0E, 4, 1, 0x0A, 0x20, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeSetAdvertiseEnable(status) => {
                    assert_eq!(status, ::hci::Status::Success);
                }
                other => panic!(
                    "Did not get LE Set Advertise Enable return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[cfg(feature = "version-5-0")]
#[test]
fn le_set_advertising_enable() {
    let buffer = [0x0E, 4, 1, 0x0A, 0x20, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeSetAdvertisingEnable(status) => {
                    assert_eq!(status, ::hci::Status::Success);
                }
                other => panic!(
                    "Did not get LE Set Advertising Enable return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn le_set_scan_parameters() {
    let buffer = [0x0E, 4, 1, 0x0B, 0x20, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeSetScanParameters(status) => {
                    assert_eq!(status, ::hci::Status::Success);
                }
                other => panic!(
                    "Did not get LE Set Scan Parameters return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn le_set_scan_enable() {
    let buffer = [0x0E, 4, 1, 0x0C, 0x20, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeSetScanEnable(status) => {
                    assert_eq!(status, ::hci::Status::Success);
                }
                other => panic!(
                    "Did not get LE Set Scan Parameters return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn le_create_connection_cancel() {
    let buffer = [0x0E, 4, 1, 0x0E, 0x20, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeCreateConnectionCancel(status) => {
                    assert_eq!(status, ::hci::Status::Success);
                }
                other => panic!(
                    "Did not get LE Set Scan Parameters return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn le_read_white_list_size() {
    let buffer = [0x0E, 5, 1, 0x0F, 0x20, 0x00, 0x16];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeReadWhiteListSize(status, white_list_size) => {
                    assert_eq!(status, ::hci::Status::Success);
                    assert_eq!(white_list_size, 0x16);
                }
                other => panic!(
                    "Did not get LE Read White List Size return params: {:?}",
                    other
                ),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}

#[test]
fn le_clear_white_list() {
    let buffer = [0x0E, 4, 1, 0x10, 0x20, 0x00];
    match TestEvent::new(Packet(&buffer)) {
        Ok(Event::CommandComplete(event)) => {
            assert_eq!(event.num_hci_command_packets, 1);
            match event.return_params {
                ReturnParameters::LeClearWhiteList(status) => {
                    assert_eq!(status, ::hci::Status::Success);
                }
                other => panic!("Did not get LE Clear White List return params: {:?}", other),
            }
        }
        other => panic!("Did not get command complete event: {:?}", other),
    }
}
