#![feature(async_fn_in_trait)]

extern crate bluetooth_hci as hci;

mod vendor;

use hci::host::*;
use std::time::Duration;
use vendor::RecordingSink;

#[tokio::test]
async fn disconnect() {
    let mut sink = RecordingSink::new();
    sink.disconnect(hci::ConnectionHandle(0x0201), hci::Status::AuthFailure)
        .await
        .unwrap();
    assert_eq!(sink.written_data, [1, 0x06, 0x04, 3, 0x01, 0x02, 0x05]);
}

#[tokio::test]
async fn disconnect_bad_reason() {
    let mut sink = RecordingSink::new();
    let err = sink
        .disconnect(hci::ConnectionHandle(0x0201), hci::Status::UnknownCommand)
        .await
        .err()
        .unwrap();
    assert_eq!(
        err,
        Error::BadDisconnectionReason(hci::Status::UnknownCommand)
    );
    assert_eq!(sink.written_data, []);
}

macro_rules! conn_handle_only {
    {
        $($(#[$inner:ident $($args:tt)*])*
        $fn:ident($oc0:expr, $oc1:expr);)*
    } => {
        $(
            $(#[$inner $($args)*])*
            #[tokio::test]
            async fn $fn() {
                let mut sink = RecordingSink::new();
                sink
                    .$fn(hci::ConnectionHandle(0x0201))
                    .await
                    .unwrap();
                assert_eq!(sink.written_data, [1, $oc0, $oc1, 2, 0x01, 0x02]);
            }
        )*
    }
}

conn_handle_only! {
    read_remote_version_information(0x1D, 0x04);
    read_rssi(0x05, 0x14);
    le_read_channel_map(0x15, 0x20);
    le_read_remote_used_features(0x16, 0x20);
    le_long_term_key_request_negative_reply(0x1B, 0x20);
}

macro_rules! no_params {
    {
        $($(#[$inner:ident $($args:tt)*])*
        $fn:ident($oc0:expr, $oc1:expr);)*
    } => {
        $(
            $(#[$inner $($args)*])*
            #[tokio::test]
            async fn $fn() {
                let mut sink = RecordingSink::new();
                sink
                    .$fn()
                    .await
                    .unwrap();
                assert_eq!(sink.written_data, [1, $oc0, $oc1, 0]);
            }
        )*
    }
}

no_params! {
    reset(0x03, 0x0C);
    read_local_version_information(0x01, 0x10);
    read_local_supported_commands(0x02, 0x10);
    read_local_supported_features(0x03, 0x10);
    read_bd_addr(0x09, 0x10);
    le_read_buffer_size(0x02, 0x20);
    le_read_local_supported_features(0x03, 0x20);
    le_read_advertising_channel_tx_power(0x07, 0x20);
    le_create_connection_cancel(0x0E, 0x20);
    le_read_white_list_size(0x0F, 0x20);
    le_clear_white_list(0x10, 0x20);
    le_rand(0x18, 0x20);
    le_read_supported_states(0x1C, 0x20);
    le_test_end(0x1F, 0x20);
}

#[tokio::test]
async fn set_event_mask() {
    let mut sink = RecordingSink::new();
    sink.set_event_mask(EventFlags::INQUIRY_COMPLETE | EventFlags::AUTHENTICATION_COMPLETE)
        .await
        .unwrap();
    assert_eq!(
        sink.written_data,
        [1, 0x01, 0x0C, 8, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
}

#[tokio::test]
async fn read_tx_power_level() {
    let mut sink = RecordingSink::new();
    sink.read_tx_power_level(hci::ConnectionHandle(0x0201), TxPowerLevel::Current)
        .await
        .unwrap();
    assert_eq!(sink.written_data, [1, 0x2D, 0x0C, 3, 0x01, 0x02, 0x00])
}

#[tokio::test]
async fn le_set_event_mask() {
    let mut sink = RecordingSink::new();
    sink.le_set_event_mask(
        LeEventFlags::CONNECTION_COMPLETE | LeEventFlags::REMOTE_CONNECTION_PARAMETER_REQUEST,
    )
    .await
    .unwrap();
    assert_eq!(
        sink.written_data,
        [1, 0x01, 0x20, 8, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
}

#[tokio::test]
async fn le_set_random_address() {
    let mut sink = RecordingSink::new();
    sink.le_set_random_address(hci::BdAddr([0x01, 0x02, 0x04, 0x08, 0x10, 0x20]))
        .await
        .unwrap();
    assert_eq!(
        sink.written_data,
        [1, 0x05, 0x20, 6, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20]
    );
}

#[tokio::test]
async fn le_set_random_address_invalid_addr_type() {
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
    ]
    .iter()
    {
        let err = sink.le_set_random_address(*bd_addr).await.err().unwrap();
        assert_eq!(err, Error::BadRandomAddress(*bd_addr));
    }
    assert_eq!(sink.written_data, []);
}

#[tokio::test]
async fn le_set_advertising_parameters() {
    let mut sink = RecordingSink::new();
    sink.le_set_advertising_parameters(&AdvertisingParameters {
        advertising_interval: AdvertisingInterval::for_type(AdvertisingType::ConnectableUndirected)
            .with_range(Duration::from_millis(21), Duration::from_millis(1000))
            .unwrap(),
        own_address_type: OwnAddressType::Public,
        peer_address: hci::BdAddrType::Random(hci::BdAddr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])),
        advertising_channel_map: Channels::CH_37 | Channels::CH_39,
        advertising_filter_policy: AdvertisingFilterPolicy::AllowConnectionAndScan,
    })
    .await
    .unwrap();
    assert_eq!(
        sink.written_data,
        [
            1,
            0x06,
            0x20,
            15,
            0x21, // 0x21, 0x00 = 0x0021 = 33 ~= 21 ms / 0.625 ms
            0x00,
            0x40, // 0x40, 0x06 = 0x0640 = 1600 = 1000 ms / 0.625 ms
            0x06,
            0x00,
            0x00,
            0x01,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0b0000_0101,
            0x00
        ]
    );
}

#[tokio::test]
async fn le_set_advertising_parameters_bad_channel_map() {
    let mut sink = RecordingSink::new();
    let err = sink
        .le_set_advertising_parameters(&AdvertisingParameters {
            advertising_interval: AdvertisingInterval::for_type(
                AdvertisingType::ConnectableUndirected,
            )
            .with_range(Duration::from_millis(20), Duration::from_millis(1000))
            .unwrap(),
            own_address_type: OwnAddressType::Public,
            peer_address: hci::BdAddrType::Random(hci::BdAddr([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            ])),
            advertising_channel_map: Channels::empty(),
            advertising_filter_policy: AdvertisingFilterPolicy::AllowConnectionAndScan,
        })
        .await
        .err()
        .unwrap();
    assert_eq!(err, Error::BadChannelMap(Channels::empty()));
    assert_eq!(sink.written_data, []);
}

#[tokio::test]
async fn le_set_advertising_data_empty() {
    let mut sink = RecordingSink::new();
    sink.le_set_advertising_data(&[]).await.unwrap();
    assert_eq!(
        sink.written_data,
        vec![
            1, 0x08, 0x20, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    );
}

#[tokio::test]
async fn le_set_advertising_data_partial() {
    let mut sink = RecordingSink::new();
    sink.le_set_advertising_data(&[1, 2, 3, 4, 5, 6, 7, 8])
        .await
        .unwrap();
    assert_eq!(
        sink.written_data,
        vec![
            1, 0x08, 0x20, 32, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    );
}

#[tokio::test]
async fn le_set_advertising_data_full() {
    let mut sink = RecordingSink::new();
    sink.le_set_advertising_data(&[
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31,
    ])
    .await
    .unwrap();
    assert_eq!(
        sink.written_data,
        vec![
            1, 0x08, 0x20, 32, 31, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ]
    );
}

#[tokio::test]
async fn le_set_advertising_data_too_long() {
    let mut sink = RecordingSink::new();
    let err = sink.le_set_advertising_data(&[0; 32]).await.err().unwrap();
    assert_eq!(err, Error::AdvertisingDataTooLong(32));
}

#[tokio::test]
async fn le_set_scan_response_data_empty() {
    let mut sink = RecordingSink::new();
    sink.le_set_scan_response_data(&[]).await.unwrap();
    assert_eq!(
        sink.written_data,
        vec![
            1, 0x09, 0x20, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    );
}

#[tokio::test]
async fn le_set_scan_response_data_partial() {
    let mut sink = RecordingSink::new();
    sink.le_set_scan_response_data(&[1, 2, 3, 4, 5, 6, 7, 8])
        .await
        .unwrap();
    assert_eq!(
        sink.written_data,
        vec![
            1, 0x09, 0x20, 32, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    );
}

#[tokio::test]
async fn le_set_scan_response_data_full() {
    let mut sink = RecordingSink::new();
    sink.le_set_scan_response_data(&[
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31,
    ])
    .await
    .unwrap();
    assert_eq!(
        sink.written_data,
        vec![
            1, 0x09, 0x20, 32, 31, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ]
    );
}

#[tokio::test]
async fn le_set_scan_response_data_too_long() {
    let mut sink = RecordingSink::new();
    let err = sink
        .le_set_scan_response_data(&[0; 32])
        .await
        .err()
        .unwrap();
    assert_eq!(err, Error::AdvertisingDataTooLong(32));
}

#[cfg(not(feature = "version-5-0"))]
#[tokio::test]
async fn le_set_advertise_enable() {
    let mut sink = RecordingSink::new();
    sink.le_set_advertise_enable(true).await.unwrap();
    assert_eq!(sink.written_data, [1, 0x0A, 0x20, 1, 1]);
}

#[cfg(feature = "version-5-0")]
#[tokio::test]
async fn le_set_advertising_enable() {
    let mut sink = RecordingSink::new();
    sink.le_set_advertising_enable(true).unwrap();
    assert_eq!(sink.written_data, [1, 0x0A, 0x20, 1, 1]);
}

#[tokio::test]
async fn le_set_scan_parameters() {
    let mut sink = RecordingSink::new();
    sink.le_set_scan_parameters(&ScanParameters {
        scan_type: ScanType::Passive,
        scan_window: ScanWindow::start_every(Duration::from_millis(21))
            .and_then(|b| b.open_for(Duration::from_millis(10)))
            .unwrap(),
        own_address_type: OwnAddressType::Public,
        filter_policy: ScanFilterPolicy::AcceptAll,
    })
    .await
    .unwrap();

    // bytes 5-6: 0x21, 0x00 = 0x0021 = 33 ~= 21 ms / 0.625 ms
    // bytes 7-8: 0x10, 0x00 = 0x0010 = 16 = 10 ms / 0.625 ms
    assert_eq!(
        sink.written_data,
        [1, 0x0B, 0x20, 7, 0x00, 0x21, 0x00, 0x10, 0x00, 0x00, 0x00]
    );
}

#[tokio::test]
async fn le_set_scan_enable() {
    let mut sink = RecordingSink::new();
    sink.le_set_scan_enable(true, false).await.unwrap();
    assert_eq!(sink.written_data, [1, 0x0C, 0x20, 2, 1, 0]);
}

#[tokio::test]
async fn le_create_connection_no_whitelist() {
    let mut sink = RecordingSink::new();
    sink.le_create_connection(&ConnectionParameters {
        scan_window: ScanWindow::start_every(Duration::from_millis(50))
            .and_then(|b| b.open_for(Duration::from_millis(25)))
            .unwrap(),
        initiator_filter_policy: ConnectionFilterPolicy::UseAddress,
        peer_address: PeerAddrType::PublicDeviceAddress(hci::BdAddr([1, 2, 3, 4, 5, 6])),
        own_address_type: OwnAddressType::Public,
        conn_interval: ConnectionIntervalBuilder::new()
            .with_range(Duration::from_millis(50), Duration::from_millis(500))
            .with_latency(10)
            .with_supervision_timeout(Duration::from_secs(15))
            .build()
            .unwrap(),
        expected_connection_length: ExpectedConnectionLength::new(
            Duration::from_millis(200),
            Duration::from_millis(500),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    assert_eq!(
        sink.written_data,
        vec![
            1, 0x0D, 0x20, 25, 0x50, 0x00, 0x28, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x00, 0x28, 0x00, 0x90, 0x01, 0x0A, 0x00, 0xDC, 0x05, 0x40, 0x01, 0x20, 0x03,
        ]
    );
}

#[tokio::test]
async fn le_create_connection_use_whitelist() {
    let mut sink = RecordingSink::new();
    sink.le_create_connection(&ConnectionParameters {
        scan_window: ScanWindow::start_every(Duration::from_millis(50))
            .and_then(|b| b.open_for(Duration::from_millis(25)))
            .unwrap(),
        initiator_filter_policy: ConnectionFilterPolicy::WhiteList,
        peer_address: PeerAddrType::PublicDeviceAddress(hci::BdAddr([1, 2, 3, 4, 5, 6])),
        own_address_type: OwnAddressType::Public,
        conn_interval: ConnectionIntervalBuilder::new()
            .with_range(Duration::from_millis(50), Duration::from_millis(500))
            .with_latency(10)
            .with_supervision_timeout(Duration::from_secs(15))
            .build()
            .unwrap(),
        expected_connection_length: ExpectedConnectionLength::new(
            Duration::from_millis(200),
            Duration::from_millis(500),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    assert_eq!(
        sink.written_data,
        vec![
            1, 0x0D, 0x20, 25, 0x50, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x28, 0x00, 0x90, 0x01, 0x0A, 0x00, 0xDC, 0x05, 0x40, 0x01, 0x20, 0x03,
        ]
    );
}

#[tokio::test]
async fn le_add_device_to_white_list() {
    let mut sink = RecordingSink::new();
    sink.le_add_device_to_white_list(hci::BdAddrType::Public(hci::BdAddr([1, 2, 3, 4, 5, 6])))
        .await
        .unwrap();
    assert_eq!(
        sink.written_data,
        [1, 0x11, 0x20, 7, 0x00, 1, 2, 3, 4, 5, 6]
    );
}

#[cfg(feature = "version-5-0")]
#[tokio::test]
async fn le_add_anon_advertising_devices_to_white_list() {
    let mut sink = RecordingSink::new();
    sink.le_add_anon_advertising_devices_to_white_list()
        .unwrap();
    assert_eq!(
        sink.written_data,
        [1, 0x11, 0x20, 7, 0xFF, 0, 0, 0, 0, 0, 0]
    );
}

#[tokio::test]
async fn le_remove_device_from_white_list() {
    let mut sink = RecordingSink::new();
    sink.le_remove_device_from_white_list(hci::BdAddrType::Public(hci::BdAddr([1, 2, 3, 4, 5, 6])))
        .await
        .unwrap();
    assert_eq!(
        sink.written_data,
        [1, 0x12, 0x20, 7, 0x00, 1, 2, 3, 4, 5, 6]
    );
}

#[cfg(feature = "version-5-0")]
#[tokio::test]
async fn le_remove_anon_advertising_devices_from_white_list() {
    let mut sink = RecordingSink::new();
    sink.le_remove_anon_advertising_devices_from_white_list()
        .unwrap();
    assert_eq!(
        sink.written_data,
        [1, 0x12, 0x20, 7, 0xFF, 0, 0, 0, 0, 0, 0]
    );
}

#[tokio::test]
async fn le_connection_update() {
    let mut sink = RecordingSink::new();
    sink.le_connection_update(&ConnectionUpdateParameters {
        conn_handle: hci::ConnectionHandle(0x0201),
        conn_interval: ConnectionIntervalBuilder::new()
            .with_range(Duration::from_millis(50), Duration::from_millis(500))
            .with_latency(10)
            .with_supervision_timeout(Duration::from_secs(15))
            .build()
            .unwrap(),
        expected_connection_length: ExpectedConnectionLength::new(
            Duration::from_millis(200),
            Duration::from_millis(500),
        )
        .unwrap(),
    })
    .await
    .unwrap();
    assert_eq!(
        sink.written_data,
        vec![
            1, 0x13, 0x20, 14, 0x01, 0x02, 0x28, 0x00, 0x90, 0x01, 0x0A, 0x00, 0xDC, 0x05, 0x40,
            0x01, 0x20, 0x03,
        ]
    );
}

#[tokio::test]
async fn le_set_host_channel_classification() {
    let mut sink = RecordingSink::new();
    sink.le_set_host_channel_classification(
        hci::ChannelClassification::CH_0
            | hci::ChannelClassification::CH_4
            | hci::ChannelClassification::CH_8
            | hci::ChannelClassification::CH_12
            | hci::ChannelClassification::CH_16
            | hci::ChannelClassification::CH_20
            | hci::ChannelClassification::CH_24
            | hci::ChannelClassification::CH_28
            | hci::ChannelClassification::CH_32
            | hci::ChannelClassification::CH_36,
    )
    .await
    .unwrap();
    assert_eq!(
        sink.written_data,
        [1, 0x14, 0x20, 5, 0x11, 0x11, 0x11, 0x11, 0x11]
    );
}

#[tokio::test]
async fn le_set_host_channel_classification_failed_empty() {
    let mut sink = RecordingSink::new();
    let err = sink
        .le_set_host_channel_classification(hci::ChannelClassification::empty())
        .await
        .err()
        .unwrap();
    assert_eq!(err, Error::NoValidChannel);
    assert_eq!(sink.written_data, []);
}

#[tokio::test]
async fn le_encrypt() {
    let mut sink = RecordingSink::new();
    sink.le_encrypt(&AesParameters {
        key: EncryptionKey([
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
        ]),
        plaintext_data: PlaintextBlock([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ]),
    })
    .await
    .unwrap();
    assert_eq!(
        sink.written_data,
        vec![
            1, 0x17, 0x20, 32, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ]
    );
}

#[tokio::test]
async fn le_start_encryption() {
    let mut sink = RecordingSink::new();
    sink.le_start_encryption(&EncryptionParameters {
        conn_handle: hci::ConnectionHandle(0x0201),
        random_number: 0x0807_0605_0403_0201,
        encrypted_diversifier: 0x0a09,
        long_term_key: EncryptionKey([
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
        ]),
    })
    .await
    .unwrap();
    assert_eq!(
        sink.written_data,
        vec![
            1, 0x19, 0x20, 28, 0x01, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
        ]
    );
}

#[tokio::test]
async fn le_long_term_key_request_reply() {
    let mut sink = RecordingSink::new();
    sink.le_long_term_key_request_reply(
        hci::ConnectionHandle(0x0201),
        &EncryptionKey([
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
        ]),
    )
    .await
    .unwrap();
    assert_eq!(
        sink.written_data,
        vec![
            1, 0x1A, 0x20, 18, 0x01, 0x02, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa,
            0xb, 0xc, 0xd, 0xe, 0xf,
        ]
    );
}

#[tokio::test]
async fn le_receiver_test() {
    let mut sink = RecordingSink::new();
    sink.le_receiver_test(0x27).await.unwrap();
    assert_eq!(sink.written_data, [1, 0x1D, 0x20, 1, 0x27]);
}

#[tokio::test]
async fn le_receiver_test_out_of_range() {
    let mut sink = RecordingSink::new();
    let err = sink.le_receiver_test(0x28).await.err().unwrap();
    assert_eq!(err, Error::InvalidTestChannel(0x28));
    assert_eq!(sink.written_data, []);
}

#[tokio::test]
async fn le_transmitter_test() {
    let mut sink = RecordingSink::new();
    sink.le_transmitter_test(0x27, 0x25, TestPacketPayload::PrbS9)
        .await
        .unwrap();
    assert_eq!(sink.written_data, [1, 0x1E, 0x20, 3, 0x27, 0x25, 0x00]);
}

#[tokio::test]
async fn le_transmitter_test_channel_out_of_range() {
    let mut sink = RecordingSink::new();
    let err = sink
        .le_transmitter_test(0x28, 0x25, TestPacketPayload::PrbS9)
        .await
        .err()
        .unwrap();
    assert_eq!(err, Error::InvalidTestChannel(0x28));
    assert_eq!(sink.written_data, []);
}

#[tokio::test]
async fn le_transmitter_test_length_out_of_range() {
    let mut sink = RecordingSink::new();
    let err = sink
        .le_transmitter_test(0x27, 0x26, TestPacketPayload::PrbS9)
        .await
        .err()
        .unwrap();
    assert_eq!(err, Error::InvalidTestPayloadLength(0x26));
    assert_eq!(sink.written_data, []);
}
