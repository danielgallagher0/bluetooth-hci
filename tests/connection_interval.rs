extern crate bluetooth_hci as hci;

use hci::types::{ConnectionIntervalBuilder, ConnectionIntervalError};
use std::time::Duration;

#[test]
fn valid() {
    let interval = ConnectionIntervalBuilder::new()
        .with_range(Duration::from_millis(50), Duration::from_millis(500))
        .with_latency(10)
        .with_supervision_timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    let mut bytes = [0; 8];
    interval.into_bytes(&mut bytes);

    // 50 ms / 1.25 ms = 40 = 0x0028
    // 500 ms / 1.25 ms = 400 = 0x0190
    // 15000 ms / 10 ms = 1500 = 0x05DC
    assert_eq!(bytes, [0x28, 0x00, 0x90, 0x01, 0x0A, 0x00, 0xDC, 0x05]);
}

#[test]
fn incomplete() {
    assert_eq!(
        ConnectionIntervalBuilder::new()
            .with_latency(10)
            .with_supervision_timeout(Duration::from_secs(15))
            .build()
            .err()
            .unwrap(),
        ConnectionIntervalError::Incomplete
    );
    assert_eq!(
        ConnectionIntervalBuilder::new()
            .with_range(Duration::from_millis(50), Duration::from_millis(500))
            .with_supervision_timeout(Duration::from_secs(15))
            .build()
            .err()
            .unwrap(),
        ConnectionIntervalError::Incomplete
    );
    assert_eq!(
        ConnectionIntervalBuilder::new()
            .with_range(Duration::from_millis(50), Duration::from_millis(500))
            .with_latency(10)
            .build()
            .err()
            .unwrap(),
        ConnectionIntervalError::Incomplete
    );
}

#[test]
fn too_short() {
    let err = ConnectionIntervalBuilder::new()
        .with_range(Duration::from_millis(4), Duration::from_millis(1000))
        .with_latency(10)
        .with_supervision_timeout(Duration::from_secs(15))
        .build()
        .err()
        .unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::IntervalTooShort(Duration::from_millis(4))
    );
}

#[test]
fn too_long() {
    let err = ConnectionIntervalBuilder::new()
        .with_range(Duration::from_millis(100), Duration::from_millis(4001))
        .with_latency(10)
        .with_supervision_timeout(Duration::from_secs(15))
        .build()
        .err()
        .unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::IntervalTooLong(Duration::from_millis(4001))
    );
}

#[test]
fn inverted() {
    let err = ConnectionIntervalBuilder::new()
        .with_range(Duration::from_millis(500), Duration::from_millis(499))
        .with_latency(10)
        .with_supervision_timeout(Duration::from_secs(15))
        .build()
        .err()
        .unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::IntervalInverted(
            Duration::from_millis(500),
            Duration::from_millis(499)
        )
    );
}

#[test]
fn bad_conn_latency() {
    let err = ConnectionIntervalBuilder::new()
        .with_range(Duration::from_millis(50), Duration::from_millis(500))
        .with_latency(500)
        .with_supervision_timeout(Duration::from_secs(15))
        .build()
        .err()
        .unwrap();
    assert_eq!(err, ConnectionIntervalError::BadConnectionLatency(500));
}

#[test]
fn supervision_timeout_too_short_absolute() {
    let err = ConnectionIntervalBuilder::new()
        .with_range(Duration::from_micros(7500), Duration::from_micros(7500))
        .with_latency(0)
        .with_supervision_timeout(Duration::from_millis(99))
        .build()
        .err()
        .unwrap();

    // The relative minimum supervision timeout here would be 15 ms (7.5 ms * (1 + 0) * 2), so our
    // timeout would meet that requirement. However, it is lower than the absolute minimum.
    assert_eq!(
        err,
        ConnectionIntervalError::SupervisionTimeoutTooShort(
            Duration::from_millis(99),
            Duration::from_millis(100)
        )
    );
}

#[test]
fn supervision_timeout_too_short_relative() {
    let err = ConnectionIntervalBuilder::new()
        .with_range(Duration::from_millis(50), Duration::from_millis(500))
        .with_latency(10)
        .with_supervision_timeout(Duration::from_millis(10999))
        .build()
        .err()
        .unwrap();

    // The relative minimum supervision timeout here is be 11 s (500 ms * (1 + 10) * 2).
    assert_eq!(
        err,
        ConnectionIntervalError::SupervisionTimeoutTooShort(
            Duration::from_millis(10999),
            Duration::from_secs(11)
        )
    );
}

#[test]
fn supervision_timeout_too_long() {
    let err = ConnectionIntervalBuilder::new()
        .with_range(Duration::from_millis(50), Duration::from_millis(500))
        .with_latency(10)
        .with_supervision_timeout(Duration::from_millis(32001))
        .build()
        .err()
        .unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::SupervisionTimeoutTooLong(Duration::from_millis(32001))
    );
}

#[test]
fn impossible_supervision_timeout() {
    let err = ConnectionIntervalBuilder::new()
        .with_range(Duration::from_millis(50), Duration::from_secs(4))
        .with_latency(4)
        .with_supervision_timeout(Duration::from_secs(32))
        .build()
        .err()
        .unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::ImpossibleSupervisionTimeout(Duration::from_secs(40))
    );
}
