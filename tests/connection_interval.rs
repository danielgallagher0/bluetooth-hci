extern crate stm32wb_hci as hci;

use hci::types::{
    ConnectionInterval, ConnectionIntervalBuilder, ConnectionIntervalError, FixedConnectionInterval,
};
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
    interval.copy_into_slice(&mut bytes);

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

#[test]
fn from_bytes_valid() {
    let valid_bytes = [0x90, 0x00, 0x90, 0x01, 0x0A, 0x00, 0xDC, 0x05];
    let interval = ConnectionInterval::from_bytes(&valid_bytes).unwrap();
    let mut bytes = [0; 8];
    interval.copy_into_slice(&mut bytes);
    assert_eq!(bytes, valid_bytes);
}

#[test]
fn fixed_from_bytes_valid() {
    let valid_bytes = [0x90, 0x01, 0x0A, 0x00, 0xDC, 0x05];
    let interval = FixedConnectionInterval::from_bytes(&valid_bytes).unwrap();
    assert_eq!(interval.interval(), Duration::from_millis(0x190 * 5 / 4));
    assert_eq!(interval.conn_latency(), 0x0A);
    assert_eq!(
        interval.supervision_timeout(),
        Duration::from_millis(10 * 0x05DC)
    );
}

#[test]
fn from_bytes_interval_too_short() {
    let bytes = [0x05, 0x00, 0x09, 0x00, 0x0A, 0x00, 0xDC, 0x05];
    let err = ConnectionInterval::from_bytes(&bytes).err().unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::IntervalTooShort(Duration::from_micros(6250))
    );
}

#[test]
fn fixed_from_bytes_interval_too_short() {
    let bytes = [0x05, 0x00, 0x0A, 0x00, 0xDC, 0x05];
    let err = FixedConnectionInterval::from_bytes(&bytes).err().unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::IntervalTooShort(Duration::from_micros(6250))
    );
}

#[test]
fn from_bytes_interval_too_long() {
    let bytes = [0x90, 0x00, 0x81, 0x0c, 0x0A, 0x00, 0xDC, 0x05];
    let err = ConnectionInterval::from_bytes(&bytes).err().unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::IntervalTooLong(Duration::from_micros(4_001_250))
    );
}

#[test]
fn fixed_from_bytes_interval_too_long() {
    let bytes = [0x81, 0x0c, 0x0A, 0x00, 0xDC, 0x05];
    let err = FixedConnectionInterval::from_bytes(&bytes).err().unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::IntervalTooLong(Duration::from_micros(4_001_250))
    );
}

#[test]
fn from_bytes_bad_connection_latency() {
    let bytes = [0x90, 0x00, 0x90, 0x01, 0xF4, 0x01, 0xDC, 0x05];
    let err = ConnectionInterval::from_bytes(&bytes).err().unwrap();
    assert_eq!(err, ConnectionIntervalError::BadConnectionLatency(500));
}

#[test]
fn fixed_from_bytes_bad_connection_latency() {
    let bytes = [0x90, 0x01, 0xF4, 0x01, 0xDC, 0x05];
    let err = FixedConnectionInterval::from_bytes(&bytes).err().unwrap();
    assert_eq!(err, ConnectionIntervalError::BadConnectionLatency(500));
}

#[test]
fn from_bytes_supervision_timeout_too_short_absolute() {
    let bytes = [0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0x09, 0x00];
    let err = ConnectionInterval::from_bytes(&bytes).err().unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::SupervisionTimeoutTooShort(
            Duration::from_millis(90),
            Duration::from_millis(100)
        )
    );
}

#[test]
fn fixed_from_bytes_supervision_timeout_too_short_absolute() {
    let bytes = [0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0x09, 0x00];
    let err = ConnectionInterval::from_bytes(&bytes).err().unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::SupervisionTimeoutTooShort(
            Duration::from_millis(90),
            Duration::from_millis(100)
        )
    );
}

#[test]
fn from_bytes_supervision_timeout_too_short_relative() {
    let bytes = [0x90, 0x00, 0x90, 0x01, 0x0A, 0x00, 0x4b, 0x04];
    let err = ConnectionInterval::from_bytes(&bytes).err().unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::SupervisionTimeoutTooShort(
            Duration::from_millis(10990),
            Duration::from_secs(11)
        )
    );
}

#[test]
fn fixed_from_bytes_supervision_timeout_too_short_relative() {
    let bytes = [0x90, 0x01, 0x0A, 0x00, 0x4b, 0x04];
    let err = FixedConnectionInterval::from_bytes(&bytes).err().unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::SupervisionTimeoutTooShort(
            Duration::from_millis(10990),
            Duration::from_secs(11)
        )
    );
}

#[test]
fn from_bytes_supervision_timeout_too_long() {
    let bytes = [0x90, 0x00, 0x90, 0x01, 0x0A, 0x00, 0x81, 0x0c];
    let err = ConnectionInterval::from_bytes(&bytes).err().unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::SupervisionTimeoutTooLong(Duration::from_millis(32_010))
    );
}

#[test]
fn fixed_from_bytes_supervision_timeout_too_long() {
    let bytes = [0x90, 0x01, 0x0A, 0x00, 0x81, 0x0c];
    let err = FixedConnectionInterval::from_bytes(&bytes).err().unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::SupervisionTimeoutTooLong(Duration::from_millis(32_010))
    );
}

#[test]
fn from_bytes_supervision_timeout_impossible() {
    let bytes = [0x90, 0x00, 0x80, 0x0C, 0x03, 0x00, 0x80, 0x0c];
    let err = ConnectionInterval::from_bytes(&bytes).err().unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::ImpossibleSupervisionTimeout(Duration::from_millis(32_000))
    );
}

#[test]
fn fixed_from_bytes_supervision_timeout_impossible() {
    let bytes = [0x80, 0x0C, 0x03, 0x00, 0x80, 0x0c];
    let err = FixedConnectionInterval::from_bytes(&bytes).err().unwrap();
    assert_eq!(
        err,
        ConnectionIntervalError::ImpossibleSupervisionTimeout(Duration::from_millis(32_000))
    );
}
