extern crate bluetooth_hci as hci;

use hci::types::{ExpectedConnectionLength, ExpectedConnectionLengthError};
use std::time::Duration;

#[test]
fn valid() {
    let range =
        ExpectedConnectionLength::new(Duration::from_millis(200), Duration::from_millis(500))
            .unwrap();
    let mut bytes = [0; 4];
    range.into_bytes(&mut bytes);
    assert_eq!(bytes, [0x40, 0x01, 0x20, 0x03]);
}

#[test]
fn interval_too_long() {
    let err = ExpectedConnectionLength::new(
        Duration::from_millis(200),
        Duration::from_micros(40_959_376),
    ).err()
        .unwrap();
    assert_eq!(
        err,
        ExpectedConnectionLengthError::TooLong(Duration::from_micros(40_959_376))
    );
}

#[test]
fn inverted() {
    let err = ExpectedConnectionLength::new(Duration::from_millis(400), Duration::from_millis(399))
        .err()
        .unwrap();
    assert_eq!(
        err,
        ExpectedConnectionLengthError::Inverted(
            Duration::from_millis(400),
            Duration::from_millis(399)
        )
    );
}
