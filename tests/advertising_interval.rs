#![feature(async_fn_in_trait)]

extern crate stm32wb_hci as hci;

use hci::types::{AdvertisingInterval, AdvertisingIntervalError, AdvertisingType};
use std::time::Duration;

#[test]
fn valid() {
    let interval = AdvertisingInterval::for_type(AdvertisingType::ConnectableUndirected)
        .with_range(Duration::from_millis(21), Duration::from_millis(1000))
        .unwrap();
    let mut bytes = [0; 5];
    interval.copy_into_slice(&mut bytes);

    // 21 ms / 0.625 ms = 33 = 0x0021
    // 1000 ms / 0.625 ms = 1600 = 0x0640
    assert_eq!(bytes, [0x21, 0x00, 0x40, 0x06, 0x00]);
}

#[test]
fn normal_min_scannable_undirected() {
    let interval = AdvertisingInterval::for_type(AdvertisingType::ScannableUndirected)
        .with_range(Duration::from_millis(99), Duration::from_millis(1000))
        .unwrap();
    let mut bytes = [0; 5];
    interval.copy_into_slice(&mut bytes);

    // 99 ms / 0.625 ms = 158 = 0x009E
    // 1000 ms / 0.625 ms = 1600 = 0x0640
    assert_eq!(bytes, [0x9E, 0x00, 0x40, 0x06, 0x02]);
}

#[test]
fn connectable_directed_high_duty_cycle_without_range() {
    let interval = AdvertisingInterval::for_type(AdvertisingType::ConnectableDirectedHighDutyCycle)
        .build()
        .unwrap();
    let mut bytes = [0; 5];
    interval.copy_into_slice(&mut bytes);
    assert_eq!(bytes, [0x00, 0x00, 0x00, 0x00, 0x01]);
}

#[test]
fn connectable_directed_high_duty_cycle_with_range() {
    let interval = AdvertisingInterval::for_type(AdvertisingType::ConnectableDirectedHighDutyCycle)
        .with_range(Duration::from_millis(99), Duration::from_millis(1000))
        .unwrap();
    let mut bytes = [0; 5];
    interval.copy_into_slice(&mut bytes);

    // Interval is ignored for this advertising type.
    assert_eq!(bytes, [0x00, 0x00, 0x00, 0x00, 0x01]);
}

#[test]
fn other_type_without_range() {
    let err = AdvertisingInterval::for_type(AdvertisingType::ScannableUndirected)
        .build()
        .err()
        .unwrap();
    assert_eq!(err, AdvertisingIntervalError::NoRange);
}

#[test]
fn interval_too_short() {
    let err = AdvertisingInterval::for_type(AdvertisingType::ConnectableUndirected)
        .with_range(Duration::from_millis(19), Duration::from_millis(1000))
        .err()
        .unwrap();
    assert_eq!(
        err,
        AdvertisingIntervalError::TooShort(Duration::from_millis(19))
    );
}

#[test]
fn interval_too_long() {
    let err = AdvertisingInterval::for_type(AdvertisingType::ConnectableUndirected)
        .with_range(Duration::from_millis(100), Duration::from_millis(10241))
        .err()
        .unwrap();
    assert_eq!(
        err,
        AdvertisingIntervalError::TooLong(Duration::from_millis(10241))
    );
}

#[test]
fn inverted() {
    let err = AdvertisingInterval::for_type(AdvertisingType::ConnectableUndirected)
        .with_range(Duration::from_millis(500), Duration::from_millis(499))
        .err()
        .unwrap();
    assert_eq!(
        err,
        AdvertisingIntervalError::Inverted(Duration::from_millis(500), Duration::from_millis(499))
    );
}
