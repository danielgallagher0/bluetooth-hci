#![feature(async_fn_in_trait)]

extern crate stm32wb_hci as hci;

use hci::types::{ScanWindow, ScanWindowError};
use std::time::Duration;

#[test]
fn valid() {
    let scan_window = ScanWindow::start_every(Duration::from_millis(10))
        .unwrap()
        .open_for(Duration::from_millis(5))
        .unwrap();
    assert_eq!(scan_window.interval(), Duration::from_millis(10));
    assert_eq!(scan_window.window(), Duration::from_millis(5));
}

#[test]
fn interval_too_short() {
    let err = ScanWindow::start_every(Duration::from_millis(2))
        .err()
        .unwrap();
    assert_eq!(err, ScanWindowError::TooShort(Duration::from_millis(2)));
}

#[test]
fn interval_too_long() {
    let err = ScanWindow::start_every(Duration::from_millis(10241))
        .err()
        .unwrap();
    assert_eq!(err, ScanWindowError::TooLong(Duration::from_millis(10241)));
}

#[test]
fn window_too_short() {
    let err = ScanWindow::start_every(Duration::from_millis(10))
        .unwrap()
        .open_for(Duration::from_millis(2))
        .err()
        .unwrap();
    assert_eq!(err, ScanWindowError::TooShort(Duration::from_millis(2)));
}

#[test]
fn inverted() {
    let err = ScanWindow::start_every(Duration::from_millis(100))
        .unwrap()
        .open_for(Duration::from_millis(101))
        .err()
        .unwrap();
    assert_eq!(
        err,
        ScanWindowError::Inverted {
            interval: Duration::from_millis(100),
            window: Duration::from_millis(101),
        }
    );
}

#[test]
fn inverted_and_window_too_long() {
    let err = ScanWindow::start_every(Duration::from_millis(100))
        .unwrap()
        .open_for(Duration::from_millis(10241))
        .err()
        .unwrap();
    assert_eq!(
        err,
        ScanWindowError::Inverted {
            interval: Duration::from_millis(100),
            window: Duration::from_millis(10241),
        }
    );
}

#[test]
fn copy_into_slice() {
    let scan_window = ScanWindow::start_every(Duration::from_millis(10))
        .unwrap()
        .open_for(Duration::from_millis(5))
        .unwrap();
    let mut bytes = [0; 4];
    scan_window.copy_into_slice(&mut bytes);
    assert_eq!(bytes, [0x10, 0x00, 0x08, 0x00]);
}
