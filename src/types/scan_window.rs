//! Types related to the LE scanning window.

use byteorder::{ByteOrder, LittleEndian};
use core::time::Duration;

/// Define a scanning window.
///
/// The controller runs LE scans every [`interval`](ScanWindow::interval), with scanning active
/// during the [`window`](ScanWindow::window) in every interval.
///
/// The minimum time range is 2.5 ms, and the maximum is 10.24 s. The window must be shorter than or
/// equal to the interval.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanWindow {
    interval_width: Duration,
    window_width: Duration,
}

impl ScanWindow {
    /// Returns the interval for the scanning window. The controller starts an LE scan every
    /// interval.
    pub fn interval(&self) -> Duration {
        self.interval_width
    }

    /// Returns the amount of time the controller is scanning every interval.
    pub fn window(&self) -> Duration {
        self.window_width
    }

    /// Serializes the window into the given byte buffer.
    ///
    /// # Panics
    ///
    /// The buffer must be at least 4 bytes long.
    pub fn copy_into_slice(&self, bytes: &mut [u8]) {
        assert!(bytes.len() >= 4);

        LittleEndian::write_u16(&mut bytes[0..2], Self::duration_as_u16(self.interval_width));
        LittleEndian::write_u16(&mut bytes[2..4], Self::duration_as_u16(self.window_width));
    }

    /// Begins building a [ScanWindow]. The scan window has the given interval. Returns a
    /// [builder](ScanWindowBuilder) that can be used to set the window duration.
    ///
    /// # Errors
    ///
    /// - [ScanWindowError::TooShort] if the provided interval is too short. It must be at least 2.5
    ///   ms.
    /// - [ScanWindowError::TooLong] if the provided interval is too long. It must be 10.24 seconds
    ///   or less.
    pub fn start_every(interval: Duration) -> Result<ScanWindowBuilder, ScanWindowError> {
        Ok(ScanWindowBuilder {
            interval: ScanWindow::validate(interval)?,
        })
    }

    fn validate(d: Duration) -> Result<Duration, ScanWindowError> {
        const MIN: Duration = Duration::from_micros(2500);
        if d < MIN {
            return Err(ScanWindowError::TooShort(d));
        }

        const MAX: Duration = Duration::from_millis(10240);
        if d > MAX {
            return Err(ScanWindowError::TooLong(d));
        }

        Ok(d)
    }

    fn duration_as_u16(d: Duration) -> u16 {
        // T = 0.625 ms * N
        // so N = T / 0.625 ms
        //      = T / 625 us
        //
        // Note: 1600 = 1_000_000 / 625
        (1600 * d.as_secs() as u32 + (d.subsec_micros() / 625)) as u16
    }
}

/// Intermediate builder for the [`ScanWindow`].
pub struct ScanWindowBuilder {
    interval: Duration,
}

impl ScanWindowBuilder {
    /// Completes building a [ScanWindow]. The scan window has the given window.
    ///
    /// # Errors
    ///
    /// - [ScanWindowError::TooShort] if the provided interval is too short. It must be at least 2.5
    ///   ms.
    /// - [ScanWindowError::TooLong] if the provided interval is too long. It must be 10.24 seconds
    ///   or less.
    /// - [ScanWindowError::Inverted] if the window is longer than the interval.
    pub fn open_for(&self, window: Duration) -> Result<ScanWindow, ScanWindowError> {
        if window > self.interval {
            return Err(ScanWindowError::Inverted {
                interval: self.interval,
                window,
            });
        }

        Ok(ScanWindow {
            interval_width: self.interval,
            window_width: ScanWindow::validate(window)?,
        })
    }
}

/// Types of errors that can occure when creating a [`ScanWindow`].
#[derive(Copy, Clone, Debug, PartialEq, defmt::Format)]
pub enum ScanWindowError {
    /// The duration is too short. Both the interval and duration must be at least 2.5 ms. Includes
    /// the invalid duration.
    TooShort(Duration),
    /// The duration is too long. Both the interval and duration must be no more than 10.24
    /// seconds. Includes the invalid duration.
    TooLong(Duration),
    /// The interval and window are inverted. That is, the interval is shorter than the window.
    Inverted {
        /// The provided interval, which is shorter than the window.
        interval: Duration,
        /// The provided window, which is longer than the interval.
        window: Duration,
    },
}
