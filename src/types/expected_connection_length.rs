//! Types related to the expected connection length range.

use byteorder::{ByteOrder, LittleEndian};
use core::time::Duration;

/// Define an expected connection length range
///
/// There is no minimum. The maximum is bounded by what is representable as a u16 at T = N * 0.625
/// ms, so max = 65535 * 0.625 ms = 40.959375 seconds.
#[derive(Clone, Debug)]
pub struct ExpectedConnectionLength {
    range: (Duration, Duration),
}

impl ExpectedConnectionLength {
    /// Creates a new ExpectedConnectionLength, or returns an error if the duration is invalid.
    ///
    /// # Errors
    ///
    /// - [Inverted](ExpectedConnectionLengthError::Inverted) if `min` is greater than `max`
    /// - [TooLong](ExpectedConnectionLengthError::TooLong) if `max` is longer than 40.959375
    ///   seconds.
    pub fn new(
        min: Duration,
        max: Duration,
    ) -> Result<ExpectedConnectionLength, ExpectedConnectionLengthError> {
        if min > max {
            return Err(ExpectedConnectionLengthError::Inverted(min, max));
        }

        const ABSOLUTE_MAX: Duration = Duration::from_micros(40_959_375);
        assert_eq!(Self::as_u16(ABSOLUTE_MAX), 0xFFFF);
        if max > ABSOLUTE_MAX {
            return Err(ExpectedConnectionLengthError::TooLong(max));
        }

        Ok(ExpectedConnectionLength { range: (min, max) })
    }

    /// Serializes the expected connection length range into the given byte buffer.
    ///
    /// # Panics
    ///
    /// The buffer must be at least 4 bytes long.
    pub fn copy_into_slice(&self, bytes: &mut [u8]) {
        assert!(bytes.len() >= 4);

        LittleEndian::write_u16(&mut bytes[0..2], Self::as_u16(self.range.0));
        LittleEndian::write_u16(&mut bytes[2..4], Self::as_u16(self.range.1));
    }

    fn as_u16(d: Duration) -> u16 {
        // T = 0.625 ms * N
        // so N = T / 0.625 ms
        //      = T / 625 us
        //
        // Note: 1600 = 1_000_000 / 625
        (1600 * d.as_secs() as u32 + (d.subsec_micros() / 625)) as u16
    }
}

/// Types of errors that can occure when creating a [ExpectedConnectionLength].
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ExpectedConnectionLengthError {
    /// The maximum expected length is too long. The maximum is 40.959375, because nothing higher
    /// can be represented as a u16.
    TooLong(Duration),
    /// The min is greater than the max. Returns the min and max, respectively.
    Inverted(Duration, Duration),
}
