//! Types related to the LE advertising interval.

use byteorder::{ByteOrder, LittleEndian};
use core::time::Duration;

/// Define an advertising interval range.
///
/// The advertising interval min shall be less than or equal to the advertising interval
/// max. The advertising interval min and advertising interval max should not be the same value
/// to enable the Controller to determine the best advertising interval given other activities,
/// though this implementation allows them to be equal.
///
/// For [high duty cycle directed
/// advertising](AdvertisingType::ConnectableDirectedHighDutyCycle), the advertising interval is
/// not used and shall be ignored.  This implementation sends 0 for both fields in that case.
///
/// The advertising interval min and advertising interval max shall not be set to less than 100
/// ms if the advertising type is [`ScannableUndirected`](AdvertisingType::ScannableUndirected)
/// or [`NonConnectableUndirected`](AdvertisingType::NonConnectableUndirected).  This
/// restriction is removed in version 5.0 of the spec.
#[derive(Clone, Debug)]
pub struct AdvertisingInterval {
    // The first field is the min; the second is the max
    interval: (Duration, Duration),
    _advertising_type: AdvertisingType,
}

impl AdvertisingInterval {
    /// Begins building an advertising interval.
    pub fn for_type(adv_type: AdvertisingType) -> AdvertisingIntervalBuilder {
        AdvertisingIntervalBuilder {
            advertising_type: adv_type,
        }
    }

    /// Serialize the interval into the given buffer.
    ///
    /// Serializes the minimum range of the interval (2 bytes), the maximum range of the interval (2
    /// bytes), and the advertising type (1 byte).
    ///
    /// If the advertising type is [high duty cycle
    /// directed](AdvertisingType::ConnectableDirectedHighDutyCycle), the advertising interval is
    /// not used and shall be ignored.  This implementation sends 0 for both fields in that case.
    ///
    /// # Panics
    ///
    /// - If the provided buffer is not at least 5 bytes long.
    pub fn copy_into_slice(&self, bytes: &mut [u8]) {
        if self._advertising_type == AdvertisingType::ConnectableDirectedHighDutyCycle {
            bytes[0..4].copy_from_slice(&[0; 4]);
        } else {
            LittleEndian::write_u16(&mut bytes[0..2], Self::duration_as_u16(self.interval.0));
            LittleEndian::write_u16(&mut bytes[2..4], Self::duration_as_u16(self.interval.1));
        }
        bytes[4] = self._advertising_type as u8;
    }

    fn duration_as_u16(d: Duration) -> u16 {
        // T = 0.625 ms * N
        // so N = T / 0.625 ms
        //      = T / 625 us
        //
        // Note: 1600 = 1_000_000 / 625
        (1600 * d.as_secs() as u32 + (d.subsec_micros() / 625)) as u16
    }

    /// Returns the advertising type.
    pub fn advertising_type(&self) -> AdvertisingType {
        self._advertising_type
    }
}

/// Partially-specified advertising interval.
pub struct AdvertisingIntervalBuilder {
    advertising_type: AdvertisingType,
}

impl AdvertisingIntervalBuilder {
    /// Completes the advertising interval with the provided minimum and maximum values.
    ///
    /// # Errors
    ///
    /// - [TooShort](AdvertisingIntervalError::TooShort) if the minimum value is too small. For
    ///   Bluetooth specifications v4.x, if the advertising type is
    ///   [ScannableUndirected](AdvertisingType::ScannableUndirected), then the minimum value is 100
    ///   ms. In all other cases, the minimum value is 20 ms.
    /// - [TooLong](AdvertisingIntervalError::TooLong) if the maximum value is too large. The
    ///   maximum value is 10.24 seconds.
    /// - [Inverted](AdvertisingIntervalError::Inverted) if the minimum is greater than the
    ///   maximum.
    pub fn with_range(
        &self,
        min: Duration,
        max: Duration,
    ) -> Result<AdvertisingInterval, AdvertisingIntervalError> {
        const MIN: Duration = Duration::from_millis(20);
        if min < MIN {
            return Err(AdvertisingIntervalError::TooShort(min));
        }

        const MAX: Duration = Duration::from_millis(10240);
        if max > MAX {
            return Err(AdvertisingIntervalError::TooLong(max));
        }

        if min > max {
            return Err(AdvertisingIntervalError::Inverted(min, max));
        }

        Ok(AdvertisingInterval {
            interval: (min, max),
            _advertising_type: self.advertising_type,
        })
    }

    /// Completes the advertising interval without a range.
    ///
    /// This is only valid if the advertising type is
    /// [ScannableUndirected](AdvertisingType::ScannableUndirected).
    ///
    /// # Errors
    ///
    /// - [NoRange](AdvertisingIntervalError::NoRange) if the advertising type is anything except
    ///   [ConnectableDirectedHighDutyCycle](AdvertisingType::ConnectableDirectedHighDutyCycle).
    pub fn build(&self) -> Result<AdvertisingInterval, AdvertisingIntervalError> {
        if self.advertising_type == AdvertisingType::ConnectableDirectedHighDutyCycle {
            Ok(AdvertisingInterval {
                interval: (Duration::from_secs(0), Duration::from_secs(0)),
                _advertising_type: self.advertising_type,
            })
        } else {
            Err(AdvertisingIntervalError::NoRange)
        }
    }
}

/// Potential errors that can occur when specifying an [`AdvertisingInterval`].
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AdvertisingIntervalError {
    /// The minimum value was too short. Includes the invalid value.
    TooShort(Duration),
    /// The maximum value was too long. Includes the invalid value.
    TooLong(Duration),
    /// The minimum value was greater than the maximum value. Includes the provided minimum and
    /// value, respectively.
    Inverted(Duration, Duration),
    /// The advertising interval was not given a range, and the type was not
    /// [ConnectableDirectedHighDutyCycle](AdvertisingType::ConnectableDirectedHighDutyCycle).
    NoRange,
}

/// The advertising type is used in the
/// [`AdvertisingParameters`]($crate::host::AdvertisingParameters) to determine the packet type that
/// is used for advertising when advertising is enabled.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AdvertisingType {
    /// Connectable undirected advertising
    ConnectableUndirected = 0x00,
    /// Connectable high duty cycle directed advertising
    ConnectableDirectedHighDutyCycle = 0x01,
    /// Scannable undirected advertising
    ScannableUndirected = 0x02,
    /// Non connectable undirected advertising
    NonConnectableUndirected = 0x03,
    /// Connectable low duty cycle directed advertising
    ConnectableDirectedLowDutyCycle = 0x04,
}
