//! Types related to the connection interval.

use byteorder::{ByteOrder, LittleEndian};
use core::cmp;
use core::time::Duration;

/// Define a connection interval range with its latency and supervision timeout. This value is
/// passed to the controller, which determines the [actual connection
/// interval](FixedConnectionInterval).
#[derive(Copy, Clone, Debug)]
pub struct ConnectionInterval {
    interval_: (Duration, Duration),
    conn_latency_: u16,
    supervision_timeout_: Duration,
}

impl ConnectionInterval {
    /// Serializes the connection interval into the given byte buffer.
    ///
    /// The interval is serialized as:
    /// - The minimum interval value, appropriately converted (2 bytes)
    /// - The maximum interval value, appropriately converted (2 bytes)
    /// - The connection latency (2 bytes)
    /// - The supervision timeout, appropriately converted (2 bytes)
    ///
    /// # Panics
    ///
    /// The provided buffer must be at least 8 bytes long.
    pub fn into_bytes(&self, bytes: &mut [u8]) {
        assert!(bytes.len() >= 8);

        LittleEndian::write_u16(&mut bytes[0..2], Self::interval_as_u16(self.interval_.0));
        LittleEndian::write_u16(&mut bytes[2..4], Self::interval_as_u16(self.interval_.1));
        LittleEndian::write_u16(&mut bytes[4..6], self.conn_latency_);
        LittleEndian::write_u16(
            &mut bytes[6..8],
            Self::timeout_as_u16(self.supervision_timeout_),
        );
    }

    /// Deserializes the connection interval from the given byte buffer.
    ///
    /// - The minimum interval value, appropriately converted (2 bytes)
    /// - The maximum interval value, appropriately converted (2 bytes)
    /// - The connection latency (2 bytes)
    /// - The supervision timeout, appropriately converted (2 bytes)
    ///
    /// # Panics
    ///
    /// The provided buffer must be at least 8 bytes long.
    ///
    /// # Errors
    ///
    /// Any of the errors from the [builder](ConnectionIntervalBuilder::build) except for
    /// Incomplete.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectionIntervalError> {
        assert!(bytes.len() >= 8);

        // Do the error checking with the standard connection interval builder. The min and max of
        // the interval range are allowed to be equal.
        let interval_min =
            Duration::from_micros(1_250) * LittleEndian::read_u16(&bytes[0..2]) as u32;
        let interval_max =
            Duration::from_micros(1_250) * LittleEndian::read_u16(&bytes[2..4]) as u32;
        let latency = LittleEndian::read_u16(&bytes[4..6]);
        let timeout = Duration::from_millis(10) * LittleEndian::read_u16(&bytes[6..8]) as u32;
        ConnectionIntervalBuilder::new()
            .with_range(interval_min, interval_max)
            .with_latency(latency)
            .with_supervision_timeout(timeout)
            .build()
    }

    fn interval_as_u16(d: Duration) -> u16 {
        // T ms = N * 1.25 ms
        // N = T / 1.25 ms
        //   = T / (5/4) ms
        //   = 4 * T ms / 5 ms
        //
        // Note: 1000 * 4 / 5 = 800
        ((800 * d.as_secs()) as u32 + 4 * d.subsec_millis() / 5) as u16
    }

    fn timeout_as_u16(d: Duration) -> u16 {
        // T ms = N * 10 ms
        // N = T ms / 10 ms
        ((100 * d.as_secs()) as u32 + d.subsec_millis() / 10) as u16
    }
}

/// Intermediate builder for the [ConnectionInterval]
pub struct ConnectionIntervalBuilder {
    interval: Option<(Duration, Duration)>,
    conn_latency: Option<u16>,
    supervision_timeout: Option<Duration>,
}

impl ConnectionIntervalBuilder {
    /// Initializes a new builder.
    pub fn new() -> ConnectionIntervalBuilder {
        ConnectionIntervalBuilder {
            interval: None,
            conn_latency: None,
            supervision_timeout: None,
        }
    }

    /// Sets the connection interval range.
    ///
    /// # Errors
    ///
    /// There are no errors from this function, but it may cause errors in
    /// [build](ConnectionIntervalBuilder::build) if:
    /// - `min` is greater than `max`
    /// - Either `min` or `max` is less than 7.5 ms or more than 4 seconds.
    /// - `max` leads to an invalid relative supervision timeout.
    pub fn with_range(&mut self, min: Duration, max: Duration) -> &mut ConnectionIntervalBuilder {
        self.interval = Some((min, max));
        self
    }

    /// Sets the connection latency.
    ///
    /// # Errors
    ///
    /// There are no errors from this function, but it may cause errors in
    /// [build](ConnectionIntervalBuilder::build) if:
    /// - `latency` is 500 or greater.
    /// - `latency` leads to an invalid relative supervision timeout.
    pub fn with_latency(&mut self, latency: u16) -> &mut ConnectionIntervalBuilder {
        self.conn_latency = Some(latency);
        self
    }

    /// Sets the supervision timeout.
    ///
    /// # Errors
    ///
    /// There are no errors from this function, but it may cause errors in
    /// [build](ConnectionIntervalBuilder::build) if:
    /// - `timeout` less than 100 ms or greater than 32 seconds
    /// - `timeout` results in an invalid relative supervision timeout.
    pub fn with_supervision_timeout(
        &mut self,
        timeout: Duration,
    ) -> &mut ConnectionIntervalBuilder {
        self.supervision_timeout = Some(timeout);
        self
    }

    /// Builds the connection interval if all parameters are valid.
    ///
    /// # Errors
    ///
    /// - [Incomplete](ConnectionIntervalError::Incomplete) if any of
    ///   [`with_range`](ConnectionIntervalBuilder::with_range),
    ///   [`with_latency`](ConnectionIntervalBuilder::with_latency), or
    ///   [`with_supervision_timeout`](ConnectionIntervalBuilder::with_supervision_timeout) have not
    ///   been called.
    /// - [IntervalTooShort](ConnectionIntervalError::IntervalTooShort) if the minimum range value
    ///   is less than 7.5 ms.
    /// - [IntervalTooLong](ConnectionIntervalError::IntervalTooLong) if the maximum range value
    ///   is greater than 4 seconds.
    /// - [IntervalInverted](ConnectionIntervalError::IntervalInverted) if the minimum range value
    ///   is greater than the maximum.
    /// - [BadConnectionLatency](ConnectionIntervalError::BadConnectionLatency) if the connection
    ///   latency is 500 or more.
    /// - [SupervisionTimeoutTooShort](ConnectionIntervalError::SupervisionTimeoutTooShort) if the
    ///   supervision timeout is less than 100 ms, or if it is less than the computed minimum: (1 +
    ///   latency) * interval max * 2.
    /// - [SupervisionTimeoutTooLong](ConnectionIntervalError::SupervisionTimeoutTooLong) if the
    ///   supervision timeout is more than 32 seconds.
    /// - [ImpossibleSupervisionTimeout](ConnectionIntervalError::ImpossibleSupervisionTimeout) if
    ///   the computed minimum supervision timeout ((1 + latency) * interval max * 2) is 32 seconds
    ///   or more.
    pub fn build(&self) -> Result<ConnectionInterval, ConnectionIntervalError> {
        if self.interval.is_none()
            || self.conn_latency.is_none()
            || self.supervision_timeout.is_none()
        {
            return Err(ConnectionIntervalError::Incomplete);
        }

        let interval = self.interval.unwrap();
        const INTERVAL_MIN: Duration = Duration::from_micros(7500);
        if interval.0 < INTERVAL_MIN {
            return Err(ConnectionIntervalError::IntervalTooShort(interval.0));
        }

        const INTERVAL_MAX: Duration = Duration::from_secs(4);
        if interval.1 > INTERVAL_MAX {
            return Err(ConnectionIntervalError::IntervalTooLong(interval.1));
        }

        if interval.0 > interval.1 {
            return Err(ConnectionIntervalError::IntervalInverted(
                interval.0, interval.1,
            ));
        }

        let conn_latency = self.conn_latency.unwrap();
        const LATENCY_MAX: u16 = 0x1F3;
        if conn_latency > LATENCY_MAX {
            return Err(ConnectionIntervalError::BadConnectionLatency(conn_latency));
        }

        let supervision_timeout = self.supervision_timeout.unwrap();
        let computed_timeout_min = interval.1 * (1 + conn_latency as u32) * 2;
        const TIMEOUT_MAX: Duration = Duration::from_secs(32);
        if computed_timeout_min >= TIMEOUT_MAX {
            return Err(ConnectionIntervalError::ImpossibleSupervisionTimeout(
                computed_timeout_min,
            ));
        }

        const TIMEOUT_ABS_MIN: Duration = Duration::from_millis(100);
        let timeout_min = cmp::max(computed_timeout_min, TIMEOUT_ABS_MIN);
        if supervision_timeout <= timeout_min {
            return Err(ConnectionIntervalError::SupervisionTimeoutTooShort(
                supervision_timeout,
                timeout_min,
            ));
        }

        if supervision_timeout > TIMEOUT_MAX {
            return Err(ConnectionIntervalError::SupervisionTimeoutTooLong(
                supervision_timeout,
            ));
        }

        Ok(ConnectionInterval {
            interval_: interval,
            conn_latency_: conn_latency,
            supervision_timeout_: supervision_timeout,
        })
    }
}

/// Types of errors that can occure when creating a [ConnectionInterval].
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ConnectionIntervalError {
    /// At least one of any of [`with_range`](ConnectionIntervalBuilder::with_range),
    /// [`with_latency`](ConnectionIntervalBuilder::with_latency), or
    /// [`with_supervision_timeout`](ConnectionIntervalBuilder::with_supervision_timeout) has not
    /// been called.
    Incomplete,
    /// The minimum range value is less than 7.5 ms. Includes the invalid value.
    IntervalTooShort(Duration),
    /// The maximum range value is greater than 4 seconds. Includes the invalid value.
    IntervalTooLong(Duration),
    /// The minimum range value is greater than the maximum. Includes the provided minimum and
    /// maximum, respectively.
    IntervalInverted(Duration, Duration),
    /// The connection latency is 500 or more. Includes the provided value.
    BadConnectionLatency(u16),
    /// The supervision timeout is less than 100 ms, or it is less than the computed minimum: (1 +
    /// latency) * interval max * 2. The first value is the provided timeout; the second is the
    /// required minimum.
    SupervisionTimeoutTooShort(Duration, Duration),
    /// The supervision timeout is more than 32 seconds. Includes the provided timeout.
    SupervisionTimeoutTooLong(Duration),
    /// The computed minimum supervision timeout ((1 + latency) * interval max * 2) is 32 seconds
    /// or more. Includes the computed minimum.
    ImpossibleSupervisionTimeout(Duration),
}

/// Define a connection interval with its latency and supervision timeout. This value is
/// returned from the controller.
#[derive(Copy, Clone, Debug)]
pub struct FixedConnectionInterval {
    interval_: Duration,
    conn_latency_: u16,
    supervision_timeout_: Duration,
}

impl FixedConnectionInterval {
    /// Deserializes the connection interval from the given byte buffer.
    ///
    /// - The interval value, appropriately converted (2 bytes)
    /// - The connection latency (2 bytes)
    /// - The supervision timeout, appropriately converted (2 bytes)
    ///
    /// # Panics
    ///
    /// The provided buffer must be at least 6 bytes long.
    ///
    /// # Errors
    ///
    /// Any of the errors from the [builder](ConnectionIntervalBuilder::build) except for
    /// Incomplete.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectionIntervalError> {
        assert!(bytes.len() >= 6);

        // Do the error checking with the standard connection interval builder. The min and max of
        // the interval range are allowed to be equal.
        let interval = Duration::from_micros(1_250) * LittleEndian::read_u16(&bytes[0..2]) as u32;
        let latency = LittleEndian::read_u16(&bytes[2..4]);
        let timeout = Duration::from_millis(10) * LittleEndian::read_u16(&bytes[4..6]) as u32;
        ConnectionIntervalBuilder::new()
            .with_range(interval, interval)
            .with_latency(latency)
            .with_supervision_timeout(timeout)
            .build()?;

        Ok(FixedConnectionInterval {
            interval_: interval,
            conn_latency_: latency,
            supervision_timeout_: timeout,
        })
    }

    /// Returns the connection interval.
    pub fn interval(&self) -> Duration {
        self.interval_
    }

    /// Returns the connection latency, in number of events.
    pub fn conn_latency(&self) -> u16 {
        self.conn_latency_
    }

    /// Returns the supervision timeout.
    pub fn supervision_timeout(&self) -> Duration {
        self.supervision_timeout_
    }
}
