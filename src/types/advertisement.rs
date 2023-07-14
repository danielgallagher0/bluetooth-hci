//! Types for LE advertisements

use byteorder::{ByteOrder, LittleEndian};

use super::CommonDataType;

/// LE Advertisement Type
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Advertisement<'a> {
    /// Complete local name of the device.
    CompleteLocalName(&'a str),
    /// Service data with 16-bit UUID.
    ///
    /// The first parameter is the UUID, the second parameter is the payload.
    ///
    /// The payload may be up to 27 bytes for legacy advertising mode.
    ServiceData16BitUuid(u16, &'a [u8]),
    /// Service data with 32-bit UUID
    ///
    /// The first parameter is the UUID, the second parameter is the payload.
    ///
    /// The payload may be up to 25 bytes for legacy advertising mode.
    ServiceData32BitUuid(u32, &'a [u8]),
    /// Service data with 128-bit UUID
    ///
    /// The first parameter is the UUID, the second parameter is the payload.
    ///
    /// The payload may be up to 13 bytes for legacy advertising mode.
    ServiceData128BitUuid(u128, &'a [u8]),
    /// Manufacturer-specific data
    ///
    /// The first parameter is the manufacturer ID, the second parameter is the
    /// payload.
    ///
    /// The payload may be up to 27 bytes for legacy advertising mode.
    ManufacturerSpecificData(u16, &'a [u8]),
}

impl Advertisement<'_> {
    /// Gets the length of the advertisement payload, in bytes.
    ///
    /// This includes the length byte itself.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        use Advertisement::*;
        2 + match self {
            CompleteLocalName(n) => n.len(),
            ServiceData16BitUuid(_, b) | ManufacturerSpecificData(_, b) => 2 + b.len(),
            ServiceData32BitUuid(_, b) => 4 + b.len(),
            ServiceData128BitUuid(_, b) => 16 + b.len(),
        }
    }

    /// Gets the [CommonDataType] for this advertisement.
    const fn get_type(&self) -> CommonDataType {
        use Advertisement::*;
        match self {
            CompleteLocalName(_) => CommonDataType::CompleteLocalName,
            ServiceData16BitUuid(_, _) => CommonDataType::ServiceData16BitUuid,
            ServiceData32BitUuid(_, _) => CommonDataType::ServiceData32BitUuid,
            ServiceData128BitUuid(_, _) => CommonDataType::ServiceData128BitUuid,
            ManufacturerSpecificData(_, _) => CommonDataType::ManufacturerSpecificData,
        }
    }

    /// Serialize the advertisement into the given buffer, and return the number
    /// of bytes written.
    ///
    /// The maximum length of advertisements in legacy mode is 31 bytes.
    ///
    /// `bytes` must be at least [Self::len()] bytes.
    pub fn copy_into_slice(&self, bytes: &mut [u8]) -> usize {
        use Advertisement::*;
        let len = self.len();
        // Don't count the length byte.
        bytes[0] = (len - 1) as u8;
        bytes[1] = self.get_type() as u8;
        match self {
            CompleteLocalName(n) => {
                bytes[2..2 + n.len()].copy_from_slice(n.as_bytes());
            }
            ServiceData16BitUuid(u, b) | ManufacturerSpecificData(u, b) => {
                LittleEndian::write_u16(&mut bytes[2..], *u);
                bytes[4..4 + b.len()].copy_from_slice(b);
            }
            ServiceData32BitUuid(u, b) => {
                LittleEndian::write_u32(&mut bytes[2..], *u);
                bytes[6..6 + b.len()].copy_from_slice(b);
            }
            ServiceData128BitUuid(u, b) => {
                LittleEndian::write_u128(&mut bytes[2..], *u);
                bytes[18..18 + b.len()].copy_from_slice(b);
            }
        }
        len
    }
}
