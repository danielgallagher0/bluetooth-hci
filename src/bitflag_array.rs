//! Implements an arbitrary-length bitfield.  The implementation and interface is similar to and
//! derived from [bitflags](https://crates.io/crates/bitflags).

// Re-export libcore using an alias so that the macros can work without
// requiring `extern crate core` downstream.
#[doc(hidden)]
pub extern crate core as _core;

/// Implements an arbitrary-length bitfield.  The implementation and interface is similar to and
/// derived from [bitflags](https://crates.io/crates/bitflags).
///
/// Instead of implementing the bitfield over an integral type, this implements it on an array of
/// bytes.  Each flag is defined using the byte and the mask _within that byte_.  It does not
/// support masks across bytes.
///
/// # Example
///
/// See [`ChannelClassification`] and [`event::command::CommandFlags`] for examples in this crate.
///
/// Basic usage is similar to [bitflags](https://crates.io/crates/bitflags):
///
/// ```
/// # #[macro_use]
/// # extern crate bluetooth_hci;
/// # fn main() {}
/// bitflag_array! {
///     #[derive(Clone)]
///     pub struct Flags : 3; // Bit field over a [u8; 3]
///     pub struct Flag;      // Name the internal struct
///
///     const ALPHA = 0, 0x01; // First byte, first bit
///     const BETA = 0, 0x02;
///     // ...
///     const THETA = 1, 0x01; // Second byte, first bit
///     // ...
///     const OMEGA = 2, 0x80; // Third byte, last bit
/// }
/// ```
///
/// A subset of the bitflags interface is implemented, including bitwise OR operations:
/// ```
/// # #[macro_use]
/// # extern crate bluetooth_hci;
/// # bitflag_array! {
/// #    #[derive(Clone)]
/// #    pub struct Flags : 3;
/// #    pub struct Flag;
/// #
/// #    const ALPHA = 0, 0x01;
/// #    const BETA = 0, 0x02;
/// #    const THETA = 1, 0x01;
/// #    const OMEGA = 2, 0x80;
/// # }
/// # fn main() {
/// let mut letters = Flags::ALPHA | Flags::BETA;
/// letters |= Flags::THETA;
/// assert_eq!(letters.bits(), [0x03, 0x01, 0x00]);
/// assert_eq!(letters.is_empty(), false);
/// assert_eq!(letters.is_set(Flags::OMEGA), false);
/// assert!(letters.contains(Flags::BETA | Flags::THETA));
/// # }
/// ```
#[macro_export]
macro_rules! bitflag_array {
    {
        $(#[$inner:ident $($args:tt)*])*
        pub struct $flags:ident : $size:expr;
        pub struct $flag:ident;

        $(
            $(#[$var_inner:ident $($var_args:tt)*])*
            const $var:ident = $octet:expr, $mask:expr;
        )+
    } => {
        $(#[$inner $($args)*])*
        pub struct $flags([u8; $size]);

        #[doc(hidden)]
        #[allow(missing_docs)]
        #[derive(Copy, Clone, Debug)]
        pub struct $flag {
            octet: usize,
            mask: u8,
        }

        impl $flags {
            $(
                $(#[$var_inner $($var_args)*])*
                pub const $var: $flag = $flag {
                    octet: $octet,
                    mask: $mask,
                };
            )+

            /// Attempts to create a bit field from the given byte array.  If any unknown bit is
            /// set, returns None.
            pub fn from_bits(bits: &[u8]) -> Option<$flags> {
                assert_eq!(bits.len(), $size);

                let all_flags = $flags::all();
                let all_bits = all_flags.bits();
                for i in 0..$size {
                    let provided_bits = bits[i];
                    let allowed_bits = all_bits[i];
                    if (provided_bits & !allowed_bits) != 0 {
                        return None;
                    }
                }

                let mut flags = $flags([0; $size]);
                flags.0.copy_from_slice(bits);
                Some(flags)
            }

            /// Copies the bitfield array into the given slice.  The slice must have exactly the
            /// right number of elements.
            pub fn copy_into_slice(&self, bytes: &mut [u8]) {
                assert_eq!(self.0.len(), bytes.len());
                bytes.copy_from_slice(&self.0);
            }

            /// Returns a bit field with all flags set.
            #[allow(deprecated)]
            #[allow(unused_doc_comments)]
            #[allow(unused_attributes)]
            pub fn all() -> $flags {
                let mut bits = [0; $size];
                $(
                    $(#[$var_inner $($var_args)*])*
                    {
                        bits[$octet] |= $mask;
                    }
                )+
                $flags(bits)
            }

            /// Returns a bit field with no flags set.
            pub fn empty() -> $flags {
                $flags([0; $size])
            }

            /// Returns a slice to the underlying representation of the bit field.
            pub fn bits(&self) -> &[u8] {
                &self.0
            }

            /// Returns true if no fields are set.
            pub fn is_empty(&self) -> bool {
                self.0.iter().all(|&x| x == 0)
            }

            /// Returns true if the flag is set in the bitfield.
            pub fn is_set(&self, flag: $flag) -> bool {
                (self.0[flag.octet] & flag.mask) != 0
            }

            /// Returns true if all flags from `flags` are set in the bitfield.
            pub fn contains(&self, flags: $flags) -> bool {
                self.0
                    .iter()
                    .zip(flags.0.iter())
                    .all(|(a, b)| (a & b) == *b)
            }
        }

        impl $crate::bitflag_array::_core::ops::BitOr for $flag {
            type Output = $flags;

            fn bitor(self, rhs: $flag) -> Self::Output {
                let mut flags = $flags([0; $size]);
                flags.0[self.octet] |= self.mask;
                flags.0[rhs.octet] |= rhs.mask;

                flags
            }
        }

        impl $crate::bitflag_array::_core::ops::BitOr<$flag> for $flags {
            type Output = $flags;

            fn bitor(mut self, rhs: $flag) -> Self::Output {
                self |= rhs;

                self
            }
        }

        impl $crate::bitflag_array::_core::ops::BitOrAssign<$flag> for $flags {
            fn bitor_assign(&mut self, rhs: $flag) {
                self.0[rhs.octet] |= rhs.mask;
            }
        }

        impl $crate::bitflag_array::_core::cmp::PartialEq<$flag> for $flags {
            fn eq(&self, rhs: &$flag) -> bool {
                for i in 0..$size {
                    if i == rhs.octet as usize {
                        if self.0[i] != rhs.mask {
                            return false;
                        }
                    } else if self.0[i] != 0 {
                        return false;
                    }
                }

                return true;
            }
        }

        impl $crate::bitflag_array::_core::cmp::PartialEq for $flags {
            fn eq(&self, rhs: &$flags) -> bool {
                self.0.iter().zip(rhs.0.iter()).all(|(a, b)| a == b)
            }
        }

        impl $crate::bitflag_array::_core::convert::From<$flag> for $flags {
            fn from(value: $flag) -> $flags {
                let mut flags = $flags([0; $size]);
                flags.0[value.octet] = value.mask;

                flags
            }
        }
    }
}
