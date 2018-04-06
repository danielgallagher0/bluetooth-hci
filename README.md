# BLE

This crate currently for illustrative purposes only, it is NOT
intended to implement the Bluetooth specification or provide a Rust
interface to generic BLE chips.  It is, however, intended to show how
one such implementation could be organized.

## Implementation

This crate defines a trait (`Controller`) that should be implemented
for a specific BLE chip.  Once that trait is implemented, the
functions from the `hci` module can be used to write to the chip.  The
implementation of `read` should use `event::parse_event` to convert
data into BLE events.

## Supported Events

This crate contains only the bare minimum of support for commands and
events right now.  Support for HCI ACL Data Packets and HCI
Synchronous Data Packets still needs to be determined.

See the [Bluetooth
Specification](https://www.bluetooth.org/DocMan/handlers/DownloadDoc.ashx?doc_id=421043)
for more (many, many more) details on what this crate should
eventually support.  Volume 2, Part E, section 7 is the most relevant
portion for this crate.
