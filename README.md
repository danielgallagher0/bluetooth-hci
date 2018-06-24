# Bluetooth HCI

[![Build
Status](https://travis-ci.org/danielgallagher0/bluetooth-hci.svg?branch=master)](https://travis-ci.org/danielgallagher0/bluetooth-hci)

This crate is currently for illustrative purposes only, though it may
grow into a nice implementation of the Bluetooth HCI for use by
Bluetooth hosts. Comments and critiques are welcome!

## Version

This crate can support versions 4.1, 4.2, and 5.0 of the Bluetooth
specification. By default, it supports version 4.1. To enable the
other version, add the following to your `Cargo.toml`:

    [dependencies.bluetooth-hci]
    features = "version-4-2"

or

    [dependencies.bluetooth-hci]
    features = "version-5-0"

## Implementation

This crate defines a trait (`Controller`) that should be implemented
for a specific BLE chip.  Any implementor can then be used as a
`host::uart::Hci` to read and write to the chip.

## Supported Events

This crate contains only the partial support for commands and events
right now.  The only commands and events (as of June 2018) are those
used by the [BlueNRG](https://github.com/danielgallagher0/bluenrg)
chip.  Support for HCI ACL Data Packets and HCI Synchronous Data
Packets still needs to be determined.

See the [Bluetooth
Specification](https://www.bluetooth.org/DocMan/handlers/DownloadDoc.ashx?doc_id=421043)
for more (many, many more) details on what this crate should
eventually support.  Volume 2, Part E, section 7 is the most relevant
portion for this crate.
