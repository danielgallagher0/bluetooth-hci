# Bluetooth HCI Async

forked from [bluetooth_hci](https://github.com/danielgallagher0/bluetooth-hci)

[![Build
Status](https://travis-ci.org/danielgallagher0/bluetooth-hci.svg?branch=master)](https://travis-ci.org/danielgallagher0/bluetooth-hci)

This crate defines a pure Rust implementation of the Bluetooth
Host-Controller Interface for bare metal devices. It defines commands
and events from the specification, and requires specific chips to
define vendor-specific commands and events.

## Version

This crate can support versions 4.1, 4.2, and 5.0 of the Bluetooth
specification. By default, it supports version 4.1. To enable another
version, add the following to your `Cargo.toml`:

    [dependencies.bluetooth-hci]
    features = "version-4-2"

or

    [dependencies.bluetooth-hci]
    features = "version-5-0"

## Implementation

This crate defines a trait (`Controller`) that should be implemented
for a specific BLE chip. Any implementor can then be used as a
`host::uart::Hci` to read and write to the chip.

    impl bluetooth_hci_async::Controller for MyController {
        type Error = BusError;
        type Header = bluetooth_hci_async::host::uart::CommandHeader;
        async fn write(&mut self, header: &[u8], payload: &[u8]) -> Result<(), Self::Error> {
            // implementation...
        }
        async fn read_into(&mut self, buffer: &mut [u8]) -> Result<(), Self::Error> {
            // implementation...
        }
        async fn peek(&mut self, n: usize) -> Result<u8, Self::Error> {
            // implementation...
        }
    }

The entire Bluetooth HCI is implemented in terms of these functions
that handle the low-level I/O. To read events, you can use the
`host::uart::Hci` trait, which defines a `read` function. The easiest
way to specify the vendor-specific event type is via type inference:

    fn process_event(e: hci::event::Event<MyVendorEvent>) {
        // do stuff with e
    }
    // elsewhere...
    process_event(controller.read()?)

## Supported Commands and Events

This crate contains only partial support for commands and events right
now. The only commands and events (as of September 2018) are those
used by the [BlueNRG](https://github.com/danielgallagher0/bluenrg)
chip. Support for HCI ACL Data Packets and HCI Synchronous Data
Packets still needs to be determined.

See the [Bluetooth
Specification](https://www.bluetooth.org/DocMan/handlers/DownloadDoc.ashx?doc_id=421043)
for more (many, many more) details on what this crate should
eventually support. Volume 2, Part E, section 7 is the most relevant
portion for this crate.
