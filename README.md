# Bluetooth HCI Async

forked from [bluetooth_hci](https://github.com/danielgallagher0/bluetooth-hci)

[![Build Status](https://github.com/OueslatiGhaith/bluetooth-hci/actions/workflows/ci.yml/badge.svg)](https://github.com/OueslatiGhaith/bluetooth-hci/actions/workflows/ci.yml/badge.svg)

This crate defines a pure Rust implementation of the [Bluetooth Host-Controller Interface](https://github.com/STMicroelectronics/STM32CubeWB/) for the STM32WB family of microcontrollers. It defines commands
and events from the specification, and vendor-specific commands and events.

## Version

This crate aims to match the [latest firmware binaries](https://github.com/STMicroelectronics/STM32CubeWB/tree/master/Projects/STM32WB_Copro_Wireless_Binaries/STM32WB5x) released by ST. 

## Implementation

This crate defines a trait (`Controller`) that should be implemented
for a specific BLE chip. Any implementor can then be used as a
`host::uart::UartHci` to read and write to the chip.

    impl stm32wb_hci::Controller for MyController {
        async fn controller_write(&mut self, header: &[u8], payload: &[u8]) -> Result<(), Self::Error> {
            // implementation...
        }
        async fn controller_read_into(&mut self, buffer: &mut [u8]) -> Result<(), Self::Error> {
            // implementation...
        }
    }

The entire Bluetooth HCI is implemented in terms of these functions
that handle the low-level I/O. To read events, you can use the
`host::uart::UartHci` trait, which defines a `read` function. The easiest
way to specify the vendor-specific event type is via type inference:

    fn process_event(e: hci::event::Event<MyVendorEvent>) {
        // do stuff with e
    }
    // elsewhere...
    process_event(controller.read()?)