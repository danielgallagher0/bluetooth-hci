//! Vendor specific commands for STM32WB family

pub mod command;
pub mod event;
pub mod opcode;

/// specify vendor specifi extensions for STM32WB family
pub struct Stm32wbTypes;
impl crate::Vendor for Stm32wbTypes {}

pub use crate::host::uart::CommandHeader;
pub use event::VendorError;

/// master trait that encompasses all commands, and communicats over UART
pub trait UartController:
    command::gap::GapCommands
    + command::gatt::GattCommands
    + command::hal::HalCommands
    + command::l2cap::L2capCommands
    + crate::host::uart::UartHci
{
}

impl<T> UartController for T where
    T: command::gap::GapCommands
        + command::gatt::GattCommands
        + command::hal::HalCommands
        + command::l2cap::L2capCommands
        + crate::host::uart::UartHci
{
}
