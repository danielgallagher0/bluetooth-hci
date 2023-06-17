//! Vendor specific commands for STM32WB family

pub mod command;
pub mod event;
pub mod opcode;

/// specify vendor specifi extensions for STM32WB family
pub struct Stm32wbTypes;
impl crate::Vendor for Stm32wbTypes {
    type Status = event::Status;
    type Event = event::Stm32Wb5xEvent;
}
