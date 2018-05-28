mod ogf {
    pub const LINK_CONTROL: u16 = 0x0001;
    pub const CONTROLLER_OR_BASEBAND: u16 = 0x0003;
    pub const INFO_PARAM: u16 = 0x0004;
}

mod ocf {
    // Link control commands
    pub const DISCONNECT: u16 = 0x0006;
    pub const READ_REMOTE_VERSION_INFO: u16 = 0x001D;

    // Controller or Baseband commands
    pub const SET_EVENT_MASK: u16 = 0x0001;
    pub const RESET: u16 = 0x0003;
    pub const READ_TX_POWER_LEVEL: u16 = 0x002D;

    // Info commands
    pub const READ_LOCAL_VERSION_INFO: u16 = 0x0001;
    pub const READ_LOCAL_SUPPORTED_COMMANDS: u16 = 0x0002;
}

/// Newtype wrapper for a Bluetooth Opcode. Opcodes are used to indicate which command to send to
/// the Controller as well as which command results are returned by the Command Complete and Command
/// Status events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opcode(pub u16);

impl Opcode {
    /// Create an opcode from the OGF (Opcode group field) and OCF (Opcode command field).
    pub const fn new(ogf: u16, ocf: u16) -> Opcode {
        Opcode((ogf << 10) | (ocf & 0x03ff))
    }

    /// Return the OGF (Opcode group field) of the opcode.
    pub fn ogf(&self) -> u16 {
        self.0 >> 10
    }

    /// Return the OCF (Opcode command field) of the opcode.
    pub fn ocf(&self) -> u16 {
        self.0 & 0x03ff
    }
}

pub const DISCONNECT: Opcode = Opcode::new(ogf::LINK_CONTROL, ocf::DISCONNECT);
pub const READ_REMOTE_VERSION_INFO: Opcode =
    Opcode::new(ogf::LINK_CONTROL, ocf::READ_REMOTE_VERSION_INFO);

pub const SET_EVENT_MASK: Opcode = Opcode::new(ogf::CONTROLLER_OR_BASEBAND, ocf::SET_EVENT_MASK);
pub const RESET: Opcode = Opcode::new(ogf::CONTROLLER_OR_BASEBAND, ocf::RESET);
pub const READ_TX_POWER_LEVEL: Opcode =
    Opcode::new(ogf::CONTROLLER_OR_BASEBAND, ocf::READ_TX_POWER_LEVEL);

pub const READ_LOCAL_VERSION_INFO: Opcode =
    Opcode::new(ogf::INFO_PARAM, ocf::READ_LOCAL_VERSION_INFO);
pub const READ_LOCAL_SUPPORTED_COMMANDS: Opcode =
    Opcode::new(ogf::INFO_PARAM, ocf::READ_LOCAL_SUPPORTED_COMMANDS);
