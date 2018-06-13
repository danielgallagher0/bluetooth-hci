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

macro_rules! opcodes {
    (
        $(
            $_ogf_comment:ident = $ogf:expr;
            {
                $(pub const $var:ident = $ocf:expr;)+
            }
        )+
    ) => {
        $($(
            pub const $var: Opcode = Opcode::new($ogf, $ocf);
        )+)+
    }
}

opcodes! {
    LinkControl = 0x0001;
    {
        pub const DISCONNECT = 0x0006;
        pub const READ_REMOTE_VERSION_INFO = 0x001D;
    }

    ControllerOrBaseband = 0x0003;
    {
        pub const SET_EVENT_MASK = 0x0001;
        pub const RESET = 0x0003;
        pub const READ_TX_POWER_LEVEL = 0x002D;
    }

    InfoParam = 0x0004;
    {
        pub const READ_LOCAL_VERSION_INFO = 0x0001;
        pub const READ_LOCAL_SUPPORTED_COMMANDS = 0x0002;
        pub const READ_LOCAL_SUPPORTED_FEATURES = 0x0003;
        pub const READ_BD_ADDR = 0x0009;
    }

    StatusParam = 0x0005;
    {
        pub const READ_RSSI = 0x0005;
    }

    LeCommands = 0x0008;
    {
        pub const LE_SET_EVENT_MASK = 0x0001;
        pub const LE_READ_BUFFER_SIZE = 0x0002;
        pub const LE_READ_LOCAL_SUPPORTED_FEATURES = 0x0003;
        pub const LE_SET_RANDOM_ADDRESS = 0x0005;
        pub const LE_SET_ADVERTISING_PARAMETERS = 0x0006;
        pub const LE_READ_ADVERTISING_CHANNEL_TX_POWER = 0x0007;
        pub const LE_SET_ADVERTISING_DATA = 0x0008;
        pub const LE_SET_SCAN_RESPONSE_DATA = 0x0009;
        pub const LE_SET_ADVERTISE_ENABLE = 0x000A;
        pub const LE_SET_SCAN_PARAMETERS = 0x000B;
        pub const LE_SET_SCAN_ENABLE = 0x000C;
        pub const LE_CREATE_CONNECTION = 0x000D;
        pub const LE_CREATE_CONNECTION_CANCEL = 0x000E;
        pub const LE_READ_WHITE_LIST_SIZE = 0x000F;
        pub const LE_CLEAR_WHITE_LIST = 0x0010;
        pub const LE_ADD_DEVICE_TO_WHITE_LIST = 0x0011;
        pub const LE_REMOVE_DEVICE_FROM_WHITE_LIST = 0x0012;
        pub const LE_CONNECTION_UPDATE = 0x0013;
        pub const LE_SET_HOST_CHANNEL_CLASSIFICATION = 0x0014;
        pub const LE_READ_CHANNEL_MAP = 0x0015;
        pub const LE_READ_REMOTE_USED_FEATURES = 0x0016;
    }
}
