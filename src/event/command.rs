use byteorder::{ByteOrder, LittleEndian};

/// Values returned by local version information query. Bluetooth Specification 5.0, Vol 2 Part E,
/// 7.4.1: Read Local Version Information Command
#[derive(Clone, Debug)]
pub struct LocalVersionInfo {
    pub hci_version: u8,
    pub hci_revision: u16,
    pub lmp_version: u8,
    pub manufacturer_name: u16,
    pub lmp_subversion: u16,
}

impl LocalVersionInfo {
    fn new<VE>(bytes: &[u8]) -> Result<LocalVersionInfo, ::event::Error<VE>> {
        if bytes.len() < 8 {
            return Err(::event::Error::BadLength(bytes.len(), 8));
        }

        Ok(LocalVersionInfo {
            hci_version: bytes[0],
            hci_revision: LittleEndian::read_u16(&bytes[1..]),
            lmp_version: bytes[3],
            manufacturer_name: LittleEndian::read_u16(&bytes[4..]),
            lmp_subversion: LittleEndian::read_u16(&bytes[6..]),
        })
    }
}

#[derive(Clone, Debug)]
pub enum ReturnParameters {
    None,
    ReadLocalVersion(LocalVersionInfo),
}

#[derive(Clone, Debug)]
pub struct CommandComplete {
    pub num_hci_command_packets: u8,
    pub return_params: ReturnParameters,
}

impl CommandComplete {
    pub fn new<VE>(bytes: &[u8]) -> Result<CommandComplete, ::event::Error<VE>> {
        if bytes.len() < 3 {
            return Err(::event::Error::BadLength(bytes.len(), 3));
        }

        let params = match ::opcode::OpCode(LittleEndian::read_u16(&bytes[1..])) {
            ::opcode::LOCAL_VERSION_INFO => {
                ReturnParameters::ReadLocalVersion(LocalVersionInfo::new(&bytes)?)
            }
            _ => ReturnParameters::None,
        };
        Ok(CommandComplete {
            num_hci_command_packets: bytes[0],
            return_params: params,
        })
    }
}
