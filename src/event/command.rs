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

fn as_u16(lsb: u8, msb: u8) -> u16 {
    ((msb as u16) << 8) | (lsb as u16)
}

impl LocalVersionInfo {
    fn new(bytes: &[u8]) -> Result<LocalVersionInfo, ::event::Error> {
        if bytes.len() < 8 {
            return Err(::event::Error::BadLength(bytes.len(), 8));
        }

        Ok(LocalVersionInfo {
            hci_version: bytes[0],
            hci_revision: as_u16(bytes[1], bytes[2]),
            lmp_version: bytes[3],
            manufacturer_name: as_u16(bytes[4], bytes[5]),
            lmp_subversion: as_u16(bytes[6], bytes[7]),
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
    pub fn new(bytes: &[u8]) -> Result<CommandComplete, ::event::Error> {
        if bytes.len() < 3 {
            return Err(::event::Error::BadLength(bytes.len(), 3));
        }

        let params = match as_u16(bytes[1], bytes[2]) {
            ::opcode::LOCAL_VERSION_INFO => {
                ReturnParameters::ReadLocalVersion(LocalVersionInfo::new(&bytes[3..])?)
            }
            _ => ReturnParameters::None,
        };
        Ok(CommandComplete {
            num_hci_command_packets: bytes[0],
            return_params: params,
        })
    }
}
