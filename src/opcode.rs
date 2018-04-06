mod ogf {
    pub const INFO_PARAM: u16 = 0x0004;
}

mod ocf {
    pub const LOCAL_VERSION_INFO: u16 = 0x0001;
}

const fn pack(ogf: u16, ocf: u16) -> u16 {
    (ogf << 10) | (ocf & 0x03ff)
}

pub const LOCAL_VERSION_INFO: u16 = pack(ogf::INFO_PARAM, ocf::LOCAL_VERSION_INFO);
