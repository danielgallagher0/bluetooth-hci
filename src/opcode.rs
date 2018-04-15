mod ogf {
    pub const INFO_PARAM: u16 = 0x0004;
}

mod ocf {
    pub const LOCAL_VERSION_INFO: u16 = 0x0001;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpCode(pub u16);

impl OpCode {
    pub const fn new(ogf: u16, ocf: u16) -> OpCode {
        OpCode((ogf << 10) | (ocf & 0x03ff))
    }

    pub fn ogf(&self) -> u16 {
        self.0 >> 10
    }

    pub fn ocf(&self) -> u16 {
        self.0 & 0x03ff
    }
}

pub const LOCAL_VERSION_INFO: OpCode = OpCode::new(ogf::INFO_PARAM, ocf::LOCAL_VERSION_INFO);
