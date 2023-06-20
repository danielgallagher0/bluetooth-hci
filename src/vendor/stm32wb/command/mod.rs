use crate::{
    host::{uart::CommandHeader, HciHeader},
    Controller, Opcode,
};

pub async fn write_command(controller: &mut impl Controller, opcode: Opcode, params: &[u8]) {
    const HEADER_LEN: usize = 4;
    let mut header = [0; HEADER_LEN];
    CommandHeader::new(opcode, params.len()).copy_into_slice(&mut header);

    controller.write(&header, params).await
}

macro_rules! impl_params {
    ($method:ident, $param_type:ident, $opcode:path) => {
        async fn $method(&mut self, params: &$param_type) {
            let mut bytes = [0; $param_type::LENGTH];
            params.copy_into_slice(&mut bytes);

            super::write_command(self, $opcode, &bytes).await
        }
    };
}

macro_rules! impl_value_params {
    ($method:ident, $param_type:ident, $opcode:path) => {
        async fn $method(&mut self, params: $param_type) {
            let mut bytes = [0; $param_type::LENGTH];
            params.copy_into_slice(&mut bytes);

            super::write_command(self, $opcode, &bytes).await
        }
    };
}

macro_rules! impl_validate_params {
    ($method:ident, $param_type:ident, $opcode:path) => {
        async fn $method(&mut self, params: &$param_type) -> Result<(), Error> {
            params.validate()?;

            let mut bytes = [0; $param_type::LENGTH];
            params.copy_into_slice(&mut bytes);

            super::write_command(self, $opcode, &bytes).await;

            Ok(())
        }
    };
}

macro_rules! impl_variable_length_params {
    ($method:ident, $param_type:ident, $opcode:path) => {
        async fn $method(&mut self, params: &$param_type) {
            let mut bytes = [0; $param_type::MAX_LENGTH];
            params.copy_into_slice(&mut bytes);

            super::write_command(self, $opcode, &bytes).await
        }
    };
}

macro_rules! impl_validate_variable_length_params {
    ($method:ident, $param_type:ident, $opcode:path) => {
        async fn $method(&mut self, params: &$param_type) -> Result<(), Error> {
            params.validate().map_err(nb::Error::Other)?;

            let mut bytes = [0; $param_type::MAX_LENGTH];
            let len = params.copy_into_slice(&mut bytes);

            self.write($opcode, &bytes[..len])
                .map_err(|e| Error::Comm(e))
        }
    };
    ($method:ident<$($genlife:lifetime),*>, $param_type:ident<$($lifetime:lifetime),*>, $opcode:path) => {
        async fn $method<$($genlife),*>(
            &mut self,
            params: &$param_type<$($lifetime),*>
        ) -> Result<(), Error> {
            params.validate()?;

            let mut bytes = [0; $param_type::MAX_LENGTH];
            params.copy_into_slice(&mut bytes);

            super::write_command(self, $opcode, &bytes).await;

            Ok(())
        }
    };
}

pub mod gap;
pub mod gatt;
pub mod hal;
pub mod l2cap;
