macro_rules! impl_params {
    ($method:ident, $param_type:ident, $opcode:path) => {
        async fn $method(&mut self, params: &$param_type) -> Result<(), Self::Error> {
            let mut bytes = [0; $param_type::LENGTH];
            params.copy_into_slice(&mut bytes);

            self.write($opcode, &bytes).await
        }
    };
}

macro_rules! impl_value_params {
    ($method:ident, $param_type:ident, $opcode:path) => {
        async fn $method(&mut self, params: $param_type) -> Result<(), Self::Error> {
            let mut bytes = [0; $param_type::LENGTH];
            params.copy_into_slice(&mut bytes);

            self.write($opcode, &bytes).await
        }
    };
}

macro_rules! impl_validate_params {
    ($method:ident, $param_type:ident, $opcode:path) => {
        async fn $method(&mut self, params: &$param_type) -> Result<(), Error<Self::Error>> {
            params.validate()?;

            let mut bytes = [0; $param_type::LENGTH];
            params.copy_into_slice(&mut bytes);

            self.write($opcode, &bytes)
                .await
                .map_err(|e| Error::Comm(e))
        }
    };
}

macro_rules! impl_variable_length_params {
    ($method:ident, $param_type:ident, $opcode:path) => {
        async fn $method(&mut self, params: &$param_type) -> Result<(), Self::Error> {
            let mut bytes = [0; $param_type::MAX_LENGTH];
            let len = params.copy_into_slice(&mut bytes);

            self.write($opcode, &bytes[..len]).await
        }
    };
}

macro_rules! impl_validate_variable_length_params {
    ($method:ident, $param_type:ident, $opcode:path) => {
        async fn $method(&mut self, params: &$param_type) -> Result<(), Error<Self::Error>> {
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
        ) -> Result<(), Error<Self::Error>> {
            params.validate()?;

            let mut bytes = [0; $param_type::MAX_LENGTH];
            let len = params.copy_into_slice(&mut bytes);

            self.write($opcode, &bytes[..len]).await
                .map_err(|e| Error::Comm(e))
        }
    };
}

pub mod gap;
pub mod gatt;
pub mod hal;
pub mod l2cap;
