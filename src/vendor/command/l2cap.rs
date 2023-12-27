//! L2Cap-specific commands and types needed for those commands.

extern crate byteorder;

use crate::{
    types::{ConnectionInterval, ExpectedConnectionLength},
    Controller,
};
use byteorder::{ByteOrder, LittleEndian};

/// L2Cap-specific commands for the [`ActiveBlueNRG`](crate::ActiveBlueNRG).
pub trait L2capCommands {
    /// Send an L2CAP connection parameter update request from the peripheral to the central
    /// device.
    ///
    /// # Errors
    ///
    /// - Underlying communication errors.
    ///
    /// # Generated events
    ///
    /// A [command status](crate::event::Event::CommandStatus) event on the receipt of the command and
    /// an [L2CAP Connection Update
    /// Response](crate::event::BlueNRGEvent::L2CapConnectionUpdateResponse) event when the master
    /// responds to the request (accepts or rejects).
    async fn connection_parameter_update_request(
        &mut self,
        params: &ConnectionParameterUpdateRequest,
    );

    /// This command should be sent in response to the
    /// [`L2CapConnectionUpdateResponse`](crate::event::BlueNRGEvent::L2CapConnectionUpdateResponse)
    /// event from the controller. The accept parameter has to be set to true if the connection
    /// parameters given in the event are acceptable.
    ///
    /// # Errors
    ///
    /// Only underlying communication errors are reported.
    ///
    /// # Generated events
    ///
    /// A [Command
    /// Complete](crate::event::command::ReturnParameters::L2CapConnectionParameterUpdateResponse)
    /// event is generated.
    async fn connection_parameter_update_response(
        &mut self,
        params: &ConnectionParameterUpdateResponse,
    );
}

impl<T: Controller> L2capCommands for T {
    impl_params!(
        connection_parameter_update_request,
        ConnectionParameterUpdateRequest,
        crate::vendor::opcode::L2CAP_CONN_PARAM_UPDATE_REQ
    );

    impl_params!(
        connection_parameter_update_response,
        ConnectionParameterUpdateResponse,
        crate::vendor::opcode::L2CAP_CONN_PARAM_UPDATE_RESP
    );
}

/// Parameters for the
/// [`connection_parameter_update_request`](Commands::connection_parameter_update_request)
/// command.
pub struct ConnectionParameterUpdateRequest {
    /// Connection handle of the link which the connection parameter update request has to be sent.
    pub conn_handle: crate::ConnectionHandle,

    /// Defines the range of the connection interval.
    pub conn_interval: ConnectionInterval,
}

impl ConnectionParameterUpdateRequest {
    const LENGTH: usize = 10;

    fn copy_into_slice(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), Self::LENGTH);

        LittleEndian::write_u16(&mut bytes[0..], self.conn_handle.0);
        self.conn_interval.copy_into_slice(&mut bytes[2..10]);
    }
}

/// Parameters for the
/// [`connection_parameter_update_response`](Commands::connection_parameter_update_response)
/// command.
pub struct ConnectionParameterUpdateResponse {
    /// [Connection handle](crate::event::L2CapConnectionUpdateRequest::conn_handle) received in the
    /// [`L2CapConnectionUpdateRequest`](crate::event::BlueNRGEvent::L2CapConnectionUpdateRequest)
    /// event.
    pub conn_handle: crate::ConnectionHandle,

    /// [Connection interval](crate::event::L2CapConnectionUpdateRequest::conn_interval) received in
    /// the
    /// [`L2CapConnectionUpdateRequest`](crate::event::BlueNRGEvent::L2CapConnectionUpdateRequest)
    /// event.
    pub conn_interval: ConnectionInterval,

    /// Expected length of connection event needed for this connection.
    pub expected_connection_length_range: ExpectedConnectionLength,

    /// [Identifier](crate::event::L2CapConnectionUpdateRequest::identifier) received in the
    /// [`L2CapConnectionUpdateRequest`](crate::event::BlueNRGEvent::L2CapConnectionUpdateRequest)
    /// event.
    pub identifier: u8,

    /// True if the parameters from the
    /// [event](crate::event::BlueNRGEvent::L2CapConnectionUpdateRequest) are acceptable.
    pub accepted: bool,
}

impl ConnectionParameterUpdateResponse {
    const LENGTH: usize = 16;

    fn copy_into_slice(&self, bytes: &mut [u8]) {
        assert_eq!(bytes.len(), Self::LENGTH);

        LittleEndian::write_u16(&mut bytes[0..], self.conn_handle.0);
        self.conn_interval.copy_into_slice(&mut bytes[2..10]);
        self.expected_connection_length_range
            .copy_into_slice(&mut bytes[10..14]);
        bytes[14] = self.identifier;
        bytes[15] = self.accepted as u8;
    }
}
