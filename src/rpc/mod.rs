pub use crate::rpc::api::{ValidationApiClient, ValidationApiServer};
use jsonrpsee::proc_macros::rpc;
use reth::{
    providers::{
        AccountReader, BlockReaderIdExt, ChainSpecProvider, HeaderProvider, StateProviderFactory,
        WithdrawalsProvider,
    },
    rpc::server_types::eth::EthResult,
};
pub use types::*;
use validation::ValidationRequest;

mod api;
mod result;
mod types;
mod utils;
mod validation;

#[rpc(server, namespace = "flashbots")]
pub trait ValidationRpcExtApi {
    #[method(name = "validateBuilderSubmissionV3")]
    fn validate_builder_submission_v3(&self, request_body: ValidationRequestBody) -> EthResult<()>;
}

pub struct ValidationRpcExt<Provider> {
    pub provider: Provider,
}

impl<Provider> ValidationRpcExtApiServer for ValidationRpcExt<Provider>
where
    Provider: BlockReaderIdExt
        + ChainSpecProvider
        + StateProviderFactory
        + HeaderProvider
        + AccountReader
        + WithdrawalsProvider
        + Clone
        + 'static,
{
    /// Validates a block submitted to the relay
    fn validate_builder_submission_v3(&self, request_body: ValidationRequestBody) -> EthResult<()> {
        let request = ValidationRequest::new(request_body, self.provider.clone());
        let _ = request.validate();
        Ok(())
    }
}

impl<Provider> std::fmt::Debug for ValidationRpcExt<Provider> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidationApi").finish_non_exhaustive()
    }
}
