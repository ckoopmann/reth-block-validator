use jsonrpsee::{
    core::error::Error,
    http_client::{HttpClient, HttpClientBuilder},
    server::ServerBuilder,
};
use reth::primitives::{Address, Block, Bloom, Bytes, Header, B256, U256};
use reth::rpc::compat::engine::payload::try_into_block;
use reth::{
    providers::test_utils::{ExtendedAccount, MockEthProvider},
    revm::primitives::FixedBytes,
};
use reth_block_validator::rpc::{
    BidTrace, ExecutionPayloadValidation, ValidationApiClient, ValidationApiServer,
    ValidationRequestBody,
};
use reth_block_validator::ValidationApi;
use std::time::{SystemTime, UNIX_EPOCH};

const VALIDATION_REQUEST_BODY: &str = include_str!("../../tests/data/single_payload.json");

#[tokio::test(flavor = "multi_thread")]
async fn test_unknown_parent_hash() {
    let client = get_client(None).await;
    let validation_request_body: ValidationRequestBody =
        serde_json::from_str(VALIDATION_REQUEST_BODY).unwrap();
    let result = ValidationApiClient::validate_builder_submission_v2(
        &client,
        validation_request_body.clone(),
    )
    .await;
    let expected_message = format!(
        "Block parent [hash:{:?}] is not known.",
        validation_request_body.execution_payload.parent_hash
    );
    let error_message = get_call_error_message(result.unwrap_err()).unwrap();
    assert_eq!(error_message, expected_message);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_valid_block() {
    let provider = MockEthProvider::default();
    let client = get_client(Some(provider.clone())).await;

    let base_fee_per_gas = 1_000_000_000;
    let start = SystemTime::now();
    let timestamp = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    println!("timestamp: {:?}", timestamp);

    let gas_limit = 1_000_000;
    let parent_block = add_block(provider.clone(), gas_limit, base_fee_per_gas);
    let parent_block_hash = parent_block.hash_slow();

    let fee_recipient = Address::random();
    provider.add_account(fee_recipient, ExtendedAccount::new(0, U256::from(0)));

    let validation_request_body = generate_validation_request_body(
        parent_block,
        parent_block_hash,
        fee_recipient,
        timestamp + 10,
        base_fee_per_gas,
    );

    let result = ValidationApiClient::validate_builder_submission_v2(
        &client,
        validation_request_body.clone(),
    )
    .await;

    println!("result: {:?}", result);
    assert!(result.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wrong_hash() {
    let client = get_client(None).await;

    let validation_request_body: ValidationRequestBody =
        serde_json::from_str(VALIDATION_REQUEST_BODY).unwrap();
    let old_timestamp = format!("{:}", validation_request_body.execution_payload.timestamp);
    let new_timestamp = "1234567";

    let validation_request_body_wrong_timestamp: ValidationRequestBody =
        serde_json::from_str(&VALIDATION_REQUEST_BODY.replace(&old_timestamp, new_timestamp))
            .unwrap();
    let result = ValidationApiClient::validate_builder_submission_v2(
        &client,
        validation_request_body_wrong_timestamp,
    )
    .await;
    let error_message = get_call_error_message(result.unwrap_err()).unwrap();
    assert!(error_message.contains("blockhash mismatch"));
}

async fn get_client(provider: Option<MockEthProvider>) -> HttpClient {
    let server_addr = start_server(provider).await;
    let uri = format!("http://{}", server_addr);
    HttpClientBuilder::default().build(uri).unwrap()
}

async fn start_server(provider: Option<MockEthProvider>) -> std::net::SocketAddr {
    let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let provider = provider.unwrap_or_default();
    let api = ValidationApi::new(provider);
    let server_handle = server.start(api.into_rpc());

    tokio::spawn(server_handle.stopped());

    addr
}

fn get_call_error_message(err: Error) -> Option<String> {
    match err {
        Error::Call(error_obj) => Some(error_obj.message().to_string()),
        _ => None,
    }
}

fn add_block(provider: MockEthProvider, gas_limit: u64, base_fee_per_gas: u64) -> Block {
    let mut parent_payload = ExecutionPayloadValidation::default();
    parent_payload.gas_limit = 1_000_000;
    parent_payload.base_fee_per_gas = U256::from(base_fee_per_gas);
    let parent_block =
        try_into_block(parent_payload.clone().into(), None).expect("failed to create block");
    let parent_block_hash = parent_block.header.hash_slow();
    provider.add_block(parent_block_hash, parent_block.clone());
    return parent_block;
}

fn generate_validation_request_body(
    parent_block: Block,
    parent_block_hash: FixedBytes<32>,
    fee_recipient: Address,
    timestamp: u64,
    base_fee_per_gas: u64,
) -> ValidationRequestBody {
    let mut validation_request_body = ValidationRequestBody::default();
    validation_request_body.execution_payload.fee_recipient = fee_recipient;
    validation_request_body.execution_payload.base_fee_per_gas = U256::from(base_fee_per_gas);
    validation_request_body.execution_payload.timestamp = timestamp;
    validation_request_body.execution_payload.parent_hash = parent_block_hash;
    validation_request_body.execution_payload.block_number = parent_block.header.number + 1;
    validation_request_body.execution_payload.gas_limit = parent_block.gas_limit;
    validation_request_body.message.gas_limit = parent_block.gas_limit;
    validation_request_body.message.parent_hash = parent_block_hash;
    let block = try_into_block(
        validation_request_body.execution_payload.clone().into(),
        None,
    )
    .expect("failed to create block");
    let sealed_block = block.seal_slow();
    validation_request_body.execution_payload.block_hash = sealed_block.hash();
    validation_request_body.message.block_hash = sealed_block.hash();
    validation_request_body
}
