use alloy_primitives::{Address, Bloom, Bytes, B256, U256};
use derivative::Derivative;
use reth::rpc::types::{
    engine::{
        BlobsBundleV1, ExecutionPayload, ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3,
    },
    Withdrawal,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct ValidationRequestBody {
    pub execution_payload: ExecutionPayloadValidation,
    pub blobs_bundle: BlobsBundleV1,
    pub message: BidTrace,
    pub signature: Bytes,
    #[serde_as(as = "DisplayFromStr")]
    pub registered_gas_limit: u64,
    #[serde(default)]
    pub parent_beacon_block_root: Option<B256>,
}

#[serde_as]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct BidTrace {
    #[serde_as(as = "DisplayFromStr")]
    pub slot: u64,
    pub parent_hash: B256,
    pub block_hash: B256,
    pub builder_pubkey: Bytes,
    pub proposer_pubkey: Bytes,
    pub proposer_fee_recipient: Address,
    #[serde_as(as = "DisplayFromStr")]
    pub gas_limit: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub gas_used: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub value: U256,
}

/// Structure to deserialize execution payloads sent according to the builder api spec
/// Numeric fields deserialized as decimals (unlike crate::eth::engine::ExecutionPayload)
#[serde_as]
#[derive(Derivative)]
#[derivative(Debug)]
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct ExecutionPayloadValidation {
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub state_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: Bloom,
    pub prev_randao: B256,
    #[serde_as(as = "DisplayFromStr")]
    pub block_number: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub gas_limit: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub gas_used: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub timestamp: u64,
    pub extra_data: Bytes,
    pub base_fee_per_gas: U256,
    pub block_hash: B256,
    #[derivative(Debug = "ignore")]
    pub transactions: Vec<Bytes>,
    pub withdrawals: Vec<WithdrawalValidation>,
    #[serde_as(as = "DisplayFromStr")]
    pub blob_gas_used: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub excess_blob_gas: u64,
}

/// Withdrawal object with numbers deserialized as decimals
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalValidation {
    /// Monotonically increasing identifier issued by consensus layer.
    #[serde_as(as = "DisplayFromStr")]
    pub index: u64,
    /// Index of validator associated with withdrawal.
    #[serde_as(as = "DisplayFromStr")]
    pub validator_index: u64,
    /// Target address for withdrawn ether.
    pub address: Address,
    /// Value of the withdrawal in gwei.
    #[serde_as(as = "DisplayFromStr")]
    pub amount: u64,
}

impl From<ExecutionPayloadValidation> for ExecutionPayload {
    fn from(val: ExecutionPayloadValidation) -> Self {
        ExecutionPayload::V3(ExecutionPayloadV3 {
            payload_inner: ExecutionPayloadV2 {
                payload_inner: ExecutionPayloadV1 {
                    parent_hash: val.parent_hash,
                    fee_recipient: val.fee_recipient,
                    state_root: val.state_root,
                    receipts_root: val.receipts_root,
                    logs_bloom: val.logs_bloom,
                    prev_randao: val.prev_randao,
                    block_number: val.block_number,
                    gas_limit: val.gas_limit,
                    gas_used: val.gas_used,
                    timestamp: val.timestamp,
                    extra_data: val.extra_data,
                    base_fee_per_gas: val.base_fee_per_gas,
                    block_hash: val.block_hash,
                    transactions: val.transactions,
                },
                withdrawals: val.withdrawals.into_iter().map(|w| w.into()).collect(),
            },
            blob_gas_used: val.blob_gas_used,
            excess_blob_gas: val.excess_blob_gas,
        })
    }
}

impl From<WithdrawalValidation> for Withdrawal {
    fn from(val: WithdrawalValidation) -> Self {
        Withdrawal {
            index: val.index,
            validator_index: val.validator_index,
            address: val.address,
            amount: val.amount,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALIDATION_REQUEST_BODY: &str = include_str!("../../tests/data/single_payload.json");
    #[test]
    fn test_can_parse_validation_request_body() {
        let _validation_request_body: ValidationRequestBody =
            serde_json::from_str(VALIDATION_REQUEST_BODY).unwrap();
    }
}
