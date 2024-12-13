use alloy_primitives::{keccak256, Address, B256, U256};
use jsonrpsee::core::RpcResult;
use reth::{
    beacon_consensus::EthBeaconConsensus,
    chainspec::HOLESKY,
    consensus::Consensus,
    primitives::{Receipts, SealedBlock, TransactionSigned},
    providers::{
        AccountReader, BlockExecutionInput, BlockReaderIdExt, ChainSpecProvider, ExecutionOutcome,
        HeaderProvider, StateProviderFactory, WithdrawalsProvider,
    },
    revm::{database::StateProviderDatabase, db::BundleState},
    rpc::{
        compat::engine::payload::try_into_sealed_block,
        result::ToRpcResult,
        types::{
            engine::{BlobsBundleV1, CancunPayloadFields, ExecutionPayloadSidecar},
            TransactionTrait,
        },
    },
};
use reth_evm::execute::{BatchExecutor, BlockExecutorProvider};
use reth_node_ethereum::EthExecutorProvider;
use reth_tracing::tracing;
use std::{sync::Arc, time::Instant};
use uuid::Uuid;

use super::result::internal_rpc_err;
use crate::rpc::types::*;
use crate::rpc::utils::*;

pub struct ValidationRequest<Provider> {
    request_id: Uuid,
    start_time: Instant,
    request_body: ValidationRequestBody,
    provider: Provider,
}

impl<Provider> ValidationRequest<Provider> {
    pub fn new(
        request_body: ValidationRequestBody,
        provider: Provider,
    ) -> ValidationRequest<Provider> {
        let request_id = Uuid::new_v4();
        let start_time = Instant::now();
        tracing::info!(block_hash = ?request_body.message.block_hash, ?request_id, "Received Validation Request");
        Self {
            request_id,
            start_time,
            request_body,
            provider,
        }
    }
}

impl<Provider> ValidationRequest<Provider>
where
    Provider: BlockReaderIdExt
        + ChainSpecProvider
        + StateProviderFactory
        + HeaderProvider
        + AccountReader
        + WithdrawalsProvider
        + 'static,
{
    pub fn validate(&self) -> RpcResult<()> {
        self.validate_inner()
            .inspect_err(|error| {
                tracing::warn!(
                    request_id = self.request_id.to_string(),
                    ?error,
                    time_elapsed = self.start_time.elapsed().as_micros(),
                    "Validation failed"
                );
            })
            .inspect(|_| {
                tracing::info!(
                    request_id = self.request_id.to_string(),
                    time_elapsed = self.start_time.elapsed().as_micros(),
                    "Validation successful"
                );
            })
    }

    fn validate_inner(&self) -> RpcResult<()> {
        self.trace_validation_step(self.check_gas_limit(), "Check Gas Limit")?;

        self.trace_validation_step(
            self.compare_message_execution_payload(),
            "Message / Payload comparison",
        )?;

        let block = self.trace_validation_step(self.parse_block(), "Block parsing")?;

        self.trace_validation_step(self.validate_header(&block), "Full validation")?;

        let state = self.trace_validation_step(
            self.execute_and_verify_block(&block),
            "Execute and Verify Block",
        )?;
        self.trace_validation_step(self.verify_state_root(&block, &state), "Verify State Root")?;
        self.trace_validation_step(
            self.check_proposer_payment(&block, &state),
            "Check Proposer Payment",
        )?;
        Ok(())
    }

    fn trace_validation_step<T>(&self, result: RpcResult<T>, name: &str) -> RpcResult<T> {
        result
            .inspect_err(|error| {
                tracing::debug!(
                    request_id = self.request_id.to_string(),
                    ?error,
                    time_elapsed = self.start_time.elapsed().as_micros(),
                    "{}",
                    name.to_string() + " failed"
                )
            })
            .inspect(|_| {
                tracing::debug!(
                    request_id = self.request_id.to_string(),
                    time_elapsed = self.start_time.elapsed().as_micros(),
                    "{}",
                    name.to_string() + " succeeded"
                )
            })
    }

    fn compare_message_execution_payload(&self) -> RpcResult<()> {
        compare_values(
            "ParentHash",
            self.request_body.message.parent_hash,
            self.request_body.execution_payload.parent_hash,
        )?;
        compare_values(
            "BlockHash",
            self.request_body.message.block_hash,
            self.request_body.execution_payload.block_hash,
        )?;
        compare_values(
            "GasLimit",
            self.request_body.message.gas_limit,
            self.request_body.execution_payload.gas_limit,
        )?;
        compare_values(
            "GasUsed",
            self.request_body.message.gas_used,
            self.request_body.execution_payload.gas_used,
        )
    }

    fn parse_block(&self) -> RpcResult<SealedBlock> {
        let sidecar = ExecutionPayloadSidecar::v3(CancunPayloadFields {
            parent_beacon_block_root: self.request_body.parent_beacon_block_root.unwrap(),
            versioned_hashes: get_blob_versioned_hashes(&self.request_body.blobs_bundle),
        });

        try_into_sealed_block(self.request_body.execution_payload.clone().into(), &sidecar)
            .to_rpc_result()
    }

    fn validate_header(&self, block: &SealedBlock) -> RpcResult<()> {
        let consensus = Arc::new(EthBeaconConsensus::new(HOLESKY.clone()));

        consensus
            .validate_header(block)
            .map_err(|e| internal_rpc_err(format!("Error validating header: {:}", e)))?;

        consensus
            .validate_block_pre_execution(block)
            .map_err(|e| internal_rpc_err(format!("Error validating block: {:}", e)))?;

        Ok(())
    }

    fn execute_and_verify_block(&self, block: &SealedBlock) -> RpcResult<ExecutionOutcome> {
        let state_provider = self.provider.latest().to_rpc_result()?;
        // TODO: figure out spec
        let executor_provider = EthExecutorProvider::ethereum(HOLESKY.clone());

        let mut executor =
            executor_provider.batch_executor(StateProviderDatabase::new(&state_provider));

        let unsealed_block =
            block
                .clone()
                .unseal()
                .with_recovered_senders()
                .ok_or(internal_rpc_err(
                    "Error recovering senders from block, cannot execute block",
                ))?;

        // Note: Setting total difficulty to U256::MAX makes this incompatible with pre merge POW blocks
        let input = BlockExecutionInput {
            block: &unsealed_block,
            total_difficulty: U256::MAX,
        };

        executor
            .execute_and_verify_one(input)
            .map_err(|e| internal_rpc_err(format!("Error executing transactions: {:}", e)))?;

        let outcome = executor.finalize();

        Ok(outcome)
    }

    fn verify_state_root(&self, block: &SealedBlock, outcome: &ExecutionOutcome) -> RpcResult<()> {
        let state_provider = self.provider.latest().to_rpc_result()?;
        let state_root = state_provider
            .state_root(outcome.hash_state_slow())
            .map_err(|e| internal_rpc_err(format!("Error computing state root: {e:?}")))?;

        if state_root != block.state_root {
            return Err(internal_rpc_err(format!(
                "State root mismatch. Expected: {}. Received: {}",
                state_root, block.state_root
            )));
        }

        Ok(())
    }

    fn check_proposer_payment(
        &self,
        block: &SealedBlock,
        state: &ExecutionOutcome,
    ) -> RpcResult<()> {
        let expected_payment = &self.request_body.message.value;
        let fee_recipient = &self.request_body.message.proposer_fee_recipient;

        if check_proposer_balance_change(state.state(), fee_recipient, expected_payment) {
            return Ok(());
        }

        check_proposer_payment_in_last_transaction(
            &block.body.transactions[..],
            state.receipts(),
            fee_recipient,
            expected_payment,
        )
    }

    fn check_gas_limit(&self) -> RpcResult<()> {
        let parent_hash = &self.request_body.execution_payload.parent_hash;
        let registered_gas_limit = self.request_body.registered_gas_limit;
        let block_gas_limit = self.request_body.execution_payload.gas_limit;

        let parent = self
            .provider
            .header(parent_hash)
            .to_rpc_result()?
            .ok_or(internal_rpc_err(format!(
                "Parent block with hash {} not found",
                parent_hash
            )))?;

        tracing::debug!(request_id=self.request_id.to_string(), parent_hash = %parent_hash, parent_gas_limit = parent.gas_limit, registered_gas_limit = registered_gas_limit, block_gas_limit = block_gas_limit, "Checking gas limit");

        // Prysm has a bug where it registers validators with a desired gas limit
        // of 0. Some builders treat these as desiring gas limit 30_000_000. As a
        // workaround, whenever the desired gas limit is 0, we accept both the
        // limit as calculated with a desired limit of 0, and builders which fall
        // back to calculating with the default 30_000_000.
        // TODO: Review if we still need this
        if registered_gas_limit == 0
            && block_gas_limit == calc_gas_limit(parent.gas_limit, 30_000_000)
        {
            tracing::debug!(request_id=self.request_id.to_string(), parent_hash = %parent_hash, ?registered_gas_limit, ?block_gas_limit, "Registered gas limit is 0, accepting block with gas limit 30_000_000");
            return Ok(());
        }
        let calculated_gas_limit = calc_gas_limit(parent.gas_limit, registered_gas_limit);

        if calculated_gas_limit == block_gas_limit {
            tracing::debug!(request_id=self.request_id.to_string(), parent_hash = %parent_hash, ?registered_gas_limit, ?block_gas_limit, "Registered gas limit > 0, Correct gas limit set");
            return Ok(());
        }

        tracing::debug!(request_id=self.request_id.to_string(), parent_hash = %parent_hash, ?registered_gas_limit, ?block_gas_limit, ?calculated_gas_limit, "Incorrect gas limit set");

        Err(internal_rpc_err(format!(
            "Incorrect gas limit set, expected: {}, got: {}",
            calculated_gas_limit, block_gas_limit
        )))
    }
}

fn check_proposer_payment_in_last_transaction(
    transactions: &[TransactionSigned],
    receipts: &Receipts,
    fee_recipient: &Address,
    expected_payment: &U256,
) -> RpcResult<()> {
    if receipts.is_empty() || receipts[0].is_empty() {
        return Err(internal_rpc_err(
            "No receipts in block to verify proposer payment",
        ));
    }
    let receipts = &receipts[0];

    let num_transactions = transactions.len();
    if num_transactions == 0 {
        return Err(internal_rpc_err(
            "No transactions in block to verify proposer payment",
        ));
    }
    if num_transactions != receipts.len() {
        return Err(internal_rpc_err(format!(
            "Number of receipts ({}) does not match number of transactions ({})",
            receipts.len(),
            num_transactions
        )));
    }

    let proposer_payment_tx = transactions[num_transactions - 1].clone();
    if proposer_payment_tx.to() != Some(*fee_recipient) {
        return Err(internal_rpc_err(format!(
            "Proposer payment tx to address {:?} does not match fee recipient {}",
            proposer_payment_tx.to(),
            fee_recipient
        )));
    }

    if proposer_payment_tx.value() != *expected_payment {
        return Err(internal_rpc_err(format!(
            "Proposer payment tx value {} does not match expected payment {}",
            proposer_payment_tx.value(),
            expected_payment
        )));
    }

    let proposer_payment_receipt = receipts[num_transactions - 1]
        .clone()
        .ok_or_else(|| internal_rpc_err("Proposer payment receipt not found in block receipts"))?;
    if !proposer_payment_receipt.success {
        return Err(internal_rpc_err(format!(
            "Proposer payment tx failed: {:?}",
            proposer_payment_receipt
        )));
    }

    Ok(())
}

fn check_proposer_balance_change(
    output_state: &BundleState,
    fee_recipient: &Address,
    expected_payment: &U256,
) -> bool {
    let fee_receiver_account_state = match output_state.state.get(fee_recipient) {
        Some(account) => account,
        None => return false,
    };
    let fee_receiver_account_after = match fee_receiver_account_state.info.clone() {
        Some(account) => account,
        None => return false,
    };
    let fee_receiver_account_before = fee_receiver_account_state
        .original_info
        .clone()
        .unwrap_or_default();

    fee_receiver_account_after.balance >= (fee_receiver_account_before.balance + expected_payment)
}

fn get_blob_versioned_hashes(bundle: &BlobsBundleV1) -> Vec<B256> {
    bundle
        .commitments
        .iter()
        .map(|commitment| {
            let mut bytes = vec![1]; // 0x01 prefix
            bytes.extend_from_slice(commitment.as_ref());
            keccak256(bytes)
        })
        .collect()
}
