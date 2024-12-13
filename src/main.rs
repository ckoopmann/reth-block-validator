//! Reth RPC extension to add endpoint for builder payload validation
//!
//! Run with
//!
//! ```not_rust
//! RUST_LOG=info cargo run -- node --full --metrics 127.0.0.1:9001 --http --enable-ext
//! ```
//!
//! This installs an additional RPC method that can be queried using the provided sample rpc
//! payload
//!
//! ```sh
//! curl --location 'localhost:8545/' --header 'Content-Type: application/json' --data @test/data/rpc_payload.json
//! ```
use clap::Parser;
use reth::{chainspec::EthereumChainSpecParser, cli::Cli};
use reth_node_ethereum::EthereumNode;
use rpc::{ValidationRpcExt, ValidationRpcExtApiServer};

mod rpc;

fn main() {
    Cli::<EthereumChainSpecParser, RethCliValidationExt>::parse()
        .run(|builder, args| async move {
            let handle = builder
                .node(EthereumNode::default())
                .extend_rpc_modules(move |ctx| {
                    if !args.enable_ext {
                        return Ok(());
                    }
                    let provider = ctx.provider().clone();
                    let ext = ValidationRpcExt { provider };
                    ctx.modules.merge_configured(ext.into_rpc())?;

                    Ok(())
                })
                .launch()
                .await?;

            handle.wait_for_node_exit().await
        })
        .unwrap();
}

/// Our custom cli args extension that adds one flag to reth default CLI.
#[derive(Debug, Clone, Copy, Default, clap::Args)]
struct RethCliValidationExt {
    /// CLI flag to enable the txpool extension namespace
    #[arg(long)]
    pub enable_ext: bool,
}
