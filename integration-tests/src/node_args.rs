//! Renders a node's command line from the harness configs. The node parses it
//! with clap, so a flag the node renames or drops fails the spawn instead of
//! silently losing a setting.

use crate::local::NodeEnvConfig;
use crate::{Context, NodeConfig};

use mpc_chain_canton::CantonConfig;
use mpc_chain_ethereum::EthConfig;
use mpc_chain_hydration::HydrationConfig;
use mpc_chain_midnight::MidnightConfig;
use mpc_chain_solana::SolConfig;
use mpc_node::{logs, storage};

/// The `start` command line for one node.
pub fn start(ctx: &Context, node: &NodeEnvConfig) -> Vec<String> {
    let mut args = Args(vec!["start".to_string()]);
    args.flag("--near-rpc", &node.near_rpc);
    args.flag("--mpc-contract-id", ctx.mpc_contract.id());
    args.flag("--account-id", node.account.id());
    args.flag("--env", &ctx.env);
    args.flag("--account-sk", node.account.secret_key());
    args.flag("--cipher-sk", hex::encode(node.cipher_sk.to_bytes()));
    args.flag("--sign-sk", &node.sign_sk);
    args.flag("--web-port", node.web_port);
    args.chains(&node.cfg);
    args.storage(&ctx.storage_options);
    args.logs(&ctx.log_options);
    args.0
}

struct Args(Vec<String>);

impl Args {
    fn flag(&mut self, name: &str, value: impl ToString) {
        self.0.push(name.to_string());
        self.0.push(value.to_string());
    }

    fn switch(&mut self, name: &str, on: bool) {
        if on {
            self.0.push(name.to_string());
        }
    }

    fn chains(&mut self, cfg: &NodeConfig) {
        if let Some(eth) = &cfg.eth {
            self.eth(eth);
        }
        if let Some(sol) = &cfg.sol {
            self.sol(sol);
        }
        if let Some(hydration) = &cfg.hydration {
            self.hydration(hydration);
        }
        if let Some(canton) = &cfg.canton {
            self.canton(canton);
        }
        if let Some(midnight) = &cfg.midnight {
            self.midnight(midnight);
        }
    }

    fn eth(&mut self, eth: &EthConfig) {
        self.flag(
            "--eth-account-sk",
            hex::encode(eth.account_sk.credential().to_bytes()),
        );
        self.flag("--eth-execution-rpc-http-url", &eth.execution_rpc_http_url);
        self.flag("--eth-contract-address", eth.contract_address);
        self.flag("--eth-network", &eth.network);
        self.flag(
            "--eth-refresh-finalized-interval",
            eth.refresh_finalized_interval,
        );
        self.switch("--eth-optimistic-requests", eth.optimistic_requests);
    }

    fn sol(&mut self, sol: &SolConfig) {
        self.flag("--sol-account-sk", &sol.account_sk);
        self.flag("--sol-rpc-http-url", &sol.rpc_http_url);
        self.flag("--sol-program-address", &sol.program_address);
        self.flag(
            "--sol-poll-interval-ms",
            sol.indexer.poll_interval.as_millis(),
        );
    }

    fn hydration(&mut self, hydration: &HydrationConfig) {
        self.flag("--hydration-rpc-ws-url", &hydration.rpc_ws_url);
        self.flag("--hydration-signer-uri", &hydration.signer_uri);
    }

    fn canton(&mut self, canton: &CantonConfig) {
        self.flag("--canton-json-api-url", &canton.json_api_url);
        self.flag("--canton-json-api-ws-url", &canton.json_api_ws_url);
        self.flag("--canton-ledger-api-user", &canton.ledger_api_user);
        self.flag("--canton-oidc-token-url", &canton.auth.token_url);
        self.flag("--canton-oidc-client-id", &canton.auth.client_id);
        self.flag("--canton-oidc-client-secret", &canton.auth.client_secret);
        self.flag("--canton-oidc-audience", &canton.auth.audience);
        if let Some(scope) = &canton.auth.scope {
            self.flag("--canton-oidc-scope", scope);
        }
        self.flag("--canton-party-id", &canton.party_id);
        self.flag("--canton-signer-contract-id", &canton.signer_contract_id);
        self.flag("--canton-signer-template-id", &canton.signer_template_id);
    }

    fn midnight(&mut self, midnight: &MidnightConfig) {
        let publisher = &midnight.publisher;
        self.flag("--midnight-node-url", &midnight.node_url);
        self.flag(
            "--midnight-central-address",
            midnight.central_address.to_hex(),
        );
        self.flag("--midnight-funding-seed", &publisher.funding_seed);
        self.flag(
            "--midnight-intent-gen-command",
            serde_json::to_string(&publisher.intent_gen_command)
                .expect("a Vec<String> always serializes"),
        );
        self.flag("--midnight-proof-server-url", &publisher.proof_server_url);
        self.flag("--midnight-indexer-url", &publisher.indexer_url);
        self.flag("--midnight-indexer-ws-url", &publisher.indexer_ws_url);
        if let Some(storage) = &publisher.output_storage {
            self.flag("--midnight-output-storage-bucket", &storage.bucket);
            self.flag("--midnight-output-storage-prefix", &storage.prefix);
            self.flag(
                "--midnight-output-storage-timeout-secs",
                storage.timeout.as_secs(),
            );
            if let Some(endpoint) = &storage.emulator_endpoint {
                self.flag("--midnight-output-storage-emulator-endpoint", endpoint);
            }
        }
    }

    fn storage(&mut self, storage: &storage::Options) {
        self.flag("--gcp-project-id", &storage.gcp_project_id);
        if let Some(id) = &storage.sk_share_secret_id {
            self.flag("--sk-share-secret-id", id);
        }
        if let Some(path) = &storage.sk_share_local_path {
            self.flag("--sk-share-local-path", path);
        }
        self.flag("--redis-url", &storage.redis_url);
    }

    fn logs(&mut self, logs: &logs::Options) {
        self.flag("--opentelemetry-level", logs.opentelemetry_level);
        self.flag("--otlp-endpoint", &logs.otlp_endpoint);
        self.switch("--disable-gcp-logs", logs.disable_gcp_logs);
    }
}
