use std::sync::Arc;
use clap::Parser;
use fingerprinting_grpc_agent::{net, CooperationAgentService};
use halo2_axiom::halo2curves::bn256::Fr;
use hocon::HoconLoader;
use serde_derive::Deserialize;
//use std::net::SocketAddr;
use volo::net::Address;
use volo_grpc::codegen::futures;
use volo_grpc::server::{Server, ServiceBuilder};

use fingerprinting_cli::config::{AgentConfig, GrpcConfig};
use fingerprinting_cli::HealthRegistryService;
use fingerprinting_core::Compact;
use grpc_health_checking::grpc::health::v1::HealthServer;
use grpc_health_checking::HealthRegistry;

#[derive(Parser, Debug)]
#[command(name = "fingerprinting-light-agent")]
#[command(about = "Fingerprint Light Agent", long_about = None)]
struct Args {
    /// Config file location
    #[arg(long)]
    config: String,
}

#[derive(Deserialize)]
struct LightAgentConfig {
    grpc: GrpcConfig,
    #[serde(rename = "management-grpc")]
    management_grpc: GrpcConfig,
    agent: AgentConfig,
}

#[volo::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    log::info!("Starting fingerprinting light agent...");

    let args = Args::parse();
    let reference_config = include_str!("../../config/light-agent-reference.conf");
    log::info!("== loading configuration from {}", args.config);
    let conf: LightAgentConfig = HoconLoader::new()
        .load_str(reference_config)?
        .load_file(args.config)?
        .resolve()?;

    let fingerprint_agent_grpc_address: Address = conf.grpc.try_into()?;
    log::info!(
        "== starting GRPC server on {}",
        fingerprint_agent_grpc_address
    );
    let management_grpc_address: Address = conf.management_grpc.try_into()?;
    log::info!(
        "== starting management GRPC server on {}",
        management_grpc_address
    );

    let health_service = HealthRegistryService {
        name: "fingerprinting-light-agent".to_string(),
    };
    let health_service = Arc::new(health_service);

    let mut health_registry = HealthRegistry::default();
    health_registry.register(health_service);
    let heath_registry_service = ServiceBuilder::new(HealthServer::new(health_registry)).build();

    let secret_shard: Fr =
        Compact::unwrap(&conf.agent.secret_shard).expect("Cannot parse secret shard");

    let service = CooperationAgentService::new(secret_shard);

    let fingerprint_server = Server::new()
        .http2_adaptive_window(true)
        .accept_http1(true)
        .add_service(
            ServiceBuilder::new(
                net::outbe::fingerprint::agent::v1::CooperationServiceServer::new(service),
            )
            .build(),
        )
        .run(fingerprint_agent_grpc_address);

    let heath_server = Server::new()
        .add_service(heath_registry_service)
        .http2_adaptive_window(true)
        .accept_http1(true)
        .run(management_grpc_address);

    futures::future::try_join(fingerprint_server, heath_server)
        .await
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!(e))
}
