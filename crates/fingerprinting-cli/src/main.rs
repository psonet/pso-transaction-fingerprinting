use anyhow::Result;
use clap::Parser;
use fingerprinting_core::secret_sharing::SecretSharing;
use fingerprinting_core::Compact;
use halo2_axiom::arithmetic::Field;
use halo2_axiom::halo2curves::bn256::Fr;
use rand_core::OsRng;

/// Generate a transaction fingerprint
#[derive(Parser, Debug)]
#[command(name = "fingerprinting-cli")]
#[command(about = "Fingerprint CLI utility", long_about = None)]
struct Args {
    /// Threshold for cooperative computation
    #[arg(long)]
    threshold: usize,

    /// Total number of cooperative agents network size
    #[arg(long)]
    agents: usize,
}

fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();
    let mut rng = OsRng;

    let random_secret = Fr::random(&mut rng);

    let secret_sharing = SecretSharing::generate(random_secret, args.threshold, args.agents);

    let shares_set = secret_sharing.get_shares();

    log::info!("Random secret: {}", random_secret.compact());
    log::info!("Shares:");
    for (agent, secret) in shares_set.iter() {
        log::info!("== share {}: {}", agent, secret.compact());
    }

    Ok(())
}
