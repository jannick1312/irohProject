//! Connect example: prefer direct (hole-punch) first, relay as fallback.
//
// Usage (LAN / direct):
//   cargo run -p iroh --example connect -- \
//     --node-id <ID> \
//     --addrs "10.0.0.5:51820"
//
// Usage (Internet with relay fallback):
//   cargo run -p iroh --example connect -- \
//     --node-id <ID> \
//     --addrs "10.0.0.5:51820" \
//     --relay-url https://euc1-1.relay.n0.iroh.iroh.link/

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::Parser;
use iroh::{Endpoint, NodeAddr, RelayMode, RelayUrl, SecretKey};
use n0_watcher::Watcher as _; // for .initialized()
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info};

const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/magic/0";
const DIRECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
struct Cli {
    /// Remote node id (public key)
    #[clap(long)]
    node_id: iroh::NodeId,

    /// Direct UDP addresses (one or more)
    #[clap(long, value_parser, num_args = 1.., value_delimiter = ' ')]
    addrs: Vec<SocketAddr>,

    /// Optional relay URL (used only as fallback)
    #[clap(long)]
    relay_url: Option<RelayUrl>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Cli::parse();
    println!("\nconnect example (prefer direct, relay fallback)\n");

    // ephemeral key
    let secret_key = SecretKey::generate(rand::rngs::OsRng);
    println!("public key: {}", secret_key.public());

    // endpoint
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![EXAMPLE_ALPN.to_vec()])
        .relay_mode(RelayMode::Default) // allow relay as fallback; we choose via NodeAddr
        .bind()
        .await?;

    let me = endpoint.node_id();
    println!("local node id: {me}");
    println!("local listening addresses:");
    for local in endpoint.direct_addresses().initialized().await {
        println!("\t{}", local.addr);
    }

    // 1) DIRECT attempt (no relay in NodeAddr)
    let addr_direct = NodeAddr::from_parts(args.node_id, None, args.addrs.clone());
    info!("Attempting DIRECT (hole-punch) to {:?}", addr_direct);

    let direct_result = timeout(DIRECT_TIMEOUT, endpoint.connect(addr_direct, EXAMPLE_ALPN)).await;

    match direct_result {
        // Direct connection established
        Ok(Ok(conn)) => {
            info!("✅ Direct connection established (hole-punch/LAN).");
            handle_connection(conn).await?;
            endpoint.close().await;
            return Ok(());
        }
        // connect() returned error before timeout
        Ok(Err(e)) => {
            error!("Direct connect error: {e}");
        }
        // timeout expired
        Err(_) => {
            debug!("Direct connect timed out after {:?}", DIRECT_TIMEOUT);
        }
    }

    // 2) Relay fallback (only if provided)
    if let Some(relay_url) = args.relay_url.clone() {
        info!("Trying RELAY fallback via {}", relay_url);
        // brief wait so endpoint can register with home relay (optional)
        sleep(Duration::from_millis(200)).await;

        let addr_relay = NodeAddr::from_parts(args.node_id, Some(relay_url), args.addrs.clone());
        let conn = endpoint.connect(addr_relay, EXAMPLE_ALPN).await?;
        info!("🔁 Connected using RELAY (fallback).");
        handle_connection(conn).await?;
        endpoint.close().await;
        Ok(())
    } else {
        endpoint.close().await;
        bail!("direct connect failed and no --relay-url provided");
    }
}

// Simple roundtrip: send one message, read one response.
async fn handle_connection(conn: iroh::endpoint::Connection) -> Result<()> {
    info!("opening bidi stream…");
    let (mut send, mut recv) = conn.open_bi().await?;

    let msg = "hello from connector";
    use tokio::io::AsyncWriteExt;
    send.write_all(msg.as_bytes()).await?;
    // finish() is sync in this API
    send.finish()?;

    // iroh's recv has a convenience read_to_end(limit) -> Vec<u8>
    let data = recv.read_to_end(16 * 1024).await?;
    println!("received: {}", String::from_utf8_lossy(&data));
    Ok(())
}
