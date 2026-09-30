mod portable;
use eyre::{ensure, Result};
use serde_json::Value;
use std::io::Read;
#[tokio::main]
async fn main() {
    // Never print upstream diagnostics or transcripts containing account data.
    if run().await.is_err() {
        eprintln!("TLSNotary operation failed. Check configuration and proof validity.");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().take(524289).read_to_string(&mut input)?;
    ensure!(input.len() <= 524288, "input limit");
    let data: Value = serde_json::from_str(&input)?;
    match std::env::args().nth(1).as_deref() {
        Some("notary") => portable::serve(data).await?,
        Some("verify") => println!("{}", portable::verify(data)?),
        Some("prove") => println!(
            "{}",
            tokio::time::timeout(std::time::Duration::from_secs(150), portable::prove(data))
                .await??
        ),
        _ => return Err(eyre::eyre!("expected prove, verify or notary")),
    }
    Ok(())
}
