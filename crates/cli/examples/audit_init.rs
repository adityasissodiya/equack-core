use std::{env, path::Path};

#[cfg(feature = "audit")]
use ecac_store::audit_sink::StoreAuditHook;

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "audit")]
    {
        let dir = env::args().nth(1).unwrap_or_else(|| ".audit".into());
        let _hook = StoreAuditHook::open_dir(Path::new(&dir))?;
        println!("Initialized audit dir at {dir}");
        return Ok(());
    }

    #[cfg(not(feature = "audit"))]
    {
        eprintln!(
            "This example requires the `audit` feature.\n\
             Run: cargo run -p ecac-cli --features audit --example audit_init -- .audit"
        );
        Ok(())
    }
}
