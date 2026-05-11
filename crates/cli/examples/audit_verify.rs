fn main() -> anyhow::Result<()> {
    #[cfg(feature = "audit")]
    {
        use std::{env, path::Path};
        let dir = env::args().nth(1).unwrap_or_else(|| ".audit".into());
        let r = ecac_store::audit::AuditReader::open(Path::new(&dir))?;
        r.verify().map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("OK: audit chain verified at {dir}");
        return Ok(());
    }

    #[cfg(not(feature = "audit"))]
    {
        eprintln!(
            "This example requires the `audit` feature.\n\
             Run:\n  cargo run -p ecac-cli --example audit_verify --features audit -- <dir>"
        );
        Ok(())
    }
}
