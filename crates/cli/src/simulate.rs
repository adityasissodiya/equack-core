use anyhow::Result;

pub fn cmd_simulate(_scenario: Option<&str>) -> Result<()> {
    eprintln!("simulate: temporarily disabled while we switch to VC-backed grants (M4).");
    eprintln!("Use `vc-verify` and `vc-attach` for now.");
    Ok(())
}
