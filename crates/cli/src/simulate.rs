use anyhow::Result;

pub fn cmd_simulate(_scenario: Option<&str>) -> Result<()> {
    eprintln!("simulate: temporarily disabled while we switch to VC-backed grants (M4).");
    #[cfg(feature = "audit")]
    {
        let dag = ecac_core::dag::Dag::new(); // harmless empty DAG
        if let Ok(Some(mut audit)) = crate::commands::open_audit_sink_default() {
            let _ = ecac_core::replay::replay_full_with_audit(&dag, &mut audit);
        } else {
            let _ = ecac_core::replay::replay_full(&dag);
        }
    }
    #[cfg(not(feature = "audit"))]
    {
        let dag = ecac_core::dag::Dag::new();
        let _ = ecac_core::replay::replay_full(&dag);
    }
    Ok(())
}
