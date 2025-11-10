// tests/common.rs (or at top of the test)
static INIT: std::sync::Once = std::sync::Once::new();

pub fn init_logs() {
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("warn".parse().unwrap()) // default to WARN
            )
            .with_target(true)
            .try_init();
    });
}
