//! HTTP server module for the ECAC Gateway demo UI.
//!
//! Provides a web interface for exploring ECAC functionality including:
//! - Node status and peer connections
//! - Sensor data / state visualization
//! - Sync status between nodes
//! - Access control and credentials
//! - Audit log viewing

mod api;
mod state;
mod static_files;

pub use api::create_router;
pub use state::{AppState, ServeConfig};

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;

/// Start the HTTP server with the given configuration.
pub async fn run_server(config: ServeConfig) -> Result<()> {
    let mut app_state = AppState::new(config.clone())?;

    // Spawn libp2p networking task if enabled
    #[cfg(feature = "serve")]
    if config.libp2p_listen.is_some() {
        match state::spawn_network_task(&config, app_state.store.clone()).await {
            Ok((net_tx, peer_id)) => {
                app_state.set_net_channel(net_tx);
                println!("libp2p Peer ID: {}", peer_id);

                // Store peer_id for later access
                let state = Arc::new(app_state);
                state.set_peer_id(peer_id).await;

                let app = create_router(state.clone());

                let addr: SocketAddr = state.config.listen.parse()?;
                println!("ECAC Gateway starting on http://{}", addr);
                if let Some(ref name) = state.config.site_name {
                    println!("Site: {}", name);
                }
                if state.config.allow_writes {
                    println!("Write operations: ENABLED");
                }
                println!("libp2p networking: ENABLED");
                if let Some(ref listen) = state.config.libp2p_listen {
                    println!("libp2p listen: {}", listen);
                }

                let listener = tokio::net::TcpListener::bind(addr).await?;
                axum::serve(listener, app).await?;

                return Ok(());
            }
            Err(e) => {
                eprintln!("Warning: Failed to start libp2p networking: {}", e);
                eprintln!("Continuing without networking...");
            }
        }
    }

    // Run without networking
    let state = Arc::new(app_state);
    let app = create_router(state.clone());

    let addr: SocketAddr = state.config.listen.parse()?;
    println!("ECAC Gateway starting on http://{}", addr);
    if let Some(ref name) = state.config.site_name {
        println!("Site: {}", name);
    }
    if state.config.allow_writes {
        println!("Write operations: ENABLED");
    }
    println!("libp2p networking: DISABLED");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
