//! Serving: bind, serve with client addresses, stop on a signal.

use std::net::SocketAddr;

use anyhow::Context;
use axum::Router;

/// Resolves on SIGTERM (Kubernetes stopping the pod) or Ctrl-C.
///
/// # Panics
/// If the signal handlers cannot be installed (no signal support at all).
pub async fn shutdown_signal() {
    #[cfg(unix)]
    let term = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install a SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = term => {},
        r = tokio::signal::ctrl_c() => r.expect("install a Ctrl-C handler"),
    }
    tracing::info!("shutting down");
}

/// Raise the soft open-files limit to the hard one. Container runtimes start
/// processes at 1,024; a server at its limit stops accepting connections (readiness
/// probes included) while its CPU sits idle. Call before serving many sockets.
pub fn raise_open_files_limit() {
    let before = rlimit::getrlimit(rlimit::Resource::NOFILE).map_or(0, |(soft, _)| soft);
    match rlimit::increase_nofile_limit(u64::MAX) {
        Ok(now) => tracing::info!(before, now, "open files limit"),
        Err(e) => tracing::warn!(error = %e, before, "could not raise the open files limit"),
    }
}

/// Bind `addr`, then serve `app` with `ConnectInfo<SocketAddr>` available to handlers
/// until `shutdown` resolves; in-flight requests finish first.
pub async fn serve<F>(addr: &str, app: Router, shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!(addr = %listener.local_addr()?, "listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;
    Ok(())
}
