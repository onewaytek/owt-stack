//! Serving: bind, serve with client addresses, stop on a signal.
//!
//! [`serve`] bounds what a client can hold without sending a request: the request
//! head must arrive within [`ServeOptions::header_read_timeout`] (a slow-loris
//! client trickling headers is cut off rather than holding a socket for ever), and
//! a stop waits at most [`ServeOptions::drain`] for the connections still open
//! (streams and slow uploads included) before closing them, so a rollout is never
//! held to the pod's whole termination grace period. `owt_web::limits::Limits`
//! bounds the time to a response; this bounds the time before a request.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::extract::ConnectInfo;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

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

/// How [`serve_with`] bounds a connection.
#[derive(Clone, Copy, Debug)]
pub struct ServeOptions {
    /// How long a connection may take to send a request's head (the request line
    /// and headers), for its first request and each one after on a kept-alive
    /// connection. Default 10 seconds.
    pub header_read_timeout: Duration,
    /// How long a stop waits for open connections to finish before closing them.
    /// Default 20 seconds, inside Kubernetes' default 30-second grace period.
    pub drain: Duration,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            header_read_timeout: Duration::from_secs(10),
            drain: Duration::from_secs(20),
        }
    }
}

/// Bind `addr`, then serve `app` with `ConnectInfo<SocketAddr>` available to handlers
/// until `shutdown` resolves; in-flight requests finish first, for up to
/// [`ServeOptions::drain`]. [`ServeOptions::default`]'s bounds apply.
pub async fn serve<F>(addr: &str, app: Router, shutdown: F) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_with(addr, app, shutdown, ServeOptions::default()).await
}

/// [`serve`], with these bounds.
pub async fn serve_with<F>(
    addr: &str,
    app: Router,
    shutdown: F,
    options: ServeOptions,
) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!(addr = %listener.local_addr()?, "listening");
    run(listener, app, shutdown, options).await;
    Ok(())
}

/// Accept on `listener` and serve each connection over HTTP/1.1 under `options`,
/// until `shutdown`; then drain.
pub(crate) async fn run<F>(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: F,
    options: ServeOptions,
) where
    F: Future<Output = ()> + Send + 'static,
{
    let mut http = hyper::server::conn::http1::Builder::new();
    http.timer(TokioTimer::new())
        .header_read_timeout(options.header_read_timeout);
    let stopping = CancellationToken::new();
    let mut connections = tokio::task::JoinSet::new();
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    // Out of file descriptors, say: back off rather than spin.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let service = app
            .clone()
            .map_request(move |req: hyper::Request<hyper::body::Incoming>| {
                let mut req = req.map(axum::body::Body::new);
                req.extensions_mut().insert(ConnectInfo::<SocketAddr>(peer));
                req
            });
        let connection = http
            .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service))
            .with_upgrades();
        let stopping = stopping.clone();
        connections.spawn(async move {
            let mut connection = std::pin::pin!(connection);
            let ended = tokio::select! {
                ended = connection.as_mut() => ended,
                () = stopping.cancelled() => {
                    // Finish the request in flight, then close.
                    connection.as_mut().graceful_shutdown();
                    connection.await
                }
            };
            if let Err(e) = ended {
                tracing::debug!(error = %e, %peer, "connection ended with an error");
            }
        });
        // Forget the connections that have ended.
        while connections.try_join_next().is_some() {}
    }
    drop(listener);
    stopping.cancel();
    let drained = tokio::time::timeout(options.drain, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tracing::warn!(
            open = connections.len(),
            after = ?options.drain,
            "closing the connections still open at the drain deadline"
        );
        connections.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;

    const QUICK: ServeOptions = ServeOptions {
        header_read_timeout: Duration::from_millis(300),
        drain: Duration::from_millis(300),
    };

    /// `run` on an ephemeral port with `/who` (the peer's address) and `/slow` (an
    /// hour), stopped by the sender.
    async fn started() -> (
        SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/who",
                axum::routing::get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move {
                    peer.ip().to_string()
                }),
            )
            .route(
                "/slow",
                axum::routing::get(|| async {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    "late"
                }),
            );
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run(
            listener,
            app,
            async move {
                let _ = stopped.await;
            },
            QUICK,
        ));
        (addr, stop, task)
    }

    /// Everything the server sends until it closes, or until `limit`.
    async fn read_all(stream: &mut TcpStream, limit: Duration) -> Option<String> {
        let mut out = Vec::new();
        tokio::time::timeout(limit, stream.read_to_end(&mut out))
            .await
            .ok()?
            .ok()?;
        Some(String::from_utf8_lossy(&out).into_owned())
    }

    #[tokio::test]
    async fn handlers_see_the_client_address() {
        let (addr, _stop, _task) = started().await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /who HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        let answer = read_all(&mut s, Duration::from_secs(5)).await.unwrap();
        assert!(answer.ends_with("127.0.0.1"), "{answer}");
    }

    /// A client trickling its headers is cut off at the header timeout, not kept.
    #[tokio::test]
    async fn a_slow_request_head_is_cut_off() {
        let (addr, _stop, _task) = started().await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /who HTTP/1.1\r\nhost: x\r\n")
            .await
            .unwrap();
        let began = Instant::now();
        let answer = read_all(&mut s, Duration::from_secs(5)).await;
        assert!(answer.is_some(), "the connection was held open");
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "{:?}",
            began.elapsed()
        );
        assert!(!answer.unwrap().contains("127.0.0.1"));
    }

    /// A stop closes what is still open at the drain deadline instead of waiting on it.
    #[tokio::test]
    async fn a_stop_waits_no_longer_than_the_drain() {
        let (addr, stop, task) = started().await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET /slow HTTP/1.1\r\nhost: x\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let began = Instant::now();
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the server stopped")
            .unwrap();
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "{:?}",
            began.elapsed()
        );
        // And it no longer accepts.
        assert!(TcpStream::connect(addr).await.is_err());
    }
}
