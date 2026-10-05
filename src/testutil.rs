//! Crate-wide generic test helpers.

use crate::NodeAddr;

/// Build a `NodeAddr` from a single discriminating byte in position 0.
pub(crate) fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

/// Collects emitted tracing events so a test can assert on a log line.
///
/// Some behaviour is reported only in the log: a structured field an operator
/// greps on is part of the contract even when no counter or return value
/// carries it. Installed with `tracing::subscriber::with_default`, which is
/// thread-local, so tests running in parallel do not see each other's events.
#[derive(Clone, Default)]
pub(crate) struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl LogCapture {
    /// Every captured line, each prefixed with its level.
    pub(crate) fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }

    /// Only the captured lines emitted at WARN.
    pub(crate) fn warnings(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.starts_with("WARN"))
            .cloned()
            .collect()
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={:?}", field.name(), value));
            }
        }

        let mut fields = Fields(event.metadata().level().to_string());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
}

/// Run `f` with a capturing subscriber installed, returning its value and the capture.
pub(crate) fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, LogCapture) {
    use tracing_subscriber::layer::SubscriberExt;

    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let out = tracing::subscriber::with_default(subscriber, f);
    (out, capture)
}

/// Install a capturing subscriber for the rest of the current scope.
///
/// The async counterpart of [`capture_logs`]: an `async` test cannot wrap its
/// awaits in a closure, so it holds this guard instead and reads the capture
/// once the awaited work has run.
pub(crate) fn capture_logs_scoped() -> (LogCapture, tracing::subscriber::DefaultGuard) {
    use tracing_subscriber::layer::SubscriberExt;

    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let guard = tracing::subscriber::set_default(subscriber);
    (capture, guard)
}

/// Poll `f` every 10ms until it holds or `limit` elapses.
///
/// Uses tokio's clock, so a test running with paused time advances through
/// the waits instead of sleeping.
pub(crate) async fn wait_until<F: FnMut() -> bool>(mut f: F, limit: std::time::Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if f() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// A local TCP address whose SYNs go unanswered once filled.
///
/// A listener with a backlog of one whose accept queue is filled: Linux,
/// macOS and Windows drop further SYNs to a listener whose accept queue is
/// full, so a connect to it times out rather than completing or being
/// refused. How many connects the queue takes before it is full differs by
/// kernel (one on Linux, more on macOS), so filling stops at the first
/// connect that times out. The listener and the fillers must be kept alive
/// for as long as that is relied on.
///
/// FreeBSD answers a SYN to a full queue from its syncache and then resets
/// the connection, so its queue never goes silent. There, filling replaces
/// the listener with a socket bound to the same address that does not
/// listen, and the kernel must be set not to reset a SYN to a port nobody
/// listens on: `net.inet.tcp.blackhole=2` and `net.inet.tcp.blackhole_local=1`
/// (root). Those settings also stop every refused connect on the host, so a
/// test that needs one cannot run in the same pass; the FreeBSD package
/// workflow runs the tests that use a filled `Blackhole` in a pass of their
/// own.
pub(crate) struct Blackhole {
    pub(crate) listener: socket2::Socket,
    fillers: Vec<std::net::TcpStream>,
    pub(crate) addr: std::net::SocketAddr,
}

impl Blackhole {
    /// A listener with backlog 1. Not 0: macOS reads a backlog of 0 as the
    /// system default (about 128), so its queue would not fill.
    ///
    /// When `fill` is false the accept queue is left empty, so at least one
    /// connect completes; [`Blackhole::fill`] fills it later.
    pub(crate) fn open(fill: bool) -> Self {
        use socket2::{Domain, Socket, Type};
        let listener = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        listener.bind(&bind.into()).unwrap();
        listener.listen(1).unwrap();
        let addr = listener.local_addr().unwrap().as_socket().unwrap();
        let mut bh = Self {
            listener,
            fillers: Vec::new(),
            addr,
        };
        if fill {
            bh.fill();
        }
        bh
    }

    /// A listener whose SYNs already go unanswered.
    pub(crate) fn silent() -> Self {
        Self::open(true)
    }

    /// Fill the listener's accept queue, stopping at the first connect that
    /// times out, which shows a further connect now times out instead of
    /// completing or being refused.
    #[cfg(not(target_os = "freebsd"))]
    pub(crate) fn fill(&mut self) {
        const MAX_FILLERS: usize = 64;
        for _ in 0..=MAX_FILLERS {
            let probe = std::net::TcpStream::connect_timeout(
                &self.addr,
                std::time::Duration::from_millis(200),
            );
            match probe {
                Ok(filler) => self.fillers.push(filler),
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return,
                Err(e) => panic!("blackhole is not silent: probe connect returned {e:?}"),
            }
        }
        panic!("blackhole is not silent: {MAX_FILLERS} connects completed");
    }

    /// Accept every filler still queued on the listener, so the address
    /// answers again: the next connect to it, or the next retransmitted SYN
    /// of one already waiting, completes. Returns the accepted far ends,
    /// which the caller keeps alive while it relies on that.
    #[cfg(not(target_os = "freebsd"))]
    pub(crate) fn drain(&mut self) -> Vec<std::net::TcpStream> {
        self.fillers
            .iter()
            .map(|_| std::net::TcpStream::from(self.listener.accept().unwrap().0))
            .collect()
    }

    /// Close the listener and bind a socket that does not listen to the same
    /// address, then check that a connect to it now times out. Connections
    /// the listener already accepted are left as they are.
    #[cfg(target_os = "freebsd")]
    pub(crate) fn fill(&mut self) {
        use socket2::{Domain, Socket, Type};
        let quiet = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        quiet.set_reuse_address(true).unwrap();
        drop(std::mem::replace(&mut self.listener, quiet));
        self.listener.bind(&self.addr.into()).unwrap();
        let probe =
            std::net::TcpStream::connect_timeout(&self.addr, std::time::Duration::from_millis(200));
        match probe {
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            other => panic!(
                "blackhole is not silent: probe connect returned {other:?}; on FreeBSD \
                 this needs net.inet.tcp.blackhole=2 and net.inet.tcp.blackhole_local=1, \
                 and a test using it belongs in package-freebsd.yml's blackhole pass"
            ),
        }
    }

    /// Start listening on the bound socket, so the address answers again: the
    /// next connect to it, or the next retransmitted SYN of one already
    /// waiting, completes. Nothing was queued, so there are no far ends.
    #[cfg(target_os = "freebsd")]
    pub(crate) fn drain(&mut self) -> Vec<std::net::TcpStream> {
        self.listener.listen(1).unwrap();
        Vec::new()
    }

    /// The address in the transport form.
    pub(crate) fn transport_addr(&self) -> crate::transport::TransportAddr {
        crate::transport::TransportAddr::from_string(&self.addr.to_string())
    }
}
