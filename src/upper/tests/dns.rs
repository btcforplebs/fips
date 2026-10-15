//! Tests of where the DNS responder sends a reply to a mesh source address
//! when no strict pin to the arrival interface is known to hold.

#[cfg(target_os = "linux")]
use super::tests::{ForgedSourceNetns, bind_pktinfo, expect_answer, send_unanswered};
use super::*;
use std::net::IpAddr;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("test address")
}

/// Where no strict pin holds (every target but Linux), a reply to a mesh
/// source with a known arrival interface is sent only if the route returns
/// it by that interface, on either bind and whether or not the mesh index is
/// known; one with an unknown arrival interface is withheld on a specific
/// bind with a known mesh index and routed otherwise. Non-mesh sources are
/// routed, as with a strict pin.
#[test]
fn reply_path_without_a_strict_pin_sends_mesh_source_replies_only_where_they_return() {
    use ReplyPath::{Returning, Routed, Withheld};
    let at = |ip: &str| std::net::SocketAddr::new(ip.parse().unwrap(), 4444);
    const WILD: bool = true;
    const SPECIFIC: bool = false;
    let cases = [
        // Wildcard bind, mesh interface 3.
        ("fd11:2233::7", Some(2), Some(3), WILD, Returning(2)),
        ("fd11:2233::7", None, Some(3), WILD, Routed),
        ("fdab::2", Some(5), Some(3), WILD, Returning(5)),
        ("2001:db8::2", Some(2), Some(3), WILD, Routed),
        ("fe80::1", Some(2), Some(3), WILD, Routed),
        ("::1", Some(1), Some(3), WILD, Routed),
        ("::ffff:192.0.2.2", Some(2), Some(3), WILD, Routed),
        ("192.0.2.2", Some(2), Some(3), WILD, Routed),
        // Wildcard bind, no known mesh interface.
        ("fd11:2233::7", Some(2), None, WILD, Returning(2)),
        ("fd11:2233::7", None, None, WILD, Routed),
        // Specific bind, mesh interface 3.
        ("fd11:2233::7", Some(2), Some(3), SPECIFIC, Returning(2)),
        ("fdab::2", Some(5), Some(3), SPECIFIC, Returning(5)),
        ("fd11:2233::7", None, Some(3), SPECIFIC, Withheld),
        ("fd11:2233::7", Some(3), Some(3), SPECIFIC, Returning(3)),
        ("2001:db8::2", Some(2), Some(3), SPECIFIC, Routed),
        ("::ffff:192.0.2.2", Some(2), Some(3), SPECIFIC, Routed),
        ("192.0.2.2", Some(2), Some(3), SPECIFIC, Routed),
        // Specific bind, no known mesh interface.
        ("fd11:2233::7", Some(2), None, SPECIFIC, Returning(2)),
        ("fd11:2233::7", None, None, SPECIFIC, Routed),
    ];
    for (ip, arrival, mesh, wildcard, want) in cases {
        assert_eq!(
            reply_path(at(ip), arrival, mesh, wildcard, false),
            want,
            "source {ip}, arrival {arrival:?}, mesh {mesh:?}, wildcard {wildcard}"
        );
    }
}

/// A returning reply to a local destination is delivered: the probe picks
/// the destination itself as the source. Runs without root on any target.
#[tokio::test]
async fn a_returning_reply_to_a_local_address_is_delivered() {
    let sender = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let receiver = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let dst = receiver.local_addr().unwrap();
    send_reply(
        &sender,
        b"returning",
        dst,
        ReplyPath::Returning(0x7fff_fff0),
    )
    .await
    .unwrap();
    let mut buf = [0u8; 16];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        receiver.recv_from(&mut buf),
    )
    .await
    .expect("the returning reply to a local address was not delivered")
    .unwrap();
    assert_eq!(&buf[..len], b"returning");
}

/// A withheld reply is not sent on any target.
#[tokio::test]
async fn a_withheld_reply_is_not_sent_on_any_target() {
    let sender = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let receiver = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let dst = receiver.local_addr().unwrap();
    let sent = send_reply(&sender, b"withheld", dst, ReplyPath::Withheld)
        .await
        .unwrap();
    assert_eq!(sent, 0);
    let mut buf = [0u8; 16];
    let got = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        receiver.recv_from(&mut buf),
    )
    .await;
    assert!(got.is_err(), "the withheld reply was delivered: {got:?}");
}

/// A probe source on one of the arrival interface's prefixes returns the
/// reply by that interface; one on another interface's prefix does not.
#[test]
fn returns_by_is_true_only_for_a_source_on_the_arrival_interface() {
    let prefixes = OnLinkPrefixes::from_indexed([
        (ip("2001:db8:1::1"), 64, Some(2)),
        (ip("fdab::1"), 64, Some(2)),
        (ip("fd99::1"), 128, Some(3)),
    ]);
    assert!(returns_by(ip("fdab::1"), ip("fdab::2"), 2, &prefixes));
    assert!(returns_by(ip("2001:db8:1::1"), ip("fdab::2"), 2, &prefixes));
    assert!(!returns_by(ip("fd99::1"), ip("fd11:2233::7"), 2, &prefixes));
    assert!(returns_by(ip("fd99::1"), ip("fd11:2233::7"), 3, &prefixes));
    assert!(!returns_by(ip("fdab::1"), ip("fdab::2"), 7, &prefixes));
}

/// A reply whose probe source is its own destination is delivered locally,
/// whatever interface the query was reported on.
#[test]
fn returns_by_is_true_when_the_reply_is_delivered_locally() {
    let prefixes = OnLinkPrefixes::from_indexed([(ip("fd99::1"), 128, Some(3))]);
    assert!(returns_by(ip("fd99::1"), ip("fd99::1"), 2, &prefixes));
    assert!(returns_by(
        ip("fd99::1"),
        ip("fd99::1"),
        2,
        &OnLinkPrefixes::default()
    ));
}

/// An empty or failed interface read holds no prefix, so a reply that is not
/// delivered locally is not judged to return.
#[test]
fn returns_by_is_false_for_an_empty_or_failed_prefix_set() {
    for prefixes in [OnLinkPrefixes::default(), OnLinkPrefixes::failed()] {
        assert!(!returns_by(ip("fdab::1"), ip("fdab::2"), 2, &prefixes));
    }
}

/// A responder running on its own thread inside a node namespace, stopped
/// and joined on drop.
#[cfg(target_os = "linux")]
struct NetnsResponder {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    identities: DnsIdentityRx,
}

#[cfg(target_os = "linux")]
impl Drop for NetnsResponder {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(target_os = "linux")]
impl ForgedSourceNetns {
    /// Run the responder bound to `bind` on a thread that has entered the
    /// node namespace, with its own current-thread runtime, so everything it
    /// does at reply time (sockets, interface reads) sees that namespace's
    /// routes and interfaces rather than the host's.
    fn spawn_responder(
        &self,
        bind: std::net::SocketAddr,
        mesh_ifindex: Option<u32>,
    ) -> NetnsResponder {
        use std::os::fd::AsRawFd;
        let path = format!("/run/netns/{}", self.node);
        let (identity_tx, identities) = tokio::sync::mpsc::channel(16);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let file = std::fs::File::open(&path).expect("open netns");
            let ret = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
            assert_eq!(ret, 0, "setns: {}", std::io::Error::last_os_error());
            let server = bind_pktinfo(bind);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("responder runtime");
            runtime.block_on(async move {
                let server = tokio::net::UdpSocket::from_std(server).unwrap();
                let reloader = HostMapReloader::new(
                    HostMap::new(),
                    std::path::PathBuf::from("/nonexistent/hosts"),
                );
                ready_tx.send(()).unwrap();
                tokio::select! {
                    _ = run_responder(server, identity_tx, 300, reloader, None, mesh_ifindex) => {}
                    _ = stopped => {}
                }
            });
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the responder starts in the node namespace");
        NetnsResponder {
            stop: Some(stop),
            thread: Some(thread),
            identities,
        }
    }
}

/// A UDP socket bound to `addr` inside namespace `ns`, for the test runtime.
#[cfg(target_os = "linux")]
fn client_in(ns: &str, addr: &'static str) -> tokio::net::UdpSocket {
    let socket = ForgedSourceNetns::enter(ns, move || {
        let s = std::net::UdpSocket::bind(addr).unwrap();
        s.set_nonblocking(true).unwrap();
        s
    });
    tokio::net::UdpSocket::from_std(socket).unwrap()
}

/// Check, inside the node namespace, that the route probe sees that
/// namespace's table: the forged destination routes by `fips0` (source
/// `fd99::1`) and the on-link ULA client by the LAN veth (source `fdab::1`).
#[cfg(target_os = "linux")]
fn assert_probe_sees_the_node_namespace(ns: &ForgedSourceNetns) {
    let (forged, ula) = ForgedSourceNetns::enter(&ns.node, || {
        (
            probe_source("[fd11:2233::7]:4444".parse().unwrap()).unwrap(),
            probe_source("[fdab::2]:4445".parse().unwrap()).unwrap(),
        )
    });
    assert_eq!(forged, ip("fd99::1"), "probe source for the forged address");
    assert_eq!(ula, ip("fdab::1"), "probe source for the ULA client");
}

/// The specific LAN address the responder binds in the namespace tests.
#[cfg(target_os = "linux")]
const LAN_BIND: &str = "[2001:db8:1::1]:5354";

/// With the responder bound to one specific LAN address and no known mesh
/// interface index (an application-supplied TUN, or an index that did not
/// resolve), a LAN host that forges a mesh source address must not draw the
/// reply into the mesh by the `fd00::/8` route.
///
/// Needs root (network namespaces, nft): build with
/// `cargo test --lib --no-run` and run the test binary under `sudo` with
/// `--ignored`.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_forged_mesh_source_on_a_specific_bind_with_no_mesh_index_is_not_answered_into_the_mesh()
{
    let ns = ForgedSourceNetns::new();
    assert_probe_sees_the_node_namespace(&ns);
    let target: std::net::SocketAddr = LAN_BIND.parse().unwrap();
    let mut responder = ns.spawn_responder(target, None);
    let forged = client_in(&ns.lan, "[fd11:2233::7]:4444");

    send_unanswered(&forged, target, &mut responder.identities).await;
    let into_mesh = ns.mesh_replies();
    drop(responder);
    assert_eq!(
        into_mesh, 0,
        "with the responder bound to 2001:db8:1::1 and no mesh index, a LAN query from \
         forged source fd11:2233::7 was answered into the mesh: {into_mesh} UDP packet(s) \
         from port 5354 left by fips0"
    );
}

/// On the same setup a LAN client with a global source address is answered.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_global_lan_client_on_a_specific_bind_with_no_mesh_index_is_answered() {
    let ns = ForgedSourceNetns::new();
    assert_probe_sees_the_node_namespace(&ns);
    let target: std::net::SocketAddr = LAN_BIND.parse().unwrap();
    let mut responder = ns.spawn_responder(target, None);
    let client = client_in(&ns.lan, "[2001:db8:1::2]:4443");
    expect_answer(
        &client,
        target,
        &mut responder.identities,
        "the global LAN client is answered",
    )
    .await;
    assert_eq!(ns.mesh_replies(), 0);
}

/// On the same setup an on-link ULA client, whose source lies in `fd00::/8`
/// but on the LAN's own `fdab::/64`, is answered: the table sends its reply
/// back out of the LAN interface it arrived on.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn an_on_link_ula_client_on_a_specific_bind_with_no_mesh_index_is_answered() {
    let ns = ForgedSourceNetns::new();
    assert_probe_sees_the_node_namespace(&ns);
    let target: std::net::SocketAddr = LAN_BIND.parse().unwrap();
    let mut responder = ns.spawn_responder(target, None);
    let client = client_in(&ns.lan, "[fdab::2]:4445");
    expect_answer(
        &client,
        target,
        &mut responder.identities,
        "the on-link ULA client is answered",
    )
    .await;
    assert_eq!(ns.mesh_replies(), 0);
}

/// On the same setup a local process sending from the node's own mesh
/// address to the LAN bind is answered: its reply is delivered locally and
/// never leaves the node.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs root: creates network namespaces"]
async fn a_local_client_sending_from_the_mesh_address_on_a_specific_bind_is_answered() {
    let ns = ForgedSourceNetns::new();
    assert_probe_sees_the_node_namespace(&ns);
    let target: std::net::SocketAddr = LAN_BIND.parse().unwrap();
    let mut responder = ns.spawn_responder(target, None);
    let client = client_in(&ns.node, "[fd99::1]:4446");
    expect_answer(
        &client,
        target,
        &mut responder.identities,
        "the local client sending from fd99::1 is answered",
    )
    .await;
    assert_eq!(ns.mesh_replies(), 0);
}
