//! Replacing the peer list at runtime must carry peer aliases into every map
//! that reads them: the display host map, the peer ACL's alias entries and
//! the running `.fips` DNS responder.

use super::*;
use crate::config::{ConnectPolicy, PeerAddress, PeerConfig};
use crate::node::acl::{PeerAclDecision, PeerAclReloader};
use crate::node::reloadable::HostMapReloadable;
use crate::upper::hosts::HostMap;
use std::net::Ipv6Addr;

/// A suffix taken from a fresh npub's data part, so alias names cannot
/// collide with a hosts file on the build host.
fn suffix() -> String {
    Identity::generate().npub()[5..17].to_string()
}

/// A peer entry with an explicit address and connect policy.
fn peer_at(id: &Identity, alias: Option<&str>, addr: &str, policy: ConnectPolicy) -> PeerConfig {
    PeerConfig {
        npub: id.npub(),
        alias: alias.map(String::from),
        addresses: vec![PeerAddress::new("udp", addr)],
        connect_policy: policy,
        auto_reconnect: false,
        via_nostr: false,
    }
}

/// An on-demand peer entry on the placeholder address, which nothing dials.
fn peer(id: &Identity, alias: Option<&str>) -> PeerConfig {
    peer_at(id, alias, "127.0.0.1:9", ConnectPolicy::OnDemand)
}

/// The identity form of a test identity, as the ACL and display paths see it.
fn ident(id: &Identity) -> PeerIdentity {
    PeerIdentity::from_npub(&id.npub()).unwrap()
}

/// The node address of a test identity.
fn addr(id: &Identity) -> NodeAddr {
    *ident(id).node_addr()
}

/// Build a node from `peers`, with its host map and peer ACL rebuilt exactly
/// as construction builds them but on temp paths, and its display-name map
/// seeded as `start()` seeds it (alias or else short npub).
///
/// `allow`, `deny` and `hosts` are file contents; `None` leaves the file
/// absent. The returned directory must outlive the node.
fn alias_node(
    peers: Vec<PeerConfig>,
    allow: Option<&str>,
    deny: Option<&str>,
    hosts: Option<&str>,
) -> (tempfile::TempDir, Node) {
    let dir = tempfile::tempdir().unwrap();
    let allow_path = dir.path().join("peers.allow");
    let deny_path = dir.path().join("peers.deny");
    let hosts_path = dir.path().join("hosts");
    for (path, contents) in [
        (&allow_path, allow),
        (&deny_path, deny),
        (&hosts_path, hosts),
    ] {
        if let Some(contents) = contents {
            std::fs::write(path, contents).unwrap();
        }
    }

    let mut config = Config::new();
    config.peers = peers;
    let mut node = make_node_with(config);
    let base = || HostMap::from_peer_configs(node.config().peers());
    let host_map = HostMapReloadable::new(base(), hosts_path.clone());
    let peer_acl = PeerAclReloader::with_alias_sources(allow_path, deny_path, base(), hosts_path);
    node.host_map = host_map;
    node.peer_acl = peer_acl;

    let seeded: Vec<_> = node
        .config()
        .peers()
        .iter()
        .map(|pc| {
            let id = PeerIdentity::from_npub(&pc.npub).unwrap();
            let name = pc.alias.clone().unwrap_or_else(|| id.short_npub());
            (*id.node_addr(), name)
        })
        .collect();
    node.peer_aliases.extend(seeded);
    (dir, node)
}

/// The npub a name resolves to in the node's display host map.
fn resolved(node: &Node, name: &str) -> Option<String> {
    node.host_map.load().lookup_npub(name).map(String::from)
}

/// The ACL decision the node's authorization path would make for `id`.
fn decision(node: &Node, id: &Identity) -> PeerAclDecision {
    node.peer_acl.acl().check(&ident(id))
}

/// Aliases renamed, removed and moved by `update_peers` are reflected in the
/// display host map, in display names and in the stats snapshot, with the
/// hosts file still overlaid and winning as at startup.
#[tokio::test]
async fn update_peers_rebuilds_host_map_display_names_and_the_stats_snapshot_from_the_new_aliases()
{
    let s = suffix();
    let [a, b, c, d, e, f, g] = std::array::from_fn(|_| Identity::generate());
    let (alpha, alpha2, bravo) = (
        format!("alpha-{s}"),
        format!("alpha2-{s}"),
        format!("bravo-{s}"),
    );
    let (charlie, delta, echo) = (
        format!("charlie-{s}"),
        format!("delta-{s}"),
        format!("echo-{s}"),
    );
    let hosts = format!("{echo} {}\n{charlie} {}\n", f.npub(), g.npub());
    let (_dir, mut node) = alias_node(
        vec![
            peer(&a, Some(&alpha)),
            peer(&b, Some(&bravo)),
            peer(&d, Some(&delta)),
        ],
        None,
        None,
        Some(&hosts),
    );

    assert_eq!(resolved(&node, &alpha), Some(a.npub()), "before: alpha");
    assert_eq!(resolved(&node, &bravo), Some(b.npub()), "before: bravo");
    assert_eq!(
        resolved(&node, &echo),
        Some(f.npub()),
        "before: echo from file"
    );
    assert_eq!(node.peer_display_name(&addr(&a)), alpha, "before: A's name");
    assert_eq!(
        node.peer_aliases.get(&addr(&d)),
        Some(&delta),
        "before: D's seeded display entry"
    );
    assert_eq!(node.peer_display_name(&addr(&d)), delta, "before: D's name");

    node.update_peers(vec![
        peer(&a, Some(&alpha2)),
        peer(&c, Some(&charlie)),
        peer(&d, None),
        peer(&e, Some(&delta)),
    ])
    .await
    .unwrap();

    assert_eq!(
        resolved(&node, &alpha2),
        Some(a.npub()),
        "renamed alias resolves"
    );
    assert_eq!(resolved(&node, &alpha), None, "old name of a renamed alias");
    assert_eq!(resolved(&node, &bravo), None, "alias of a removed peer");
    assert_eq!(resolved(&node, &delta), Some(e.npub()), "moved alias");
    assert_eq!(resolved(&node, &echo), Some(f.npub()), "file entry kept");
    assert_eq!(
        resolved(&node, &charlie),
        Some(g.npub()),
        "file entry still wins over a peer alias"
    );

    let d_short = ident(&d).short_npub();
    assert_eq!(node.peer_display_name(&addr(&a)), alpha2, "renamed display");
    assert_eq!(node.peer_display_name(&addr(&e)), delta, "moved display");
    assert_eq!(
        node.peer_display_name(&addr(&d)),
        d_short,
        "a peer whose alias was removed shows its short npub"
    );

    node.record_stats_history();
    let snapshot = node.stats_snapshot.load();
    assert_eq!(
        snapshot.peer_aliases.get(&addr(&d)),
        Some(&d_short),
        "snapshot: removed alias"
    );
    assert_eq!(
        snapshot.peer_aliases.get(&addr(&a)),
        Some(&alpha2),
        "snapshot: renamed alias"
    );
}

/// A deny entry written as an alias follows the alias to its new npub: the
/// new key is refused and the old one is no longer denied.
#[tokio::test]
async fn update_peers_moves_a_deny_entry_written_as_an_alias_onto_the_new_npub() {
    let blocked = format!("blocked-{}", suffix());
    let [x, y] = std::array::from_fn(|_| Identity::generate());
    let (_dir, mut node) = alias_node(
        vec![peer(&x, Some(&blocked))],
        None,
        Some(&format!("{blocked}\n")),
        None,
    );
    assert_eq!(decision(&node, &x), PeerAclDecision::DenyList, "before: X");
    assert_eq!(
        decision(&node, &y),
        PeerAclDecision::DefaultAllow,
        "before: Y"
    );

    node.update_peers(vec![peer(&x, None), peer(&y, Some(&blocked))])
        .await
        .unwrap();

    assert_eq!(decision(&node, &y), PeerAclDecision::DenyList, "after: Y");
    assert_eq!(
        decision(&node, &x),
        PeerAclDecision::DefaultAllow,
        "after: X"
    );
}

/// Under deny `ALL`, an allow entry written as an alias follows the alias:
/// the new key is admitted and the old key falls to the deny.
#[tokio::test]
async fn update_peers_moves_an_allow_entry_written_as_an_alias_under_deny_all() {
    let trusted = format!("trusted-{}", suffix());
    let [a, b] = std::array::from_fn(|_| Identity::generate());
    let (_dir, mut node) = alias_node(
        vec![peer(&a, Some(&trusted))],
        Some(&format!("{trusted}\n")),
        Some("ALL\n"),
        None,
    );
    assert_eq!(decision(&node, &a), PeerAclDecision::AllowList, "before: A");
    assert_eq!(decision(&node, &b), PeerAclDecision::DenyList, "before: B");

    node.update_peers(vec![peer(&a, None), peer(&b, Some(&trusted))])
        .await
        .unwrap();

    assert_eq!(decision(&node, &b), PeerAclDecision::AllowList, "after: B");
    assert_eq!(decision(&node, &a), PeerAclDecision::DenyList, "after: A");
}

/// The rebuilt ACL is in force before `update_peers` dials an added peer: a
/// deny entry moved onto the added peer Y stops its dial, while a control
/// peer Z added in the same call is dialed.
#[tokio::test]
async fn update_peers_applies_the_rebuilt_acl_before_dialing_an_added_peer() {
    let blocked = format!("blocked-{}", suffix());
    let [x, y, z] = std::array::from_fn(|_| Identity::generate());
    let x_at = |alias| peer_at(&x, alias, "127.0.0.1:29", ConnectPolicy::OnDemand);
    let (_dir, mut node) = alias_node(
        vec![x_at(Some(&blocked))],
        None,
        Some(&format!("{blocked}\n")),
        None,
    );
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);
    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    node.update_peers(vec![
        x_at(None),
        peer_at(
            &y,
            Some(&blocked),
            "127.0.0.1:9",
            ConnectPolicy::AutoConnect,
        ),
        peer_at(&z, None, "127.0.0.1:19", ConnectPolicy::AutoConnect),
    ])
    .await
    .unwrap();

    let dialed: Vec<_> = node
        .connections()
        .filter_map(|(_, machine)| machine.conn_expected_identity().copied())
        .map(|id| *id.node_addr())
        .collect();
    assert_eq!(
        dialed.len(),
        1,
        "only the control peer is dialed; Y's dial must meet the moved deny entry"
    );
    assert_eq!(dialed[0], addr(&z), "the one dial is the control peer Z");

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

/// Send an AAAA query for `name` to the responder at `dns` and return the
/// address answered, or `None` for a reply without an answer. Fails if no
/// reply arrives within two seconds.
async fn query_aaaa(dns: std::net::SocketAddr, name: &str) -> Option<Ipv6Addr> {
    use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, TYPE};
    let mut packet = Packet::new_query(0x4242);
    packet.questions.push(Question::new(
        Name::new_unchecked(name).into_owned(),
        QTYPE::TYPE(TYPE::AAAA),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let query = packet.build_bytes_vec().unwrap();
    let client = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    client.send_to(&query, dns).await.unwrap();

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("no DNS reply for {name} within the timeout"))
        .unwrap();
    let reply = Packet::parse(&buf[..len]).expect("well-formed DNS response");
    reply.answers.first().map(|answer| match &answer.rdata {
        simple_dns::rdata::RData::AAAA(aaaa) => Ipv6Addr::from(aaaa.address),
        other => panic!("expected an AAAA record for {name}, got {other:?}"),
    })
}

/// A running DNS responder answers `.fips` alias names from the new peer
/// list after `update_peers`, through the node's real DNS start path.
#[tokio::test]
async fn update_peers_republishes_aliases_to_the_running_dns_responder() {
    let s = suffix();
    let (alpha, charlie, delta) = (
        format!("alpha-{s}"),
        format!("charlie-{s}"),
        format!("delta-{s}"),
    );
    let [a, b, c, d] = std::array::from_fn(|_| Identity::generate());
    let mut config = Config::new();
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    });
    config.dns.enabled = true;
    config.dns.bind_addr = Some("::1".to_string());
    config.dns.port = Some(0);
    config.peers = vec![peer(&a, Some(&alpha)), peer(&d, Some(&delta))];
    let mut node = make_node_with(config);
    node.start().await.unwrap();
    let dns = node.dns_local_addr().expect("responder is up");
    let fips = |name: &str| format!("{name}.fips");
    let v6 = |id: &Identity| id.address().to_ipv6();

    assert_eq!(
        query_aaaa(dns, &fips(&alpha)).await,
        Some(v6(&a)),
        "before: alpha"
    );
    assert_eq!(
        query_aaaa(dns, &fips(&charlie)).await,
        None,
        "before: charlie"
    );

    node.update_peers(vec![peer(&b, Some(&alpha)), peer(&c, Some(&charlie))])
        .await
        .unwrap();

    assert_eq!(
        query_aaaa(dns, &fips(&alpha)).await,
        Some(v6(&b)),
        "after: alpha moved to B"
    );
    assert_eq!(
        query_aaaa(dns, &fips(&charlie)).await,
        Some(v6(&c)),
        "after: charlie added"
    );
    assert_eq!(
        query_aaaa(dns, &fips(&delta)).await,
        None,
        "after: delta removed"
    );

    node.stop().await.unwrap();
}

/// `add_peer` appends a Nostr-resolved auto-connect peer and keeps the list it
/// was given; a repeat, the node itself and a bad npub change nothing.
#[tokio::test]
async fn add_peer_command_appends_a_nostr_peer() {
    let a = Identity::generate();
    let b = Identity::generate();
    let mut node = make_node();
    node.update_peers(vec![peer(&a, None)]).await.unwrap();

    let add = |npub: String| serde_json::json!({ "npub": npub });
    let response =
        crate::control::commands::dispatch(&mut node, "add_peer", Some(&add(b.npub()))).await;
    assert_eq!(response.status, "ok", "{:?}", response.message);
    assert_eq!(
        response.data,
        Some(serde_json::json!({ "added": true, "evicted": 0 }))
    );

    let peers = node.config().peers();
    assert_eq!(peers.len(), 2, "existing peer kept");
    assert!(
        peers.iter().any(|p| p.npub == a.npub()),
        "existing peer kept"
    );
    let added = peers
        .iter()
        .find(|p| p.npub == b.npub())
        .expect("added peer");
    assert!(added.via_nostr, "endpoints come from the advert");
    assert_eq!(added.connect_policy, ConnectPolicy::AutoConnect);
    assert!(
        !added.auto_reconnect,
        "a runtime peer is not redialed forever"
    );

    let response =
        crate::control::commands::dispatch(&mut node, "add_peer", Some(&add(b.npub()))).await;
    assert_eq!(
        response.data,
        Some(serde_json::json!({ "added": false, "redialed": false })),
        "just dialed, so no redial yet"
    );
    assert_eq!(node.config().peers().len(), 2);

    let own = node.identity().npub();
    let response = crate::control::commands::dispatch(&mut node, "add_peer", Some(&add(own))).await;
    assert_eq!(response.status, "error", "self is refused");
    let response =
        crate::control::commands::dispatch(&mut node, "add_peer", Some(&add("npub1nope".into())))
            .await;
    assert_eq!(response.status, "error", "bad npub is refused");
    let response = crate::control::commands::dispatch(&mut node, "add_peer", None).await;
    assert_eq!(response.status, "error", "missing npub is refused");
    assert_eq!(node.config().peers().len(), 2);
}

/// Runtime peers are capped: one past the cap drops the least recently
/// added, a re-added peer counts as fresh, and a start-time peer is never
/// dropped.
#[tokio::test]
async fn add_peer_evicts_the_stalest_runtime_peer_past_the_cap() {
    use crate::node::lifecycle::MAX_RUNTIME_PEERS;
    let start = Identity::generate();
    let mut node = make_node();
    node.update_peers(vec![peer(&start, None)]).await.unwrap();

    let added: Vec<Identity> = (0..MAX_RUNTIME_PEERS)
        .map(|_| Identity::generate())
        .collect();
    for id in &added {
        node.api_add_nostr_peer(&id.npub()).await.unwrap();
    }
    assert_eq!(node.config().peers().len(), MAX_RUNTIME_PEERS + 1);

    // Touch the oldest, so the second oldest is now the stalest.
    node.api_add_nostr_peer(&added[0].npub()).await.unwrap();
    let extra = Identity::generate();
    let data = node.api_add_nostr_peer(&extra.npub()).await.unwrap();
    assert_eq!(data["evicted"], 1);

    let has =
        |node: &Node, id: &Identity| node.config().peers().iter().any(|p| p.npub == id.npub());
    assert_eq!(node.config().peers().len(), MAX_RUNTIME_PEERS + 1);
    assert!(has(&node, &start), "start-time peer kept");
    assert!(has(&node, &added[0]), "recently touched peer kept");
    assert!(!has(&node, &added[1]), "stalest runtime peer dropped");
    assert!(has(&node, &extra));
}

/// Adding an unconnected runtime peer again redials it once the redial gap
/// has passed, and keeps it on the list.
#[tokio::test]
async fn add_peer_redials_an_unconnected_runtime_peer_after_the_gap() {
    let b = Identity::generate();
    let mut node = make_node();
    node.api_add_nostr_peer(&b.npub()).await.unwrap();

    let data = node.api_add_nostr_peer(&b.npub()).await.unwrap();
    assert_eq!(data["redialed"], false, "inside the gap");

    node.runtime_peers.back_mut().unwrap().1 = 0;
    let data = node.api_add_nostr_peer(&b.npub()).await.unwrap();
    assert_eq!(data["redialed"], true, "gap passed and not connected");
    assert_eq!(node.config().peers().len(), 1);
    assert_eq!(node.config().peers()[0].npub, b.npub());
    assert_eq!(node.runtime_peers.len(), 1);
    assert!(node.runtime_peers[0].1 > 0, "dial time refreshed");
}

/// Adding a peer dials only that peer: an earlier, unconnected runtime peer
/// is not re-dialed. A full `update_peers` does re-dial it, which is the
/// control that the probe below can see a dial at all.
#[tokio::test]
async fn add_peer_dials_only_the_added_peer() {
    let a = Identity::generate();
    let b = Identity::generate();
    let mut node = make_node();
    node.api_add_nostr_peer(&a.npub()).await.unwrap();

    let probe = |node: &Node| {
        node.peering
            .reconciler
            .retry_pending
            .get(&addr(&a))
            .map(|s| (s.retry_count, s.retry_after_ms))
    };
    let before = probe(&node);

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    node.api_add_nostr_peer(&b.npub()).await.unwrap();
    assert_eq!(probe(&node), before, "adding b must not re-dial a");

    let list = node.config().peers().to_vec();
    node.update_peers(list).await.unwrap();
    assert_ne!(
        probe(&node),
        before,
        "control: a full refresh does re-dial a"
    );
}

/// A runtime peer that never connects is given up after `max_retries`
/// failures; a start-time peer (auto-reconnect) keeps retrying. Both reach
/// the retry state through the handshake-timeout reflex, the path a failed
/// advert dial takes.
#[tokio::test]
async fn a_runtime_peer_is_given_up_after_max_retries() {
    let start = Identity::generate();
    let added = Identity::generate();
    let mut node = make_node();
    let mut start_peer = peer(&start, None);
    start_peer.connect_policy = ConnectPolicy::AutoConnect;
    start_peer.auto_reconnect = true;
    node.update_peers(vec![start_peer]).await.unwrap();
    node.api_add_nostr_peer(&added.npub()).await.unwrap();

    let max_retries = node.config().node.retry.max_retries;
    assert!(max_retries > 0);
    let mut given_up = false;
    for _ in 0..=max_retries {
        node.note_handshake_timeout(addr(&start), Node::now_ms());
        node.note_handshake_timeout(addr(&added), Node::now_ms());
        let pending = &node.peering.reconciler.retry_pending;
        assert!(
            pending.contains_key(&addr(&start)),
            "control: start-time peer still retried"
        );
        if !pending.contains_key(&addr(&added)) {
            given_up = true;
            break;
        }
    }
    // Once given up, nothing schedules another dial, so no further timeout
    // can re-create the entry.
    assert!(
        given_up,
        "runtime peer given up within max_retries failures"
    );
}
