//! Node census: which Boltchain nodes are online, the software they run, and a public address to
//! locate them by (the explorer turns it into a country).
//!
//! Two sources:
//!
//! * Peers this node is connected to: the version from identify, the address from the
//!   connection itself (or the peer's public listen addresses when we reach it over a private
//!   network or a relay).
//! * Heartbeats: every node gossips a small signed [`NodeInfo`] on `/bolt/<chain id>/nodes`
//!   every [`HEARTBEAT`]: its version and its public addresses (confirmed external addresses and
//!   the ones peers observe it at). Gossipsub signs messages with the author's key, so a node can
//!   only speak for itself; the addresses are its own claim.
//!
//! Records expire after [`EXPIRY`]; the book holds at most [`MAX_NODES`].

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};

/// How often a node announces itself.
pub const HEARTBEAT: Duration = Duration::from_secs(10 * 60);
/// A node not heard from for this long is no longer counted.
pub const EXPIRY: Duration = Duration::from_secs(35 * 60);
/// Largest number of nodes remembered (oldest dropped first).
pub const MAX_NODES: usize = 10_000;
/// Heartbeats older or newer than this (by their own clock) are ignored.
pub const MAX_SKEW_SECS: u64 = 15 * 60;
/// Largest heartbeat accepted.
pub const MAX_INFO_BYTES: usize = 2048;
/// Heartbeats accepted per author per this period (more are ignored).
pub const MIN_INTERVAL: Duration = Duration::from_secs(120);

/// A node's heartbeat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Format version (1).
    pub v: u8,
    /// The author's peer id (must match the gossip author; keeps identical heartbeats of two
    /// nodes from sharing a message id).
    pub peer: serde_bytes::ByteBuf,
    /// Software, e.g. `boltchain/v0.1.0-c01aee5`.
    pub agent: String,
    /// Public addresses (multiaddr bytes), at most 8.
    pub addrs: Vec<serde_bytes::ByteBuf>,
    /// Unix seconds when sent.
    pub at: u64,
}

impl NodeInfo {
    /// DAG-CBOR encoding.
    pub fn encode(&self) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(self).expect("node info encodes")
    }

    /// Decodes and bounds-checks a heartbeat.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() > MAX_INFO_BYTES {
            return None;
        }
        let i: Self = serde_ipld_dagcbor::from_slice(b).ok()?;
        (i.v == 1 && i.agent.len() <= 128 && i.addrs.len() <= 8).then_some(i)
    }
}

/// What the census knows about one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    /// Peer id.
    pub peer: PeerId,
    /// Software, e.g. `boltchain/v0.1.0-c01aee5` (first word of the identify agent string).
    pub version: String,
    /// Public IP addresses, best first (seen by this node before claimed by the node).
    pub ips: Vec<IpAddr>,
    /// Unix seconds when last heard from.
    pub seen: u64,
    /// Connected to this node.
    pub direct: bool,
    /// This node itself.
    pub local: bool,
}

#[derive(Debug, Default)]
struct Inner {
    nodes: HashMap<PeerId, NodeRecord>,
    accepted: HashMap<PeerId, std::time::Instant>,
}

/// Shared census, read by the explorer.
#[derive(Debug, Clone, Default)]
pub struct NodeBook(Arc<Mutex<Inner>>);

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Software name in an identify agent string (`boltchain/v0.1.0-abc fork/…` → its first word).
pub fn version_of(agent: &str) -> String {
    agent.split_whitespace().next().unwrap_or("").chars().take(64).collect()
}

/// The IP of an address when it is a public one (not a relay circuit).
pub fn public_ip(a: &Multiaddr) -> Option<IpAddr> {
    if a.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
        return None;
    }
    let ip = a.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })?;
    is_public(&ip).then_some(ip)
}

/// Globally routable unicast address.
pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            !(ip.is_loopback()
                || ip.is_private()
                || ip.is_unspecified()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || o[0] >= 240)
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] == 0x2001 && s[1] == 0x0db8))
                && ip.to_ipv4_mapped().is_none_or(|v4| is_public(&IpAddr::V4(v4)))
        }
    }
}

fn merge_ips(first: &[IpAddr], then: &[IpAddr]) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for ip in first.iter().chain(then) {
        if !out.contains(ip) && out.len() < 8 {
            out.push(*ip);
        }
    }
    out
}

impl NodeBook {
    fn put(&self, inner: &mut Inner, rec: NodeRecord) {
        if !inner.nodes.contains_key(&rec.peer) && inner.nodes.len() >= MAX_NODES {
            let oldest =
                inner.nodes.values().filter(|r| !r.local).min_by_key(|r| r.seen).map(|r| r.peer);
            if let Some(p) = oldest {
                inner.nodes.remove(&p);
                inner.accepted.remove(&p);
            }
        }
        inner.nodes.insert(rec.peer, rec);
    }

    /// A connected peer identified itself. `conn_ip`: the public IP of our connection to it.
    pub fn observe_peer(
        &self,
        peer: PeerId,
        agent: &str,
        conn_ip: Option<IpAddr>,
        listen: &[Multiaddr],
    ) {
        let mut inner = self.0.lock();
        let listen_ips: Vec<IpAddr> = listen.iter().filter_map(public_ip).collect();
        let old = inner.nodes.get(&peer).map(|r| r.ips.clone()).unwrap_or_default();
        let ips =
            merge_ips(&merge_ips(&conn_ip.into_iter().collect::<Vec<_>>(), &listen_ips), &old);
        let rec = NodeRecord {
            peer,
            version: version_of(agent),
            ips,
            seen: now_secs(),
            direct: true,
            local: false,
        };
        self.put(&mut inner, rec);
    }

    /// A connected peer is gone (it stays counted until it expires).
    pub fn disconnected(&self, peer: &PeerId) {
        if let Some(r) = self.0.lock().nodes.get_mut(peer) {
            r.direct = false;
        }
    }

    /// A heartbeat signed by `author`. Returns whether it was accepted (and should be relayed).
    pub fn heartbeat(&self, author: PeerId, info: &NodeInfo) -> bool {
        let now = now_secs();
        if info.at.abs_diff(now) > MAX_SKEW_SECS || info.peer.as_slice() != author.to_bytes() {
            return false;
        }
        let mut inner = self.0.lock();
        let t = std::time::Instant::now();
        if inner.accepted.get(&author).is_some_and(|a| t.duration_since(*a) < MIN_INTERVAL) {
            return false;
        }
        inner.accepted.insert(author, t);
        let claimed: Vec<IpAddr> = info
            .addrs
            .iter()
            .filter_map(|b| Multiaddr::try_from(b.to_vec()).ok())
            .filter_map(|a| public_ip(&a))
            .collect();
        let (seen_ips, direct) = inner
            .nodes
            .get(&author)
            .map(|r| (if r.direct { r.ips.clone() } else { vec![] }, r.direct))
            .unwrap_or_default();
        let rec = NodeRecord {
            peer: author,
            version: version_of(&info.agent),
            ips: merge_ips(&seen_ips, &claimed),
            seen: now,
            direct,
            local: false,
        };
        self.put(&mut inner, rec);
        true
    }

    /// This node's own entry.
    pub fn set_local(&self, peer: PeerId, agent: &str, addrs: &[Multiaddr]) {
        let mut inner = self.0.lock();
        let ips: Vec<IpAddr> = addrs.iter().filter_map(public_ip).collect();
        let rec = NodeRecord {
            peer,
            version: version_of(agent),
            ips: merge_ips(&ips, &[]),
            seen: now_secs(),
            direct: false,
            local: true,
        };
        self.put(&mut inner, rec);
    }

    /// Nodes heard from within [`EXPIRY`] (expired ones are dropped).
    pub fn nodes(&self) -> Vec<NodeRecord> {
        let cutoff = now_secs().saturating_sub(EXPIRY.as_secs());
        let mut inner = self.0.lock();
        inner.nodes.retain(|_, r| r.local || r.direct || r.seen >= cutoff);
        let mut v: Vec<NodeRecord> = inner.nodes.values().cloned().collect();
        v.sort_by_key(|r| r.peer.to_bytes());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_addresses_only() {
        assert_eq!(
            public_ip(&ma("/ip4/211.22.118.149/udp/8017/quic-v1")),
            Some("211.22.118.149".parse().unwrap())
        );
        for a in [
            "/ip4/127.0.0.1/tcp/1",
            "/ip4/192.168.1.2/tcp/1",
            "/ip4/100.64.0.1/tcp/1",
            "/ip4/0.0.0.0/tcp/1",
            "/ip6/fe80::1/tcp/1",
            "/ip6/fd00::1/tcp/1",
            "/ip4/1.2.3.4/tcp/1/p2p/12D3KooWDypD3MtXm8HxHV2fpt2banWaWDsNXMmmhwLNAePTS1Zx/p2p-circuit",
        ] {
            assert_eq!(public_ip(&ma(a)), None, "{a}");
        }
        assert!(public_ip(&ma("/ip6/2001:4860::8888/tcp/1")).is_some());
    }

    #[test]
    fn census_merges_sources_and_limits_heartbeats() {
        let book = NodeBook::default();
        let (a, b) = (PeerId::random(), PeerId::random());
        book.observe_peer(a, "boltchain/v0.1.0-abc fork/12-0", None, &[ma("/ip4/127.0.0.1/tcp/1")]);
        let info = |ip: &str| NodeInfo {
            v: 1,
            peer: serde_bytes::ByteBuf::from(a.to_bytes()),
            agent: "boltchain/v0.1.0-abc fork/12-0".into(),
            addrs: vec![serde_bytes::ByteBuf::from(ma(&format!("/ip4/{ip}/tcp/8017")).to_vec())],
            at: now_secs(),
        };
        // Reached over loopback: the heartbeat supplies the public address.
        assert!(book.heartbeat(a, &info("8.8.8.8")));
        assert!(!book.heartbeat(a, &info("9.9.9.9")), "too soon");
        let mut ib = info("1.1.1.1");
        assert!(!book.heartbeat(b, &ib), "signed by another peer");
        ib.peer = serde_bytes::ByteBuf::from(b.to_bytes());
        assert!(book.heartbeat(b, &NodeInfo::decode(&ib.encode()).unwrap()));
        let c = PeerId::random();
        let stale =
            NodeInfo { at: 1, peer: serde_bytes::ByteBuf::from(c.to_bytes()), ..info("1.1.1.1") };
        assert!(!book.heartbeat(c, &stale), "stale");
        book.set_local(PeerId::random(), "boltchain/v0.1.0-def fork/12-0", &[]);
        let n = book.nodes();
        assert_eq!(n.len(), 3);
        let ra = n.iter().find(|r| r.peer == a).unwrap();
        assert_eq!((ra.version.as_str(), ra.direct), ("boltchain/v0.1.0-abc", true));
        assert_eq!(ra.ips, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
        // A seen address comes before a claimed one.
        book.observe_peer(b, "boltchain/v0.1.0-abc", Some("5.5.5.5".parse().unwrap()), &[]);
        let rb = book.nodes().into_iter().find(|r| r.peer == b).unwrap();
        assert_eq!(rb.ips[0], "5.5.5.5".parse::<IpAddr>().unwrap());
        assert!(NodeInfo::decode(&vec![0u8; MAX_INFO_BYTES + 1]).is_none());
    }
}
