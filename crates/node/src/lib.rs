//! Boltchain node library: devnet producer, follower, benchmarks, used by the `boltchain` binary.

/// Version with the source commit, e.g. `0.1.0-9ffeafb` (see `build.rs`).
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-", env!("BOLT_COMMIT"));

/// Client name and version, e.g. `boltchain/v0.1.0-9ffeafb` (explorer, `web3_clientVersion`).
pub const CLIENT_VERSION: &str =
    concat!("boltchain/v", env!("CARGO_PKG_VERSION"), "-", env!("BOLT_COMMIT"));

/// Raises this process's open-file limit to the hard limit (capped at 1,048,576). A node holds a
/// socket per connection, stream server and client plus its database files; the usual soft
/// limit of 1,024 is reached long before the hard one (testnet, 2026-10-11). Returns the limit
/// in force.
#[cfg(unix)]
#[allow(unsafe_code)]
pub fn raise_open_file_limit() -> Option<u64> {
    let mut l = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit/setrlimit only read and write the struct passed to them.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut l) } != 0 {
        return None;
    }
    let want = l.rlim_max.min(1 << 20);
    if l.rlim_cur < want {
        let before = l.rlim_cur;
        l.rlim_cur = want;
        // SAFETY: as above.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &l) } == 0 {
            tracing::debug!(before, after = want, "raised the open-file limit");
        } else {
            l.rlim_cur = before;
        }
    }
    #[allow(clippy::unnecessary_cast)] // rlim_t is not u64 everywhere
    let limit = l.rlim_cur as u64;
    if limit < 8192 {
        tracing::warn!(
            limit,
            "open-file limit is low; raise it (ulimit -n) for a long-running node"
        );
    }
    Some(limit)
}

/// Not needed off Unix.
#[cfg(not(unix))]
pub fn raise_open_file_limit() -> Option<u64> {
    None
}

pub mod attest;
pub mod bench;
pub mod certificates;
pub mod checkpoint;
pub mod compute;
pub mod devnet;
pub mod explorer;
pub mod follow;
pub mod gateway;
pub mod keys;
pub mod keystore;
pub mod market;
pub mod metrics;
pub mod miner;
pub mod p2p;
pub mod relay;
pub mod storage;
pub mod swarm;
pub mod tee;
pub mod validator;
pub mod wallet;
