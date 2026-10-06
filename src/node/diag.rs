//! Shared field vocabulary for diagnostic log lines.
//!
//! Lines about one link at both of its ends use the same field names and the
//! same renderings, so two nodes' logs can be joined on them: the transport
//! and address a message arrived on, the peer's established link and whether
//! the two are the same path, a 4-byte prefix of a msg1's digest, and a
//! 4-byte prefix of a session's handshake hash, which both ends of a session
//! hold. Every value here displays without spaces, and an absent one as
//! `none`.

use crate::noise::NoiseSession;
use crate::proto::fmp::Msg1Digest;
use crate::transport::{TransportAddr, TransportId};
use std::fmt;

/// A 4-byte prefix of a digest or hash, displayed as 8 lowercase hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tag4([u8; 4]);

impl fmt::Display for Tag4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// The session's tag: the first four bytes of its handshake hash. Both ends
/// of a session derive the same hash, so both ends' lines carry the same tag.
pub(crate) fn epoch_tag(session: &NoiseSession) -> Tag4 {
    let h = session.handshake_hash();
    Tag4([h[0], h[1], h[2], h[3]])
}

/// The msg1's tag: the first four bytes of its digest.
pub(crate) fn msg1_tag(digest: &Msg1Digest) -> Tag4 {
    Tag4(digest.prefix())
}

/// Displays the value, or `none` when there is none.
pub(crate) struct OrNone<T>(pub(crate) Option<T>);

impl<T: fmt::Display> fmt::Display for OrNone<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(v) => v.fmt(f),
            None => f.write_str("none"),
        }
    }
}

/// Where a msg1 arrived, against the peer's established link.
pub(crate) struct Msg1Path {
    link: Option<(TransportId, TransportAddr)>,
    same: bool,
}

impl Msg1Path {
    /// A msg1 that arrived on `tid` from `addr`, for a peer whose
    /// established link is `link` (`None` when it has none).
    pub(crate) fn new(
        tid: TransportId,
        addr: &TransportAddr,
        link: Option<(TransportId, TransportAddr)>,
    ) -> Self {
        let same = link.as_ref().is_some_and(|(t, a)| *t == tid && a == addr);
        Self { link, same }
    }

    /// Whether the msg1 arrived on the established link's own transport and
    /// address. False with no established link.
    pub(crate) fn same_path(&self) -> bool {
        self.same
    }

    /// The established link's transport.
    pub(crate) fn link_tid(&self) -> OrNone<TransportId> {
        OrNone(self.link.as_ref().map(|(t, _)| *t))
    }

    /// The established link's address.
    pub(crate) fn link_addr(&self) -> OrNone<&TransportAddr> {
        OrNone(self.link.as_ref().map(|(_, a)| a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_renders_exactly_the_first_four_bytes_of_a_msg1_digest() {
        let wire = b"a msg1";
        let digest = Msg1Digest::of(wire);
        let full: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(wire).into()
        };
        let want: String = full[..4].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(msg1_tag(&digest).to_string(), want);
        assert_eq!(Tag4([0x00, 0x0a, 0xb0, 0xff]).to_string(), "000ab0ff");
    }

    #[test]
    fn an_absent_value_renders_as_none() {
        assert_eq!(OrNone::<u32>(None).to_string(), "none");
        assert_eq!(OrNone(Some(7u32)).to_string(), "7");
    }

    #[test]
    fn same_path_holds_only_for_the_established_transport_and_address() {
        let addr = TransportAddr::from_string("10.0.0.1:2121");
        let other = TransportAddr::from_string("10.0.0.2:2121");
        let t1 = TransportId::new(1);
        let t2 = TransportId::new(2);
        let link = Some((t1, addr.clone()));

        assert!(Msg1Path::new(t1, &addr, link.clone()).same_path());
        assert!(!Msg1Path::new(t2, &addr, link.clone()).same_path());
        assert!(!Msg1Path::new(t1, &other, link.clone()).same_path());

        let none = Msg1Path::new(t1, &addr, None);
        assert!(!none.same_path());
        assert_eq!(none.link_tid().to_string(), "none");
        assert_eq!(none.link_addr().to_string(), "none");

        let p = Msg1Path::new(t2, &other, link);
        assert_eq!(p.link_tid().to_string(), "transport:1");
        assert_eq!(p.link_addr().to_string(), "10.0.0.1:2121");
    }
}
