//! A msg2 that does not authenticate leaves an initial (IK) dial's handshake
//! where it was, so the genuine msg2 can still complete it.
//!
//! The index a msg2 names travels in cleartext in our msg1, so anyone who saw
//! the msg1 can send a msg2 under it. These tests drive
//! [`PeerMachine::complete_handshake`] directly because the wire parser drops a
//! msg2 of the wrong length before it reaches the machine, so a short one
//! cannot be delivered from the node.

use super::*;
use crate::noise::HANDSHAKE_MSG2_SIZE;
use crate::{Identity, PeerIdentity};

/// An initiator that has sent msg1, and the genuine msg2 the responder answered
/// it with.
fn dial_with_genuine_msg2() -> (PeerMachine, Vec<u8>) {
    let initiator = Identity::generate();
    let responder = Identity::generate();
    let responder_id = PeerIdentity::from_pubkey_full(responder.pubkey_full());

    let mut ini = PeerMachine::new_outbound(LinkId::new(1), responder_id, 1000);
    ini.set_leg(HandshakeCrypto::new());
    let mut res = PeerMachine::new_inbound(LinkId::new(2), 1000);
    res.set_leg(HandshakeCrypto::new());

    let msg1 = ini
        .start_handshake(initiator.keypair(), [1; 8], 1100)
        .expect("msg1 is written");
    let msg2 = res
        .receive_handshake_init(responder.keypair(), [2; 8], &msg1, 1200)
        .expect("the responder answers msg1");
    (ini, msg2)
}

/// True when the leg still holds the handshake handle, i.e. the attempt can
/// still read a msg2.
fn handle_kept(machine: &PeerMachine) -> bool {
    machine
        .leg()
        .is_some_and(|leg| leg.noise_handshake.is_some())
}

/// Deliver `forged`, check it is refused with the handshake kept and nothing
/// else changed, then check the genuine msg2 still completes the session.
fn forged_then_genuine(forged: &[u8]) {
    let (mut ini, genuine) = dial_with_genuine_msg2();
    let activity = ini.conn_last_activity();

    assert!(
        ini.complete_handshake(forged, 1300).is_err(),
        "a msg2 that does not authenticate must be refused"
    );
    assert!(
        handle_kept(&ini),
        "a refused msg2 must leave the handshake in the leg"
    );
    assert!(!ini.has_session(), "a refused msg2 must not make a session");
    assert_eq!(
        ini.conn_remote_epoch(),
        None,
        "a refused msg2 must not set the remote epoch"
    );
    assert_eq!(
        ini.conn_last_activity(),
        activity,
        "a refused msg2 must not count as activity on the attempt"
    );

    ini.complete_handshake(&genuine, 1400)
        .expect("the genuine msg2 must still complete the handshake");
    assert!(ini.has_session(), "the genuine msg2 makes the session");
    assert_eq!(ini.conn_remote_epoch(), Some([2; 8]));
}

#[test]
fn a_too_short_msg2_keeps_the_handshake_for_the_genuine_one() {
    let (_, genuine) = dial_with_genuine_msg2();
    forged_then_genuine(&genuine[..HANDSHAKE_MSG2_SIZE - 1]);
}

#[test]
fn a_msg2_with_an_invalid_ephemeral_keeps_the_handshake_for_the_genuine_one() {
    // 0xFF is not a valid compressed-point prefix.
    forged_then_genuine(&[0xFF; HANDSHAKE_MSG2_SIZE]);
}

#[test]
fn a_garbage_full_length_msg2_keeps_the_handshake_for_the_genuine_one() {
    // A valid point followed by bytes that do not authenticate: the read gets
    // as far as both DH operations before the AEAD check fails.
    let mut forged = Identity::generate().pubkey_full().serialize().to_vec();
    forged.resize(HANDSHAKE_MSG2_SIZE, 0xA5);
    forged_then_genuine(&forged);
}

#[test]
fn several_forged_msg2s_in_a_row_still_leave_the_genuine_one_readable() {
    let (mut ini, genuine) = dial_with_genuine_msg2();
    let mut garbage = Identity::generate().pubkey_full().serialize().to_vec();
    garbage.resize(HANDSHAKE_MSG2_SIZE, 0x5A);
    for forged in [
        &garbage[..],
        &[0xFF; HANDSHAKE_MSG2_SIZE][..],
        &[0u8; 3][..],
    ] {
        assert!(ini.complete_handshake(forged, 1300).is_err());
        assert!(handle_kept(&ini));
    }
    ini.complete_handshake(&genuine, 1400)
        .expect("the genuine msg2 must still complete the handshake");
    assert!(ini.has_session());
}
