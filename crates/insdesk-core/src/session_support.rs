//! Small helpers shared by the host and controller engines.

use insdesk_crypto::{auth_proof, verify_auth_proof};
use insdesk_fs::transfer::OutStep;
use insdesk_fs::OutboundTransfer;
use insdesk_net::SessionSender;
use insdesk_proto::{FileMsg, Message};

/// Stream an outbound file on a blocking task so disk IO never stalls the async
/// runtime. Shared by both the host (answering a download) and the controller
/// (performing an upload).
pub fn stream_outbound(mut out: OutboundTransfer, sender: SessionSender) {
    tokio::task::spawn_blocking(move || loop {
        match out.next(insdesk_fs::DEFAULT_CHUNK) {
            Ok(OutStep::Chunk(m)) => {
                if sender.blocking_send(Message::File(m)).is_err() {
                    break;
                }
            }
            Ok(OutStep::Done(m)) => {
                let _ = sender.blocking_send(Message::File(m));
                break;
            }
            Err(e) => {
                let _ = sender.blocking_send(Message::File(FileMsg::TransferAbort {
                    transfer: out.transfer_id(),
                    reason: e.to_string(),
                }));
                break;
            }
        }
    });
}

/// Channel-bound password authentication.
///
/// Both sides compute the proof over the empty string when no password is set,
/// so an unauthenticated session still exchanges a (matching) proof and the
/// code path is uniform.
pub struct SessionAuth {
    pub password: Option<String>,
}

impl SessionAuth {
    /// Produce the proof this side should send (controller side).
    pub fn make_proof(&self, handshake_hash: &[u8]) -> Vec<u8> {
        auth_proof(self.password.as_deref().unwrap_or(""), handshake_hash)
    }

    /// Verify a received proof (host side). A host with no password accepts any
    /// proof; a host with a password requires an exact channel-bound match.
    pub fn verify(&self, handshake_hash: &[u8], proof: &[u8]) -> bool {
        match &self.password {
            None => true,
            Some(pw) => verify_auth_proof(pw, handshake_hash, proof),
        }
    }
}

/// Decide whether to accept an incoming session.
///
/// Today this simply honors the unattended-access policy. An interactive host
/// binary can replace this with a real user prompt before the session starts.
pub fn compute_accept(auto_accept: bool) -> bool {
    auto_accept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_password_accepts_anything() {
        let host = SessionAuth { password: None };
        assert!(host.verify(&[9u8; 32], b"whatever"));
    }

    #[test]
    fn password_requires_matching_channel_bound_proof() {
        let hh = [7u8; 32];
        let ctrl = SessionAuth { password: Some("s3cret".into()) };
        let host = SessionAuth { password: Some("s3cret".into()) };
        let proof = ctrl.make_proof(&hh);
        assert!(host.verify(&hh, &proof));

        let wrong = SessionAuth { password: Some("nope".into()) };
        assert!(!host.verify(&hh, &wrong.make_proof(&hh)));
    }
}
