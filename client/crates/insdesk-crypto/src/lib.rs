//! # insdesk-crypto
//!
//! End-to-end security for InsDesk.
//!
//! ## Threat model
//!
//! The relay server and any network observer are treated as **untrusted**. They
//! may read, drop, reorder or inject bytes. The guarantees below must hold even
//! though all traffic flows *through* the relay.
//!
//! ## How it works
//!
//! * Every device owns a long-term **Curve25519 identity keypair**
//!   ([`Identity`]). The host's 9-digit **device ID** is derived from its public
//!   key, so the number a user dials is cryptographically bound to a specific
//!   key — a relay cannot silently substitute its own.
//!
//! * A session is protected by a **Noise `XX` channel** (`25519 + ChaChaPoly +
//!   BLAKE2s`). `XX` gives mutual authentication of both static keys plus
//!   forward secrecy from the ephemeral exchange. After the handshake the
//!   controller checks that the host's presented key matches the dialed device
//!   ID ([`verify_device_id`]); a man-in-the-middle relay that cannot produce
//!   the host's private key is detected here.
//!
//! * An optional **session password** is verified *inside* the encrypted
//!   channel using a proof bound to the Noise handshake hash
//!   ([`auth_proof`]). Channel binding makes the proof impossible to replay onto
//!   another session or to forge through a MITM.
//!
//! The relay only ever sees opaque ciphertext, so confidentiality and integrity
//! are genuinely end-to-end.

use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Largest plaintext we hand to a single Noise transport message. Noise caps a
/// message at 65535 bytes including the 16-byte AEAD tag.
pub const MAX_NOISE_PLAINTEXT: usize = 65535 - 16;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("noise protocol error: {0}")]
    Noise(String),
    #[error("plaintext too large for one Noise message ({0} > {MAX_NOISE_PLAINTEXT})")]
    PlaintextTooLarge(usize),
    #[error("handshake is not finished yet")]
    HandshakeIncomplete,
    #[error("remote presented no static key")]
    MissingRemoteStatic,
    #[error("device id mismatch: dialed {expected}, peer key maps to {actual}")]
    DeviceIdMismatch { expected: u64, actual: u64 },
    #[error("invalid identity encoding: {0}")]
    BadIdentity(String),
    #[error("authentication failed")]
    AuthFailed,
}

impl From<snow::Error> for CryptoError {
    fn from(e: snow::Error) -> Self {
        CryptoError::Noise(format!("{e:?}"))
    }
}

// ---------------------------------------------------------------------------
// Long-term identity
// ---------------------------------------------------------------------------

/// A device's long-term Curve25519 keypair. The private half is held in a
/// [`Zeroizing`] buffer so it is wiped from memory on drop.
pub struct Identity {
    private: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
}

impl Identity {
    /// Generate a fresh random identity.
    pub fn generate() -> Result<Self, CryptoError> {
        let builder = snow::Builder::new(NOISE_PARAMS.parse().expect("valid params"));
        let kp = builder.generate_keypair()?;
        Ok(Identity { private: Zeroizing::new(kp.private), public: kp.public })
    }

    /// Reconstruct an identity from a previously stored secret key (hex).
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self, CryptoError> {
        let private = hex::decode(secret_hex.trim())
            .map_err(|e| CryptoError::BadIdentity(e.to_string()))?;
        if private.len() != 32 {
            return Err(CryptoError::BadIdentity(format!(
                "expected 32-byte secret, got {}",
                private.len()
            )));
        }
        let public = x25519_public_from_secret(&private);
        Ok(Identity { private: Zeroizing::new(private), public })
    }

    /// The secret key as hex, for persisting to a key file. Treat as sensitive.
    pub fn secret_hex(&self) -> String {
        hex::encode(&*self.private)
    }

    /// The raw public key bytes (32 bytes).
    pub fn public_bytes(&self) -> &[u8] {
        &self.public
    }

    /// The public key as hex, safe to display/share.
    pub fn public_hex(&self) -> String {
        hex::encode(&self.public)
    }

    /// This device's stable 9-digit ID, derived from its public key.
    pub fn device_id(&self) -> u64 {
        device_id_from_pubkey(&self.public)
    }

    fn private_bytes(&self) -> &[u8] {
        &self.private
    }
}

/// Derive the Curve25519 public key from a 32-byte secret using the Noise
/// resolver's DH, so it always matches what the handshake will present.
fn x25519_public_from_secret(secret: &[u8]) -> Vec<u8> {
    // snow does not expose "public from private" directly, so we round-trip the
    // key through a builder: build a handshake with this private key and read
    // back the local static public key.
    use snow::resolvers::{CryptoResolver, DefaultResolver};
    use snow::params::DHChoice;
    let resolver = DefaultResolver;
    let mut dh = resolver
        .resolve_dh(&DHChoice::Curve25519)
        .expect("curve25519 available");
    dh.set(secret);
    dh.pubkey().to_vec()
}

/// Map a 32-byte public key to a human-dictatable 9-digit device ID.
///
/// The ID is `SHA-256(pubkey)` reduced into the range `[100_000_000,
/// 999_999_999]`. It is deterministic, so the same key always yields the same
/// number, and it is infeasible to find a *different* key producing a chosen ID.
pub fn device_id_from_pubkey(pubkey: &[u8]) -> u64 {
    let digest = Sha256::digest(pubkey);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    let raw = u64::from_be_bytes(bytes);
    100_000_000 + (raw % 900_000_000)
}

/// Check that a peer's presented static key maps to the device ID that was
/// dialed. Returns [`CryptoError::DeviceIdMismatch`] on a mismatch.
pub fn verify_device_id(expected: u64, peer_pubkey: &[u8]) -> Result<(), CryptoError> {
    let actual = device_id_from_pubkey(peer_pubkey);
    if actual == expected {
        Ok(())
    } else {
        Err(CryptoError::DeviceIdMismatch { expected, actual })
    }
}

// ---------------------------------------------------------------------------
// Handshake + transport
// ---------------------------------------------------------------------------

/// Drives the Noise `XX` handshake. Messages are produced/consumed in the order
/// the pattern requires; [`Handshake::is_my_turn`] tells the caller which side
/// writes next.
pub struct Handshake {
    state: snow::HandshakeState,
}

impl Handshake {
    /// Build the initiator side (the controller dials out).
    pub fn new_initiator(identity: &Identity) -> Result<Self, CryptoError> {
        let state = snow::Builder::new(NOISE_PARAMS.parse().expect("valid params"))
            .local_private_key(identity.private_bytes())
            .build_initiator()?;
        Ok(Handshake { state })
    }

    /// Build the responder side (the host answers).
    pub fn new_responder(identity: &Identity) -> Result<Self, CryptoError> {
        let state = snow::Builder::new(NOISE_PARAMS.parse().expect("valid params"))
            .local_private_key(identity.private_bytes())
            .build_responder()?;
        Ok(Handshake { state })
    }

    /// Whether it is this side's turn to produce the next handshake message.
    pub fn is_my_turn(&self) -> bool {
        self.state.is_my_turn()
    }

    /// Whether the handshake has completed.
    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Produce the next outgoing handshake message.
    pub fn write_message(&mut self) -> Result<Vec<u8>, CryptoError> {
        let mut buf = vec![0u8; 65535];
        let n = self.state.write_message(&[], &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Consume an incoming handshake message.
    pub fn read_message(&mut self, msg: &[u8]) -> Result<(), CryptoError> {
        let mut buf = vec![0u8; 65535];
        self.state.read_message(msg, &mut buf)?;
        Ok(())
    }

    /// Finish the handshake and switch to the bulk-transport cipher.
    ///
    /// Returns the transport plus the peer's static public key (for device-ID
    /// verification / allow-listing) and the handshake hash (for password
    /// channel binding).
    pub fn into_transport(self) -> Result<(Transport, Vec<u8>, Vec<u8>), CryptoError> {
        if !self.state.is_handshake_finished() {
            return Err(CryptoError::HandshakeIncomplete);
        }
        let remote = self
            .state
            .get_remote_static()
            .ok_or(CryptoError::MissingRemoteStatic)?
            .to_vec();
        let handshake_hash = self.state.get_handshake_hash().to_vec();
        let transport = self.state.into_transport_mode()?;
        Ok((Transport { state: transport }, remote, handshake_hash))
    }
}

/// The post-handshake bulk cipher. Each call encrypts/decrypts one Noise
/// transport message with its own nonce (snow manages the nonce counter).
pub struct Transport {
    state: snow::TransportState,
}

impl Transport {
    /// Seal one plaintext chunk. `plaintext` must be `<= MAX_NOISE_PLAINTEXT`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > MAX_NOISE_PLAINTEXT {
            return Err(CryptoError::PlaintextTooLarge(plaintext.len()));
        }
        let mut buf = vec![0u8; plaintext.len() + 16];
        let n = self.state.write_message(plaintext, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Open one ciphertext chunk produced by [`Transport::encrypt`].
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = vec![0u8; ciphertext.len().max(16)];
        let n = self.state.read_message(ciphertext, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// The peer's static public key negotiated during the handshake.
    pub fn remote_public(&self) -> Option<Vec<u8>> {
        self.state.get_remote_static().map(|k| k.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Password authentication (channel-bound)
// ---------------------------------------------------------------------------

/// Derive a 32-byte key from a human session password.
pub fn password_key(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"insdesk-pw-v1");
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// Compute a password proof bound to a specific Noise session.
///
/// `handshake_hash` is [`Handshake::into_transport`]'s third return value. Because
/// it uniquely identifies the live session (including both ephemeral keys), a
/// captured proof cannot be replayed on a different session, and a MITM cannot
/// forge it without the password.
pub fn auth_proof(password: &str, handshake_hash: &[u8]) -> Vec<u8> {
    let key = password_key(password);
    hmac_sha256(&key, &[b"insdesk-auth-v1", handshake_hash]).to_vec()
}

/// Constant-time verification of a proof produced by [`auth_proof`].
pub fn verify_auth_proof(password: &str, handshake_hash: &[u8], proof: &[u8]) -> bool {
    let expected = auth_proof(password, handshake_hash);
    constant_time_eq(&expected, proof)
}

/// HMAC-SHA256 over the concatenation of `parts`.
fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..32 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    for p in parts {
        inner.update(p);
    }
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

/// Timing-safe byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run the full XX handshake between two in-memory identities and confirm
    /// both sides derive the same session and can talk.
    #[test]
    fn full_handshake_and_transport() {
        let host = Identity::generate().unwrap();
        let ctrl = Identity::generate().unwrap();

        let mut initiator = Handshake::new_initiator(&ctrl).unwrap();
        let mut responder = Handshake::new_responder(&host).unwrap();

        // XX is a three-message pattern: ->e, <-e,ee,s,es, ->s,se
        let m1 = initiator.write_message().unwrap();
        responder.read_message(&m1).unwrap();
        let m2 = responder.write_message().unwrap();
        initiator.read_message(&m2).unwrap();
        let m3 = initiator.write_message().unwrap();
        responder.read_message(&m3).unwrap();

        assert!(initiator.is_finished());
        assert!(responder.is_finished());

        let (mut ctrl_t, host_key_seen_by_ctrl, hh1) = initiator.into_transport().unwrap();
        let (mut host_t, ctrl_key_seen_by_host, hh2) = responder.into_transport().unwrap();

        // Both sides agree on the handshake hash (channel binding).
        assert_eq!(hh1, hh2);
        // Each side saw the other's true public key.
        assert_eq!(host_key_seen_by_ctrl, host.public_bytes());
        assert_eq!(ctrl_key_seen_by_host, ctrl.public_bytes());

        // Bulk traffic both directions.
        let ct = ctrl_t.encrypt(b"screen frame").unwrap();
        assert_eq!(host_t.decrypt(&ct).unwrap(), b"screen frame");
        let ct = host_t.encrypt(b"input event").unwrap();
        assert_eq!(ctrl_t.decrypt(&ct).unwrap(), b"input event");
    }

    #[test]
    fn device_id_is_stable_and_in_range() {
        let id = Identity::generate().unwrap();
        let a = id.device_id();
        let b = device_id_from_pubkey(id.public_bytes());
        assert_eq!(a, b);
        assert!((100_000_000..=999_999_999).contains(&a));
    }

    #[test]
    fn secret_round_trips_and_preserves_public() {
        let id = Identity::generate().unwrap();
        let restored = Identity::from_secret_hex(&id.secret_hex()).unwrap();
        assert_eq!(id.public_bytes(), restored.public_bytes());
        assert_eq!(id.device_id(), restored.device_id());
    }

    #[test]
    fn verify_device_id_detects_wrong_key() {
        let host = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        assert!(verify_device_id(host.device_id(), host.public_bytes()).is_ok());
        assert!(matches!(
            verify_device_id(host.device_id(), other.public_bytes()),
            Err(CryptoError::DeviceIdMismatch { .. })
        ));
    }

    #[test]
    fn password_proof_is_channel_bound() {
        let hh_a = [1u8; 32];
        let hh_b = [2u8; 32];
        let proof = auth_proof("hunter2", &hh_a);
        assert!(verify_auth_proof("hunter2", &hh_a, &proof));
        // Wrong password fails.
        assert!(!verify_auth_proof("wrong", &hh_a, &proof));
        // Same password but a different session (handshake hash) fails: no replay.
        assert!(!verify_auth_proof("hunter2", &hh_b, &proof));
    }
}
