//! End-to-end transport test: two identities complete the Noise handshake over
//! a real TCP pair and exchange messages, including one large enough to span
//! multiple encrypted chunks (exercising record reassembly).

use insdesk_crypto::Identity;
use insdesk_net::{perform_handshake, spawn_session, HandshakeRole};
use insdesk_proto::{ClipboardData, Features, Hello, Message, Role, PROTOCOL_VERSION};
use tokio::net::{TcpListener, TcpStream};

fn hello(role: Role, name: &str) -> Message {
    Message::Hello(Hello {
        protocol_version: PROTOCOL_VERSION,
        role,
        display_name: name.into(),
        features: Features::current(),
    })
}

#[tokio::test]
async fn handshake_exchange_and_large_reassembly() {
    let host_id = Identity::generate().unwrap();
    let ctrl_id = Identity::generate().unwrap();
    let host_pub = host_id.public_bytes().to_vec();
    let ctrl_pub = ctrl_id.public_bytes().to_vec();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // --- Host side ---
    let host = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let est = perform_handshake(&mut sock, HandshakeRole::Responder, &host_id).await.unwrap();
        let remote_public = est.meta.remote_public.clone();
        let (t, _meta) = est.into_parts();
        let sess = spawn_session(sock, t, 16);
        let (tx, mut rx) = (sess.sender, sess.receiver);

        tx.send(hello(Role::Host, "host")).await.unwrap();
        // Reflect every message the controller sends until it says Bye.
        while let Some(Ok(msg)) = rx.recv().await {
            if matches!(msg, Message::Bye { .. }) {
                break;
            }
            tx.send(msg).await.unwrap();
        }
        remote_public
    });

    // --- Controller side ---
    let mut sock = TcpStream::connect(addr).await.unwrap();
    let est = perform_handshake(&mut sock, HandshakeRole::Initiator, &ctrl_id).await.unwrap();
    // The controller must see the host's true public key (no MITM).
    assert_eq!(est.meta.remote_public, host_pub);
    let (t, _meta) = est.into_parts();
    let sess = spawn_session(sock, t, 16);
    let (tx, mut rx) = (sess.sender, sess.receiver);

    // Host greets first.
    match rx.recv().await.unwrap().unwrap() {
        Message::Hello(h) => assert_eq!(h.role, Role::Host),
        other => panic!("expected host hello, got {other:?}"),
    }

    // Small message round-trips.
    let ping = Message::Ping { nonce: 42, sent_unix_millis: 7 };
    tx.send(ping.clone()).await.unwrap();
    assert_eq!(rx.recv().await.unwrap().unwrap(), ping);

    // Large message (~500 KiB of text) must survive chunking + reassembly.
    let big = "A".repeat(500_000);
    let clip = Message::Clipboard(ClipboardData::Text(big.clone()));
    tx.send(clip.clone()).await.unwrap();
    match rx.recv().await.unwrap().unwrap() {
        Message::Clipboard(ClipboardData::Text(t)) => assert_eq!(t.len(), big.len()),
        other => panic!("expected reflected clipboard, got {other:?}"),
    }

    tx.send(Message::Bye { reason: None }).await.unwrap();

    let remote_seen_by_host = host.await.unwrap();
    // The host likewise authenticated the controller's real key.
    assert_eq!(remote_seen_by_host, ctrl_pub);
}
