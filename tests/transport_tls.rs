//! TLS behaviour against a local rustls test server with an rcgen certificate.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rs_loxone::auth::Secret;
use rs_loxone::transport::TransportError;
use rs_loxone::transport::http::{BootstrapConfig, HttpBootstrap};
use rs_loxone::transport::retry::RetryPolicy;
use rs_loxone::transport::tls::{TlsOptions, cloud_dns_host};
use rs_loxone::transport::url::Endpoint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

const CLOUD_HOST: &str = "10-0-0-5.100-00-00-01.dyndns.loxonecloud.com";

struct TestCert {
    pem: String,
    der: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn test_cert() -> TestCert {
    let ck =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), CLOUD_HOST.to_string()])
            .expect("rcgen");
    TestCert {
        pem: ck.cert.pem(),
        der: CertificateDer::from(ck.cert.der().to_vec()),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der())),
    }
}

/// A TLS server on 127.0.0.1 that answers every request with `{}`.
fn spawn_tls_server(cert: &TestCert) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der.clone()], cert.key.clone_key())
            .unwrap(),
    );
    thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { break };
            let conn = ServerConnection::new(config.clone()).unwrap();
            let mut tls = StreamOwned::new(conn, tcp);
            let mut buf = [0u8; 1024];
            let _ = tls.read(&mut buf); // request line and headers
            let _ = tls
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    addr
}

fn bootstrap(endpoint: &str, tls: TlsOptions, connect_addr: Option<SocketAddr>) -> HttpBootstrap {
    HttpBootstrap::new(BootstrapConfig {
        endpoint: Endpoint::parse(endpoint).unwrap(),
        username: "admin".into(),
        password: Secret::new("pw"),
        tls,
        retry: RetryPolicy {
            max_attempts: 1,
            base: Duration::from_millis(1),
            max: Duration::from_millis(1),
        },
        connect_addr,
    })
    .unwrap()
}

#[tokio::test]
async fn unknown_certificate_is_rejected_by_default() {
    let cert = test_cert();
    let addr = spawn_tls_server(&cert);
    let b = bootstrap(
        &format!("https://localhost:{}", addr.port()),
        TlsOptions::default(),
        Some(addr),
    );
    let err = b.structure_file().await.unwrap_err();
    assert!(matches!(err, TransportError::Tls(_)), "{err:?}");
}

#[tokio::test]
async fn extra_root_makes_the_certificate_trusted() {
    let cert = test_cert();
    let addr = spawn_tls_server(&cert);
    let opts = TlsOptions {
        verify: true,
        extra_root_pem: Some(cert.pem.clone().into_bytes()),
        pinned_cert_sha256: None,
        trust_on_first_use: false,
        first_use_file: None,
    };
    let b = bootstrap(
        &format!("https://localhost:{}", addr.port()),
        opts,
        Some(addr),
    );
    let file = b.structure_file().await.unwrap();
    assert_eq!(file.bytes, b"{}");
}

#[tokio::test]
async fn verification_off_accepts_any_certificate() {
    let cert = test_cert();
    let addr = spawn_tls_server(&cert);
    let opts = TlsOptions {
        verify: false,
        extra_root_pem: None,
        pinned_cert_sha256: None,
        trust_on_first_use: false,
        first_use_file: None,
    };
    let b = bootstrap(
        &format!("https://localhost:{}", addr.port()),
        opts,
        Some(addr),
    );
    assert_eq!(b.structure_file().await.unwrap().bytes, b"{}");
}

#[tokio::test]
async fn cloud_dns_name_with_local_ip_verifies_against_the_name() {
    // The name in the certificate is the CloudDNS name built from IPHTTPS. The TCP
    // connection goes to 127.0.0.1, and the name is used for SNI and verification.
    let cert = test_cert();
    let addr = spawn_tls_server(&cert);
    let name = cloud_dns_host(&format!("10.0.0.5:{}", addr.port()), "100-00-00-01").unwrap();
    assert!(name.starts_with(CLOUD_HOST.split(':').next().unwrap()));
    let opts = TlsOptions {
        verify: true,
        extra_root_pem: Some(cert.pem.clone().into_bytes()),
        pinned_cert_sha256: None,
        trust_on_first_use: false,
        first_use_file: None,
    };
    let b = bootstrap(&format!("https://{name}"), opts, Some(addr));
    assert_eq!(b.structure_file().await.unwrap().bytes, b"{}");
}

#[tokio::test]
async fn cloud_dns_name_without_trusted_root_is_rejected() {
    let cert = test_cert();
    let addr = spawn_tls_server(&cert);
    let name = cloud_dns_host(&format!("10.0.0.5:{}", addr.port()), "100-00-00-01").unwrap();
    let b = bootstrap(
        &format!("https://{name}"),
        TlsOptions::default(),
        Some(addr),
    );
    let err = b.structure_file().await.unwrap_err();
    assert!(matches!(err, TransportError::Tls(_)), "{err:?}");
}

#[tokio::test]
async fn pinned_fingerprint_accepts_only_that_certificate() {
    use sha2::{Digest, Sha256};
    let cert = test_cert();
    let addr = spawn_tls_server(&cert);
    let pin: [u8; 32] = Sha256::digest(cert.der.as_ref()).into();

    // The right fingerprint: no CA is needed, the name is not checked.
    let opts = TlsOptions {
        pinned_cert_sha256: Some(pin),
        ..TlsOptions::default()
    };
    let b = bootstrap(
        &format!("https://localhost:{}", addr.port()),
        opts,
        Some(addr),
    );
    assert_eq!(b.structure_file().await.unwrap().bytes, b"{}");

    // A different fingerprint: refused, even with verification off.
    let wrong = TlsOptions {
        pinned_cert_sha256: Some([0u8; 32]),
        verify: false,
        ..TlsOptions::default()
    };
    let b = bootstrap(
        &format!("https://localhost:{}", addr.port()),
        wrong,
        Some(addr),
    );
    let err = b.structure_file().await.unwrap_err();
    assert!(matches!(err, TransportError::Tls(_)), "{err:?}");
}

#[tokio::test]
async fn first_use_remembers_the_certificate_and_refuses_a_changed_one() {
    // Unique host names: the memory is per process and shared by all tests.
    let host = "tofu-first-use.test";
    let first = test_cert();
    let first_addr = spawn_tls_server(&first);
    let tofu = || TlsOptions {
        trust_on_first_use: true,
        ..TlsOptions::default()
    };

    let b = bootstrap(
        &format!("https://{host}:{}", first_addr.port()),
        tofu(),
        Some(first_addr),
    );
    assert_eq!(
        b.structure_file().await.unwrap().bytes,
        b"{}",
        "first contact"
    );
    let b = bootstrap(
        &format!("https://{host}:{}", first_addr.port()),
        tofu(),
        Some(first_addr),
    );
    assert_eq!(
        b.structure_file().await.unwrap().bytes,
        b"{}",
        "same certificate again"
    );

    // Another certificate under the same name: refused.
    let other = test_cert();
    let other_addr = spawn_tls_server(&other);
    let b = bootstrap(
        &format!("https://{host}:{}", other_addr.port()),
        tofu(),
        Some(other_addr),
    );
    let err = b.structure_file().await.unwrap_err();
    assert!(matches!(err, TransportError::Tls(_)), "{err:?}");
}

fn first_use_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rs-loxone-tofu-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("tls-first-use.json")
}

#[tokio::test]
async fn first_use_file_records_the_first_certificate() {
    use sha2::{Digest, Sha256};
    let host = "tofu-file-record.test";
    let path = first_use_path("record");
    let cert = test_cert();
    let addr = spawn_tls_server(&cert);
    let opts = TlsOptions {
        trust_on_first_use: true,
        first_use_file: Some(path.clone()),
        ..TlsOptions::default()
    };
    let b = bootstrap(&format!("https://{host}:{}", addr.port()), opts, Some(addr));
    assert_eq!(b.structure_file().await.unwrap().bytes, b"{}");

    let text = std::fs::read_to_string(&path).expect("file written");
    let digest = hex::encode(Sha256::digest(cert.der.as_ref()));
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json[host].as_str(), Some(digest.as_str()));
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn first_use_file_is_enforced_after_a_restart() {
    use sha2::{Digest, Sha256};
    let host = "tofu-file-restart.test";
    let path = first_use_path("restart");
    let known = test_cert();
    // The file says which certificate was seen first, as an earlier run would have written it.
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let digest = hex::encode(Sha256::digest(known.der.as_ref()));
    std::fs::write(&path, serde_json::json!({ host: digest }).to_string()).unwrap();

    let opts = || TlsOptions {
        trust_on_first_use: true,
        first_use_file: Some(path.clone()),
        ..TlsOptions::default()
    };
    // A different certificate under the remembered name: refused.
    let other = test_cert();
    let other_addr = spawn_tls_server(&other);
    let b = bootstrap(
        &format!("https://{host}:{}", other_addr.port()),
        opts(),
        Some(other_addr),
    );
    let err = b.structure_file().await.unwrap_err();
    assert!(matches!(err, TransportError::Tls(_)), "{err:?}");

    // The remembered certificate: accepted.
    let addr = spawn_tls_server(&known);
    let b = bootstrap(
        &format!("https://{host}:{}", addr.port()),
        opts(),
        Some(addr),
    );
    assert_eq!(b.structure_file().await.unwrap().bytes, b"{}");
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
