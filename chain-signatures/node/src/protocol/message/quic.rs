use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use mpc_keys::hpke::Ciphered;
use tracing::{info, warn, error};
use url::Url;

use rustls::client::danger::{ServerCertVerifier, HandshakeSignatureValid};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;

#[derive(Debug)]
pub struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

pub struct QuicConnectionPool {
    endpoint: quinn::Endpoint,
    connections: Mutex<HashMap<String, quinn::Connection>>,
}

impl QuicConnectionPool {
    pub fn new() -> Result<Self, anyhow::Error> {
        let client_crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider().clone(),
        ))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
        ));

        let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            connections: Mutex::new(HashMap::new()),
        })
    }

    pub async fn send(&self, url_str: &str, payload: &[&Ciphered]) -> Result<(), anyhow::Error> {
        let conn = self.get_or_connect(url_str).await?;
        let mut send = conn.open_uni().await?;
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf)?;
        send.write_all(&buf).await?;
        send.finish()?;
        Ok(())
    }

    async fn get_or_connect(&self, url_str: &str) -> Result<quinn::Connection, anyhow::Error> {
        {
            let conns = self.connections.lock().unwrap();
            if let Some(conn) = conns.get(url_str) {
                if conn.close_reason().is_none() {
                    return Ok(conn.clone());
                }
            }
        }

        let url = Url::parse(url_str)?;
        let host = url.host_str().ok_or_else(|| anyhow::anyhow!("no host in url"))?;
        let port = url.port().ok_or_else(|| anyhow::anyhow!("no port in url"))?;
        
        let addr_str = format!("{}:{}", host, port);
        let addr = addr_str.to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("failed to resolve address: {}", addr_str))?;

        let connection = self.endpoint.connect(addr, "localhost")?.await?;

        {
            let mut conns = self.connections.lock().unwrap();
            conns.insert(url_str.to_string(), connection.clone());
        }

        Ok(connection)
    }
}

pub fn start_quic_server(
    port: u16,
    inbox_tx: mpsc::Sender<Ciphered>,
) -> Result<tokio::task::JoinHandle<()>, anyhow::Error> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();

    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key_der));

    let server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider().clone(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    server_config.transport_config(Arc::new(transport_config));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    info!(?addr, "QUIC server listening");

    let handle = tokio::spawn(async move {
        while let Some(conn) = endpoint.accept().await {
            let inbox_tx = inbox_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(conn, inbox_tx).await {
                    warn!("QUIC connection handler error: {:?}", e);
                }
            });
        }
    });

    Ok(handle)
}

async fn handle_connection(
    conn: quinn::Incoming,
    inbox_tx: mpsc::Sender<Ciphered>,
) -> Result<(), anyhow::Error> {
    let connection = conn.await?;
    loop {
        match connection.accept_uni().await {
            Ok(mut recv) => {
                let inbox_tx = inbox_tx.clone();
                tokio::spawn(async move {
                    let buf = match recv.read_to_end(10 * 1024 * 1024).await {
                        Ok(buf) => buf,
                        Err(e) => {
                            warn!("QUIC read stream error: {:?}", e);
                            return;
                        }
                    };
                    let ciphered_list: Result<Vec<Ciphered>, _> = ciborium::from_reader(buf.as_slice());
                    match ciphered_list {
                        Ok(list) => {
                            for ciphered in list {
                                if let Err(e) = inbox_tx.send(ciphered).await {
                                    error!("Failed to forward ciphered message to inbox: {:?}", e);
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to deserialize CBOR Vec<Ciphered> from QUIC stream: {:?}", e);
                        }
                    }
                });
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}
