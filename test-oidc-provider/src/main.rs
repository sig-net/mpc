use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    net::SocketAddr,
};

use axum::{routing::get, Router};
use tracing_subscriber::EnvFilter;

const _SECRET_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";

const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAg6UuFBM3QmtQID8cOHlt
jM8WF/XpFj2d5feVShG19jan76n6kEQPIhbqC4gweqWWdKdwbOmJKvDzV7qER5BC
2tKB7ViKRFpsEc5pSp2vc4w81Wni9Dzicpz1R0Qr2p3lkqLuG6G/nJaD6s0KMfiy
PiIBSBOgd1gaGIZcN2MtZm4bT2cVBxgBBW9L3bkpyONf0JHtia+6M7LPwzKwd29L
YuirPFU31psCBejXwuWst/KBncEeHASEW/LK0UJS4tJVH05mNuicBjKkYJ8Q+UTV
ZPA+8bgkrWEzScAoedVn+QwbwUxZ+C0r1NunllwU+e29s9rpf9wifzX43vA4FGPY
dDuEPiGmaNqFTsV/Z8oOMLDuAt/QqFVrp24S6DyHy/aWAZcJzcAbwckP0B5Gsrvb
AogcWzPpRzFLFkPmsQ1IMG/MK382AJ04rh+u0jomXxImLYiDFvzEXTelNsiDICHY
6PQ1Fd/OfxuKVFl4cVVx5VeyWOIAjRePaeMaijHr0KrxKDZiz+Umx8UJTwbjAfPx
9fM5mvBXlmsXYAm/hmnp74xDlr/s8c4fAyXmuqRocu8jq0GkMDjYJKj2QQSZSLQU
MxmeF6gRIFpjK8mawsSvM88Kiu6o/pZD3i0e3QL5OBwYjcd0muxY23yvcmdVmLeT
ds+wB0xAtA8wkWEu8N8SGXcCAwEAAQ==
-----END PUBLIC KEY-----";

#[tokio::main]
async fn main() {
    // Tracing setup
    tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("Starting Test OIDC Provider server...");
    let app = Router::new().route(
        "/jwt_signature_public_keys",
        get(jwt_signature_public_keys_handler),
    );

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    tracing::info!(?addr, "Binding OIDC Provider server...");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .expect("Failed to bind server");
}

async fn jwt_signature_public_keys_handler() -> impl axum::response::IntoResponse {
    tracing::info!("jwt_signature_public_keys called");
    axum::Json(jwt_signature_public_keys().await)
}

async fn jwt_signature_public_keys() -> HashMap<String, String> {
    let public_keys = HashMap::from([(hash_string(PUBLIC_KEY), String::from(PUBLIC_KEY))]);
    tracing::info!("Returning jwt_signature_public_keys: {:?}", public_keys);
    public_keys
}

fn hash_string(input_string: &str) -> String {
    let mut hasher = DefaultHasher::new();
    input_string.hash(&mut hasher);
    hasher.finish().to_string()
}
