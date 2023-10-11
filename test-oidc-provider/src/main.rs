use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    net::SocketAddr,
};

use axum::{routing::get, Router};
use tracing_subscriber::EnvFilter;

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
