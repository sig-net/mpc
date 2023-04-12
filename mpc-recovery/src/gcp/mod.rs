use std::fs::File;

use mpc_recovery_gcp::google::cloud::secretmanager::v1::{
    secret_manager_service_client::SecretManagerServiceClient, AccessSecretVersionRequest,
};
use tonic::{
    transport::{Certificate, Channel, ClientTlsConfig},
    Request,
};

use self::auth::TokenManager;

mod auth;

const DOMAIN_NAME: &str = "secretmanager.googleapis.com";
const ENDPOINT: &str = "https://secretmanager.googleapis.com";
const SCOPES: [&'static str; 1] = ["https://www.googleapis.com/auth/cloud-platform"];
const TLS_CERTS: &[u8] = include_bytes!("../../roots.pem");

pub async fn load_secret_share(node_id: u64) -> anyhow::Result<Vec<u8>> {
    // GOOGLE_APPLICATION_CREDENTIALS points to the credentials file on GCP:
    // https://cloud.google.com/docs/authentication/application-default-credentials
    let path = std::env::var("GOOGLE_APPLICATION_CREDENTIALS")?;
    let file = File::open(path)?;
    let creds = serde_json::from_reader(file)?;
    let mut token_manager = TokenManager::new(creds, &SCOPES);
    let token = token_manager.token().await?;

    let tls_config = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(TLS_CERTS))
        .domain_name(DOMAIN_NAME);

    let channel = Channel::from_static(ENDPOINT)
        .tls_config(tls_config)?
        .connect()
        .await?;
    let mut client =
        SecretManagerServiceClient::with_interceptor(channel, move |mut req: Request<()>| {
            req.metadata_mut()
                .insert("authorization", token.parse().unwrap());
            Ok(req)
        });
    let request = Request::new(AccessSecretVersionRequest {
        name: format!(
            "projects/pagoda-discovery-platform-dev/secrets/mpc-recovery-secret-share-{node_id}/versions/latest"
        )
        .into(),
    });

    let response = client.access_secret_version(request).await?;
    let secret_payload = response
        .into_inner()
        .payload
        .ok_or_else(|| anyhow::anyhow!("failed to fetch secret share from GCP Secret Manager"))?;
    Ok(secret_payload.data)
}
