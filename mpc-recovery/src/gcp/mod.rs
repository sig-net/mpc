use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use mpc_recovery_gcp::google::cloud::secretmanager::v1::{
    secret_manager_service_client::SecretManagerServiceClient, AccessSecretVersionRequest,
};
use tonic::{
    transport::{Certificate, Channel, ClientTlsConfig},
    Request, Status,
};
use yup_oauth2::{
    authenticator::{ApplicationDefaultCredentialsTypes, Authenticator},
    ApplicationDefaultCredentialsAuthenticator, ApplicationDefaultCredentialsFlowOpts,
};

const DOMAIN_NAME: &str = "secretmanager.googleapis.com";
const ENDPOINT: &str = "https://secretmanager.googleapis.com";
const TLS_CERTS: &[u8] = include_bytes!("../../roots.pem");

pub struct GcpService {
    authenticator: Authenticator<HttpsConnector<HttpConnector>>,
}

impl GcpService {
    pub async fn new() -> anyhow::Result<Self> {
        let opts = ApplicationDefaultCredentialsFlowOpts::default();
        let authenticator = match ApplicationDefaultCredentialsAuthenticator::builder(opts).await {
            ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => auth.build().await?,
            ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => auth.build().await?,
        };

        Ok(Self { authenticator })
    }

    pub async fn load_secret(&self, name: String) -> anyhow::Result<Vec<u8>> {
        let access_token = self
            .authenticator
            .token(&["https://www.googleapis.com/auth/cloud-platform"])
            .await?;
        let token = access_token
            .token()
            .ok_or_else(|| anyhow::anyhow!("GCP token did not have access_token field in it"))?;

        let tls_config = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(TLS_CERTS))
            .domain_name(DOMAIN_NAME);

        let channel = Channel::from_static(ENDPOINT)
            .tls_config(tls_config)?
            .connect()
            .await?;
        let mut client =
            SecretManagerServiceClient::with_interceptor(channel, move |mut req: Request<()>| {
                req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", token)
                        .parse()
                        .map_err(|_| Status::unauthenticated("failed to parse access token"))?,
                );
                Ok(req)
            });

        let request = Request::new(AccessSecretVersionRequest { name });
        let response = client.access_secret_version(request).await?;
        let secret_payload = response.into_inner().payload.ok_or_else(|| {
            anyhow::anyhow!("failed to fetch secret share from GCP Secret Manager")
        })?;
        Ok(secret_payload.data)
    }
}
