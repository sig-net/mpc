use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use bytes::Bytes;
use google_cloud_storage::client::Storage;

use crate::config::{MidnightAddress, PublisherConfig};

#[async_trait]
pub(crate) trait OutputStore: Send + Sync {
    async fn ensure_output(&self, request_id: &[u8; 32], output: &[u8]) -> anyhow::Result<()>;
}

pub(crate) struct GcsOutputStore {
    client: Storage,
    bucket: String,
    prefix: String,
    timeout: Duration,
}

impl GcsOutputStore {
    pub(crate) async fn connect(
        config: &PublisherConfig,
        network_id: &str,
        central_address: MidnightAddress,
    ) -> anyhow::Result<Option<Self>> {
        config.validate_output_storage()?;
        if config.output_storage_bucket.is_none() {
            return Ok(None);
        }
        #[cfg(feature = "sandbox")]
        if let Some(endpoint) = &config.output_storage_emulator_endpoint {
            return Self::connect_emulator(config, network_id, central_address, endpoint)
                .await
                .map(Some);
        }
        let client = Storage::builder().build().await?;
        Self::new(config, network_id, central_address, client).map(Some)
    }

    #[cfg(feature = "sandbox")]
    async fn connect_emulator(
        config: &PublisherConfig,
        network_id: &str,
        central_address: MidnightAddress,
        endpoint: &str,
    ) -> anyhow::Result<Self> {
        let client = Storage::builder()
            .with_endpoint(endpoint)
            .with_credentials(google_cloud_auth::credentials::anonymous::Builder::new().build())
            .build()
            .await?;
        Self::new(config, network_id, central_address, client)
    }

    pub(crate) fn new(
        config: &PublisherConfig,
        network_id: &str,
        central_address: MidnightAddress,
        client: Storage,
    ) -> anyhow::Result<Self> {
        config.validate_output_storage()?;
        Ok(Self {
            client,
            bucket: format!(
                "projects/_/buckets/{}",
                config
                    .output_storage_bucket
                    .as_deref()
                    .context("GCS output storage requires a bucket")?
            ),
            prefix: format!(
                "{}/{}/{}",
                config.output_storage_prefix.trim_matches('/'),
                network_id,
                central_address.to_hex(),
            ),
            timeout: config.output_storage_timeout,
        })
    }

    async fn upload(&self, object: &str, output: &[u8]) -> anyhow::Result<()> {
        let result = self
            .client
            .write_object(&self.bucket, object, Bytes::copy_from_slice(output))
            .set_content_type("application/octet-stream")
            .set_if_generation_match(0)
            .send_unbuffered()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error) if error.http_status_code() == Some(412) => {
                // A lost upload reply or another publisher can create this object first.
                // Only identical bytes satisfy the precondition for publishing on-chain.
                let mut response = self.client.read_object(&self.bucket, object).send().await?;
                let mut offset = 0;
                while let Some(chunk) = response.next().await.transpose()? {
                    let end = offset + chunk.len();
                    anyhow::ensure!(
                        output.get(offset..end) == Some(chunk.as_ref()),
                        "stored Midnight output differs from the attested bytes"
                    );
                    offset = end;
                }
                anyhow::ensure!(
                    offset == output.len(),
                    "stored Midnight output is truncated"
                );
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

#[async_trait]
impl OutputStore for GcsOutputStore {
    async fn ensure_output(&self, request_id: &[u8; 32], output: &[u8]) -> anyhow::Result<()> {
        let object = format!("{}/{}.bin", self.prefix, hex::encode(request_id));
        let result = tokio::time::timeout(self.timeout, self.upload(&object, output))
            .await
            .context("Midnight output upload timed out")
            .and_then(|result| result);
        if let Err(error) = &result {
            tracing::error!(%object, ?error, "Midnight output is unavailable; withholding on-chain response");
        }
        // The shared RPC retry policy inspects the outer error's text for HTTP codes.
        // Keep all storage failures pending, retaining provider details in the cause.
        result.context("Midnight output storage unavailable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use google_cloud_auth::credentials::anonymous;
    use mockito::{Matcher, Server};

    const REQUEST_ID: [u8; 32] = [0x5c; 32];

    async fn store(server: &Server) -> GcsOutputStore {
        let client = Storage::builder()
            .with_endpoint(server.url())
            .with_credentials(anonymous::Builder::new().build())
            .build()
            .await
            .unwrap();
        GcsOutputStore::new(
            &PublisherConfig {
                output_storage_bucket: Some("outputs".into()),
                output_storage_prefix: "v1/test-deployment".into(),
                output_storage_timeout: Duration::from_secs(2),
                ..Default::default()
            },
            "preprod",
            MidnightAddress::from_bytes([0xab; 32]),
            client,
        )
        .unwrap()
    }

    fn object_name() -> String {
        format!(
            "v1/test-deployment/preprod/{}/{}.bin",
            "ab".repeat(32),
            "5c".repeat(32)
        )
    }

    fn upload(server: &mut Server) -> mockito::Mock {
        server
            .mock("POST", "/upload/storage/v1/b/outputs/o")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("name".into(), object_name()),
                Matcher::UrlEncoded("ifGenerationMatch".into(), "0".into()),
                Matcher::UrlEncoded("uploadType".into(), "multipart".into()),
            ]))
    }

    fn download(server: &mut Server) -> mockito::Mock {
        let encoded: String =
            url::form_urlencoded::byte_serialize(object_name().as_bytes()).collect();
        server
            .mock("GET", format!("/storage/v1/b/outputs/o/{encoded}").as_str())
            .match_query(Matcher::UrlEncoded("alt".into(), "media".into()))
            .with_header("x-goog-generation", "1")
    }

    #[tokio::test]
    async fn uploads_exact_binary_output_at_the_request_location() {
        let mut server = Server::new_async().await;
        let store = store(&server).await;
        let output = [0, 0xff, 0xde, 0xad, 0xbe, 0xef, 1, 0];
        let write = upload(&mut server)
            .match_request(move |request| {
                let headers = request.header("content-type");
                let boundary = headers[0]
                    .to_str()
                    .unwrap()
                    .split("boundary=")
                    .nth(1)
                    .unwrap();
                let suffix = [
                    b"\r\n\r\n".as_slice(),
                    &output,
                    format!("\r\n--{boundary}--\r\n").as_bytes(),
                ]
                .concat();
                request.body().unwrap().ends_with(&suffix)
            })
            .with_status(200)
            .with_body(r#"{"bucket":"outputs","generation":"1"}"#)
            .create_async()
            .await;
        store.ensure_output(&REQUEST_ID, &output).await.unwrap();
        write.assert_async().await;
    }

    #[tokio::test]
    async fn an_existing_object_must_match_every_byte() {
        let mut server = Server::new_async().await;
        let store = store(&server).await;
        let write = upload(&mut server)
            .with_status(412)
            .expect(5)
            .create_async()
            .await;
        for (existing, output, accepted) in [
            (vec![0, 255, 0], vec![0, 255, 0], true),
            (vec![], vec![], true),
            (vec![0, 255, 0], vec![0, 254, 0], false),
            (vec![0, 255], vec![0, 255, 0], false),
            (vec![0, 255, 0, 0], vec![0, 255, 0], false),
        ] {
            let read = download(&mut server)
                .with_status(200)
                .with_body(existing)
                .create_async()
                .await;
            let result = store.ensure_output(&REQUEST_ID, &output).await;
            assert_eq!(result.is_ok(), accepted, "{result:#?}");
            read.assert_async().await;
            read.remove_async().await;
        }
        write.assert_async().await;
    }

    #[tokio::test]
    async fn storage_errors_keep_the_response_retryable() {
        let mut server = Server::new_async().await;
        let store = store(&server).await;
        let write = upload(&mut server).with_status(403).create_async().await;
        let error = store.ensure_output(&REQUEST_ID, &[1]).await.unwrap_err();
        assert!(mpc_chain_integration_core::utils::retry::is_retryable(
            &error
        ));
        assert!(format!("{error:#}").contains("403"));
        write.assert_async().await;
    }

    #[tokio::test]
    async fn an_unresponsive_store_is_bounded_by_the_upload_budget() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = Storage::builder()
            .with_endpoint(format!("http://{}", listener.local_addr().unwrap()))
            .with_credentials(anonymous::Builder::new().build())
            .build()
            .await
            .unwrap();
        let store = GcsOutputStore::new(
            &PublisherConfig {
                output_storage_bucket: Some("outputs".into()),
                output_storage_timeout: Duration::from_millis(100),
                ..Default::default()
            },
            "preprod",
            MidnightAddress::from_bytes([0xab; 32]),
            client,
        )
        .unwrap();
        let error = store.ensure_output(&REQUEST_ID, &[1]).await.unwrap_err();
        assert!(format!("{error:#}").contains("timed out"));
        assert!(mpc_chain_integration_core::utils::retry::is_retryable(
            &error
        ));
    }

    #[tokio::test]
    async fn no_bucket_disables_storage_before_client_initialization() {
        let store = GcsOutputStore::connect(
            &PublisherConfig::default(),
            "preprod",
            MidnightAddress::from_bytes([0xab; 32]),
        )
        .await
        .unwrap();
        assert!(store.is_none());
    }

    #[test]
    fn output_storage_configuration_rejects_empty_buckets_and_invalid_tuning() {
        let mut config = PublisherConfig::default();
        config.validate_output_storage().unwrap();
        config.output_storage_bucket = Some(" ".into());
        assert!(config.validate_output_storage().is_err());
        config.output_storage_bucket = Some("outputs".into());
        config.validate_output_storage().unwrap();
        config.output_storage_timeout = Duration::ZERO;
        assert!(config.validate_output_storage().is_err());
        config.output_storage_timeout = Duration::from_secs(1);
        config.output_storage_prefix = String::new();
        assert!(config.validate_output_storage().is_err());
    }
}
