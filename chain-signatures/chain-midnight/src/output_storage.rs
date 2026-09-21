use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use bytes::Bytes;
use google_cloud_storage::client::Storage;
use mpc_primitives::RequestId;
use mpc_utils::task::AbortOnDrop;

use crate::config::{MidnightAddress, OutputStorageConfig};

#[async_trait]
pub(crate) trait OutputStore: Send + Sync {
    async fn ensure_output(&self, request_id: RequestId, output: &[u8]) -> anyhow::Result<()>;
}

/// Keeps optional caching recoverable without making publishers wait for initialization.
pub(crate) struct RecoveringOutputStore {
    ready: Arc<OnceLock<GcsOutputStore>>,
    _initializer: AbortOnDrop,
}

impl RecoveringOutputStore {
    pub(crate) fn start(
        config: Option<&OutputStorageConfig>,
        network_id: &str,
        central_address: MidnightAddress,
    ) -> anyhow::Result<Option<Self>> {
        let Some(config) = config else {
            return Ok(None);
        };
        config.validate()?;
        let config = config.clone();
        let network_id = network_id.to_owned();
        Ok(Some(Self::spawn(
            config.bucket.clone(),
            config.timeout,
            move || {
                let config = config.clone();
                let network_id = network_id.clone();
                async move { GcsOutputStore::connect(&config, &network_id, central_address).await }
            },
        )))
    }

    pub(crate) fn spawn<F, Fut>(bucket: String, timeout: Duration, mut connect: F) -> Self
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = anyhow::Result<GcsOutputStore>> + Send,
    {
        let ready = Arc::new(OnceLock::new());
        let initialized = ready.clone();
        let initializer = tokio::spawn(async move {
            let mut delay = Duration::from_secs(1);
            loop {
                match tokio::time::timeout(timeout, connect())
                    .await
                    .context("Midnight output storage initialization timed out")
                    .and_then(|result| result)
                {
                    Ok(store) => {
                        // Only this task initializes the slot; uploads only read it.
                        let _ = initialized.set(store);
                        tracing::info!(%bucket, "Midnight output storage initialized");
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(
                            %bucket,
                            ?error,
                            retry_in = ?delay,
                            "Midnight output storage initialization failed; retrying in background"
                        );
                    }
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(60));
            }
        });
        Self {
            ready,
            _initializer: AbortOnDrop(initializer),
        }
    }
}

#[async_trait]
impl OutputStore for RecoveringOutputStore {
    async fn ensure_output(&self, request_id: RequestId, output: &[u8]) -> anyhow::Result<()> {
        self.ready
            .get()
            .context("Midnight output storage is initializing; retrying in background")?
            .ensure_output(request_id, output)
            .await
    }
}

pub(crate) struct GcsOutputStore {
    client: Storage,
    bucket: String,
    prefix: String,
    timeout: Duration,
}

impl GcsOutputStore {
    async fn connect(
        config: &OutputStorageConfig,
        network_id: &str,
        central_address: MidnightAddress,
    ) -> anyhow::Result<Self> {
        #[cfg(feature = "sandbox")]
        if let Some(endpoint) = &config.emulator_endpoint {
            return Self::connect_emulator(config, network_id, central_address, endpoint).await;
        }
        let client = Storage::builder().build().await?;
        Self::new(config, network_id, central_address, client)
    }

    #[cfg(feature = "sandbox")]
    async fn connect_emulator(
        config: &OutputStorageConfig,
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
        config: &OutputStorageConfig,
        network_id: &str,
        central_address: MidnightAddress,
        client: Storage,
    ) -> anyhow::Result<Self> {
        config.validate()?;
        Ok(Self {
            client,
            bucket: format!("projects/_/buckets/{}", config.bucket),
            prefix: format!(
                "{}/{}/{}",
                config.prefix.trim_matches('/'),
                network_id,
                central_address.to_hex(),
            ),
            timeout: config.timeout,
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
                // Only identical bytes count as a successful cache publication.
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
    async fn ensure_output(&self, request_id: RequestId, output: &[u8]) -> anyhow::Result<()> {
        let object = format!("{}/{}.bin", self.prefix, hex::encode(request_id.bytes));
        tokio::time::timeout(self.timeout, self.upload(&object, output))
            .await
            .context("Midnight output upload timed out")
            .and_then(|result| result)
            .with_context(|| format!("Midnight output storage unavailable for {object}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use google_cloud_auth::credentials::anonymous;
    use mockito::{Matcher, Server};

    const SIGN_ID: RequestId = RequestId::from_u8(0x5c);

    async fn store(server: &Server) -> GcsOutputStore {
        let client = Storage::builder()
            .with_endpoint(server.url())
            .with_credentials(anonymous::Builder::new().build())
            .build()
            .await
            .unwrap();
        GcsOutputStore::new(
            &OutputStorageConfig::new(
                "outputs".into(),
                "v1/test-deployment".into(),
                Duration::from_secs(2),
            ),
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
        store.ensure_output(SIGN_ID, &output).await.unwrap();
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
            let result = store.ensure_output(SIGN_ID, &output).await;
            assert_eq!(result.is_ok(), accepted, "{result:#?}");
            read.assert_async().await;
            read.remove_async().await;
        }
        write.assert_async().await;
    }

    #[tokio::test]
    async fn storage_errors_preserve_the_object_and_provider_details() {
        let mut server = Server::new_async().await;
        let store = store(&server).await;
        let write = upload(&mut server).with_status(403).create_async().await;
        let error = store.ensure_output(SIGN_ID, &[1]).await.unwrap_err();
        assert!(format!("{error:#}").contains("403"));
        assert!(format!("{error:#}").contains(&object_name()));
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
            &OutputStorageConfig::new("outputs".into(), "v1".into(), Duration::from_millis(100)),
            "preprod",
            MidnightAddress::from_bytes([0xab; 32]),
            client,
        )
        .unwrap();
        let error = store.ensure_output(SIGN_ID, &[1]).await.unwrap_err();
        assert!(format!("{error:#}").contains("timed out"));
    }

    #[test]
    fn no_bucket_disables_storage_before_client_initialization() {
        let store =
            RecoveringOutputStore::start(None, "preprod", MidnightAddress::from_bytes([0xab; 32]))
                .unwrap();
        assert!(store.is_none());
    }

    #[test]
    fn invalid_configuration_is_rejected_before_spawning_initialization() {
        for config in [
            OutputStorageConfig::new("".into(), "v1".into(), Duration::from_secs(2)),
            OutputStorageConfig::new("outputs".into(), "".into(), Duration::from_secs(2)),
            OutputStorageConfig::new("outputs".into(), "v1".into(), Duration::ZERO),
        ] {
            assert!(RecoveringOutputStore::start(
                Some(&config),
                "preprod",
                MidnightAddress::from_bytes([0xab; 32]),
            )
            .is_err());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn initialization_failures_back_off_and_keep_retrying_at_the_cap() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = Arc::new(AtomicUsize::new(0));
        let calls = attempts.clone();
        let _store =
            RecoveringOutputStore::spawn("outputs".into(), Duration::from_secs(2), move || {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Err(anyhow::anyhow!("403: credentials unavailable")))
            });
        tokio::task::yield_now().await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        for (index, seconds) in [1, 2, 4, 8, 16, 32, 60, 60].into_iter().enumerate() {
            tokio::time::advance(Duration::from_secs(seconds) - Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
            assert_eq!(attempts.load(Ordering::SeqCst), index + 1);
            tokio::time::advance(Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
            assert_eq!(attempts.load(Ordering::SeqCst), index + 2);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn initialization_timeout_retries_after_the_deadline_and_backoff() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = Arc::new(AtomicUsize::new(0));
        let calls = attempts.clone();
        let store =
            RecoveringOutputStore::spawn("outputs".into(), Duration::from_secs(2), move || {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::pending()
            });
        tokio::task::yield_now().await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        for (seconds, expected) in [(2, 1), (1, 2), (2, 2), (2, 3)] {
            tokio::time::advance(Duration::from_secs(seconds)).await;
            tokio::task::yield_now().await;
            assert_eq!(attempts.load(Ordering::SeqCst), expected);
            let started = tokio::time::Instant::now();
            store.ensure_output(SIGN_ID, &[1]).await.unwrap_err();
            assert_eq!(started.elapsed(), Duration::ZERO);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_storage_cancels_pending_initialization_and_sleeping_retries() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Attempt(Arc<AtomicUsize>);
        impl Drop for Attempt {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        for pending in [true, false] {
            let attempts = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let calls = attempts.clone();
            let drops = dropped.clone();
            let store =
                RecoveringOutputStore::spawn("outputs".into(), Duration::from_secs(2), move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let attempt = Attempt(drops.clone());
                    async move {
                        let _attempt = attempt;
                        if pending {
                            std::future::pending::<()>().await;
                        }
                        anyhow::bail!("initialization failed")
                    }
                });
            tokio::task::yield_now().await;
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
            drop(store);
            tokio::task::yield_now().await;
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            tokio::time::advance(Duration::from_secs(120)).await;
            tokio::task::yield_now().await;
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
        }
    }

    #[cfg(feature = "sandbox")]
    #[tokio::test]
    async fn client_initialization_failure_keeps_storage_available_for_retries() {
        let mut config =
            OutputStorageConfig::new("outputs".into(), "v1".into(), Duration::from_secs(2));
        config.emulator_endpoint = Some("http://[invalid".into());
        let address = MidnightAddress::from_bytes([0xab; 32]);
        assert!(GcsOutputStore::connect(&config, "preprod", address)
            .await
            .is_err());
        let store = RecoveringOutputStore::start(Some(&config), "preprod", address)
            .unwrap()
            .unwrap();
        tokio::task::yield_now().await;
        assert!(store
            .ensure_output(SIGN_ID, &[1])
            .await
            .unwrap_err()
            .to_string()
            .contains("initializing"));
    }

    #[test]
    fn output_storage_configuration_rejects_empty_buckets_and_invalid_tuning() {
        let mut config = OutputStorageConfig::new(" ".into(), "v1".into(), Duration::from_secs(30));
        assert!(config.validate().is_err());
        config.bucket = "outputs".into();
        config.validate().unwrap();
        config.timeout = Duration::ZERO;
        assert!(config.validate().is_err());
        config.timeout = Duration::from_secs(1);
        config.prefix = String::new();
        assert!(config.validate().is_err());
    }
}
