use std::time::Duration;

use anyhow::Context as _;
use reqwest::Client;
use testcontainers::core::{IntoContainerPort as _, WaitFor};
use testcontainers::runners::AsyncRunner as _;
use testcontainers::{ContainerAsync, GenericImage, ImageExt as _};

const PORT: u16 = 4443;

pub struct GcsEmulator {
    pub endpoint: String,
    pub bucket: String,
    _container: ContainerAsync<GenericImage>,
    client: Client,
}

impl GcsEmulator {
    pub async fn run() -> anyhow::Result<Self> {
        let container = GenericImage::new("fsouza/fake-gcs-server", "1.56.1")
            .with_exposed_port(PORT.tcp())
            .with_wait_for(WaitFor::message_on_stderr("server started at"))
            .with_cmd(["-scheme", "http", "-backend", "memory", "-port", "4443"])
            .start()
            .await
            .context("starting the GCS emulator")?;
        let host = container.get_host().await?;
        let host_port = container.get_host_port_ipv4(PORT).await?;
        let endpoint = format!("http://{host}:{host_port}");
        let emulator = Self {
            endpoint,
            bucket: format!("mpc-test-{}", uuid::Uuid::new_v4()),
            _container: container,
            client: Client::builder().timeout(Duration::from_secs(5)).build()?,
        };
        emulator.create_bucket().await?;
        Ok(emulator)
    }

    async fn create_bucket(&self) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                match self
                    .client
                    .post(format!("{}/storage/v1/b", self.endpoint))
                    .query(&[("project", "local-test")])
                    .json(&serde_json::json!({ "name": self.bucket }))
                    .send()
                    .await
                {
                    Ok(response) => {
                        response
                            .error_for_status()
                            .context("creating the GCS test bucket")?;
                        return Ok::<_, anyhow::Error>(());
                    }
                    Err(error) if error.is_connect() => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        })
        .await
        .context("waiting for the GCS emulator to accept bucket creation")?
    }

    pub async fn read_object(&self, object: &str) -> anyhow::Result<Vec<u8>> {
        let mut url = url::Url::parse(&self.endpoint)?;
        url.path_segments_mut()
            .map_err(|()| anyhow::anyhow!("GCS emulator endpoint cannot hold a path"))?
            .extend(["storage", "v1", "b", &self.bucket, "o", object]);
        Ok(self
            .client
            .get(url)
            .query(&[("alt", "media")])
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?
            .to_vec())
    }
}
