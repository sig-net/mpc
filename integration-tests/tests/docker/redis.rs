use bollard::{
    container::{Config, RemoveContainerOptions},
    image::CreateImageOptions,
    service::HostConfig,
    Docker,
};
use futures::TryStreamExt;

pub struct Redis {
    docker: Docker,
    container_id: String,
    pub hostname: String,
}

impl Redis {
    pub async fn start(docker: &Docker, network: &str) -> anyhow::Result<Redis> {
        docker
            .create_image(
                Some(CreateImageOptions {
                    from_image: "redis:latest",
                    ..Default::default()
                }),
                None,
                None,
            )
            .try_collect::<Vec<_>>()
            .await?;

        let relayer_config = Config {
            image: Some("redis:latest".to_string()),
            tty: Some(true),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            cmd: None,
            host_config: Some(HostConfig {
                network_mode: Some(network.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let container_id = docker
            .create_container::<&str, String>(None, relayer_config)
            .await?
            .id;

        super::continuously_print_docker_output(docker, &container_id).await?;
        docker
            .start_container::<String>(&container_id, None)
            .await?;

        let network_settings = docker
            .inspect_container(&container_id, None)
            .await?
            .network_settings
            .unwrap();
        let ip_address = network_settings
            .networks
            .unwrap()
            .get(network)
            .cloned()
            .unwrap()
            .ip_address
            .unwrap();

        Ok(Redis {
            docker: docker.clone(),
            container_id,
            hostname: ip_address,
        })
    }
}

// Removing container is an asynchronous operation and hence has to be scheduled to execute
// outside of `drop`'s scope. This leads to problems when the drop happens right before the
// execution ends. The invoker needs to be aware of this behavior and give `drop` some time
// to finalize.
impl Drop for Redis {
    fn drop(&mut self) {
        let container_id = self.container_id.clone();
        let docker = self.docker.clone();
        tokio::spawn(async move {
            docker
                .remove_container(
                    &container_id,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await
        });
    }
}
