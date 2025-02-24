use std::fmt;

use tracing::{Event, Subscriber};
use tracing_stackdriver::layer as stackdriver_layer;
use tracing_subscriber::fmt::format::{Format, FormatEvent, Full};
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::fmt::{FmtContext, FormatFields, format};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, Registry};

/// This will whether this code is being ran on top of GCP or not.
fn is_running_on_gcp() -> bool {
    // Check if running in Google Cloud Run: https://cloud.google.com/run/docs/container-contract#services-env-vars
    if std::env::var("K_SERVICE").is_ok() {
        return true;
    }

    let resp = reqwest::blocking::Client::new()
        .get("http://metadata.google.internal/computeMetadata/v1/instance/id")
        .header("Metadata-Flavor", "Google")
        .timeout(std::time::Duration::from_millis(200))
        .send();

    match resp {
        Ok(resp) => resp.status().is_success(),
        _ => false,
    }
}

/// Formatter that adds the `NodeId({node_id})` to the log line. Useful for tests when
/// multiple nodes are logging to the same std/err output.
struct NodeIdFormatter {
    fmt: Format<Full, SystemTime>,
    repr: String,
}

impl NodeIdFormatter {
    pub fn new(id: usize) -> Self {
        Self {
            fmt: Format::default(),
            repr: format!("NodeId({id})"),
        }
    }
}

// Reference: https://docs.rs/tracing-subscriber/0.3.17/tracing_subscriber/fmt/trait.FormatEvent.html
impl<S, N> FormatEvent<S, N> for NodeIdFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: format::Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        write!(&mut writer, "{} ", self.repr)?;
        self.fmt.format_event(ctx, writer, event)
    }
}

pub fn install_global(node_id: Option<usize>) {
    // Install global collector configured based on RUST_LOG env var.
    let base_subscriber = Registry::default().with(EnvFilter::from_default_env());

    if let Some(node_id) = node_id {
        let fmt_layer =
            tracing_subscriber::fmt::layer().event_format(NodeIdFormatter::new(node_id));
        let subscriber = base_subscriber.with(fmt_layer);
        tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");
    } else if is_running_on_gcp() {
        let stackdriver = stackdriver_layer().with_writer(std::io::stderr);
        let subscriber = base_subscriber.with(stackdriver);
        tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");
    } else {
        let fmt_layer = tracing_subscriber::fmt::layer().with_thread_ids(true);
        let subscriber = base_subscriber.with(fmt_layer);
        tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");
    }
}
