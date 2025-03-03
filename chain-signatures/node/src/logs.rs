use std::fmt::{self, Display};

use opentelemetry::KeyValue;
use opentelemetry_appender_tracing::layer;
use opentelemetry_otlp::{LogExporter, Protocol, WithExportConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::Resource;
use tracing::{Event, Subscriber};
use tracing_stackdriver::layer as stackdriver_layer;
use tracing_subscriber::fmt::format::{Format, FormatEvent, Full};
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::fmt::{format, FmtContext, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, Layer, Registry};

#[derive(Debug, Clone, clap::Parser)]
pub struct Options {
    #[clap(
        long,
        env("MPC_OPENTELEMETRY_LEVEL"),
        value_enum,
        default_value = "off"
    )]
    pub opentelemetry_level: OpenTelemetryLevel,

    #[clap(long, env("MPC_OTLP_ENDPOINT"), default_value = "http://jaeger:4318")]
    pub otlp_endpoint: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            opentelemetry_level: OpenTelemetryLevel::DEBUG,
            otlp_endpoint: "http://jaeger:4318".to_string(),
        }
    }
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        let opts = vec![
            "--opentelemetry-level".to_string(),
            self.opentelemetry_level.to_string(),
            "--otlp-endpoint".to_string(),
            self.otlp_endpoint,
        ];
        opts
    }
}

#[derive(Copy, Clone, Debug, Default, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
pub enum OpenTelemetryLevel {
    #[default]
    OFF,
    INFO,
    DEBUG,
    TRACE,
}

impl Display for OpenTelemetryLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            OpenTelemetryLevel::OFF => "off",
            OpenTelemetryLevel::INFO => "info",
            OpenTelemetryLevel::DEBUG => "debug",
            OpenTelemetryLevel::TRACE => "trace",
        };
        write!(f, "{}", str)
    }
}

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
    pub fn new(node_id: &str) -> Self {
        Self {
            fmt: Format::default(),
            repr: format!("NodeId({})", node_id),
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

pub fn setup(env: &str, node_id: &str, options: &Options) -> anyhow::Result<()> {
    let otel_exporter = LogExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(options.otlp_endpoint.clone())
        .build()?;

    let otel_recource = Resource::builder()
        .with_service_name(format!("mpc:{}:{}", env, node_id))
        .with_attributes(vec![
            KeyValue::new("env", env.to_string()),
            KeyValue::new("node_id", node_id.to_string()),
        ])
        .build();

    let otel_provider = SdkLoggerProvider::builder()
        .with_batch_exporter(otel_exporter)
        .with_resource(otel_recource)
        .build();

    // Trasing Subscriber
    let otel_filter = EnvFilter::new(options.opentelemetry_level.to_string())
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("opentelemetry=off".parse().unwrap())
        .add_directive("tonic=off".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("reqwest=off".parse().unwrap());

    let otel_layer =
        layer::OpenTelemetryTracingBridge::new(&otel_provider).with_filter(otel_filter);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(atty::is(atty::Stream::Stderr))
        .with_line_number(true)
        .with_thread_names(true)
        .event_format(NodeIdFormatter::new(node_id));

    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt_layer)
        .with(otel_layer);

    if is_running_on_gcp() {
        tracing::info!("Setting global logging subscriber: fmt, otel, stackdriver");
        let stackdriver_layer = stackdriver_layer().with_writer(std::io::stderr);
        let subscriber = subscriber.with(stackdriver_layer);

        // switching to tracing
        tracing::subscriber::set_global_default(subscriber)
            .map_err(|err| anyhow::anyhow!("Failed to set subscriber: {:?}", err))?;
    } else {
        tracing::info!("Setting global logging subscriber: fmt, otel");
        // switching to tracing
        tracing::subscriber::set_global_default(subscriber)
            .map_err(|err| anyhow::anyhow!("Failed to set subscriber: {:?}", err))?;
    }
    tracing::info!(
        "Logging parameters: env={}, node_id={}, options={:?}",
        env,
        node_id,
        options
    );
    Ok(())
}
