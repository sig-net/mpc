use std::fmt::{self, Display};
use std::sync::OnceLock;

use opentelemetry::{global, KeyValue};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing::{Event, Subscriber};
use tracing_stackdriver::layer as stackdriver_layer;
use tracing_subscriber::fmt::format::{Format, FormatEvent, Full};
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::fmt::{format, FmtContext, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

#[derive(Debug, Clone, clap::Parser)]
pub struct Options {
    #[clap(
        long,
        env("MPC_OPENTELEMETRY_LEVEL"),
        value_enum,
        default_value = "off"
    )]
    pub opentelemetry_level: OpenTelemetryLevel,

    #[clap(
        long,
        env("MPC_OTLP_ENDPOINT"),
        default_value = "http://localhost:4318"
    )]
    pub otlp_endpoint: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            opentelemetry_level: OpenTelemetryLevel::DEBUG,
            otlp_endpoint: "http://localhost:4318".to_string(),
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

pub struct OtelGuard {
    tracer_provider: SdkTracerProvider,
    logger_provider: SdkLoggerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(err) = self.tracer_provider.shutdown() {
            eprintln!("{err:?}");
        }
        if let Err(err) = self.logger_provider.shutdown() {
            eprintln!("{err:?}");
        }
    }
}

/// This will whether this code is being ran on top of GCP or not.
async fn is_running_on_gcp() -> bool {
    // Check if running in Google Cloud Run: https://cloud.google.com/run/docs/container-contract#services-env-vars
    if std::env::var("K_SERVICE").is_ok() {
        return true;
    }

    let resp = reqwest::Client::new()
        .get("http://metadata.google.internal/computeMetadata/v1/instance/id")
        .header("Metadata-Flavor", "Google")
        .timeout(std::time::Duration::from_millis(200))
        .send()
        .await;

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

fn get_resource(env: &str, node_id: &str) -> Resource {
    static RESOURCE: OnceLock<Resource> = OnceLock::new();
    RESOURCE
        .get_or_init(|| {
            Resource::builder()
                .with_service_name(format!("mpc:{}:{}", env, node_id))
                .with_attributes(vec![
                    KeyValue::new("env", env.to_string()),
                    KeyValue::new("node_id", node_id.to_string()),
                ])
                .build()
        })
        .clone()
}

async fn init_otlp_logs(env: &str, node_id: &str, otlp_endpoint: &str) -> SdkLoggerProvider {
    let exporter = LogExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(format!("{otlp_endpoint}/v1/logs"))
        .build()
        .expect("Failed to create log exporter");

    SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(get_resource(env, node_id))
        .build()
}

async fn init_otlp_traces(env: &str, node_id: &str, otlp_endpoint: &str) -> SdkTracerProvider {
    let exporter = SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary) //can be changed to `Protocol::HttpJson` to export in JSON format
        .with_endpoint(format!("{otlp_endpoint}/v1/traces"))
        .build()
        .expect("Failed to create trace exporter");

    SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(get_resource(env, node_id))
        .build()
}

pub async fn setup(env: &str, node_id: &str, options: &Options) -> OtelGuard {
    let logger_provider = init_otlp_logs(env, node_id, options.otlp_endpoint.as_str()).await;
    let log_otel_layer = OpenTelemetryTracingBridge::new(&logger_provider);

    let log_otel_filter = EnvFilter::new(options.opentelemetry_level.to_string())
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("opentelemetry=off".parse().unwrap())
        .add_directive("tonic=off".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("reqwest=off".parse().unwrap());

    let log_otel_layer = log_otel_layer.with_filter(log_otel_filter);

    let log_fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(atty::is(atty::Stream::Stderr))
        .with_line_number(true)
        .with_thread_names(true)
        .event_format(NodeIdFormatter::new(node_id))
        .with_filter(EnvFilter::from_default_env());

    if is_running_on_gcp().await {
        let log_stackdriver_layer = stackdriver_layer()
            .with_writer(std::io::stderr)
            .with_filter(EnvFilter::from_default_env());

        tracing_subscriber::registry()
            .with(log_fmt_layer)
            .with(log_otel_layer)
            .with(log_stackdriver_layer)
            .init();
        tracing::info!("Set global logging subscriber: fmt, otel, stackdriver");
    } else {
        tracing_subscriber::registry()
            .with(log_fmt_layer)
            .with(log_otel_layer)
            .init();
        tracing::info!("Set global logging subscriber: fmt, otel");
    }

    // Setup tracing
    let tracer_provider = init_otlp_traces(env, node_id, options.otlp_endpoint.as_str()).await;
    global::set_tracer_provider(tracer_provider.clone());

    tracing::info!(
        "Logging parameters: env={}, node_id={}, options={:?}",
        env,
        node_id,
        options
    );

    OtelGuard {
        tracer_provider,
        logger_provider,
    }
}
