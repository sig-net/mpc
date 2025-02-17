use std::fmt::{self, Display};

use opentelemetry::sdk::Resource;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::{self, RandomIdGenerator, Sampler};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
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

    #[clap(
        long,
        env("MPC_OTLP_ENDPOINT"),
        default_value = "http://localhost:4317"
    )]
    pub otlp_endpoint: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            opentelemetry_level: OpenTelemetryLevel::DEBUG,
            otlp_endpoint: "http://localhost:4317".to_string(),
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

pub fn setup(env: &str, node_id: &str, options: &Options, rt: &tokio::runtime::Runtime) {
    let subscriber = Registry::default().with(EnvFilter::from_default_env());

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(atty::is(atty::Stream::Stderr))
        .with_line_number(true)
        .with_thread_names(true)
        .event_format(NodeIdFormatter::new(node_id));

    let trace_config = trace::config()
        .with_sampler(Sampler::AlwaysOn)
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(Resource::new(vec![
            KeyValue::new(SERVICE_NAME, format!("mpc:{}:{}", env, node_id)),
            KeyValue::new("env", env.to_string()),
            KeyValue::new("node_id", node_id.to_string()),
        ]));

    let tracer = rt.block_on(async {
        opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .http()
                    .with_endpoint(options.otlp_endpoint.clone()),
            )
            .with_trace_config(trace_config)
            .install_batch(opentelemetry::runtime::Tokio)
            .expect("Failed to build OpenTelemetry tracer")
    });

    let otel_layer = tracing_opentelemetry::layer()
        .with_tracer(tracer)
        .with_filter(EnvFilter::new(options.opentelemetry_level.to_string()));

    let subscriber = subscriber.with(fmt_layer).with(otel_layer);

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");
}
