use std::fmt::{self, Display};
use std::io::IsTerminal;
use std::sync::OnceLock;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use tracing::{Event, Subscriber};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_stackdriver::layer as stackdriver_layer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::{Format, FormatEvent, Full};
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::fmt::{format, FmtContext, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

#[derive(Debug, Clone, clap::Parser)]
pub struct Options {
    #[arg(
        long,
        env("MPC_OPENTELEMETRY_LEVEL"),
        value_enum,
        default_value_t = OpenTelemetryLevel::default()
    )]
    pub opentelemetry_level: OpenTelemetryLevel,

    #[arg(
        long,
        env("MPC_OTLP_ENDPOINT"),
        default_value = "http://localhost:4318",
        hide_env_values = true
    )]
    pub otlp_endpoint: String,

    /// Console log format. `json` is GCP Cloud Logging structured output.
    #[arg(long, env("MPC_LOG_FORMAT"), value_enum, default_value_t = LogFormat::Plain)]
    pub log_format: LogFormat,
}

/// Deployment a node belongs to; labels logs and telemetry.
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Env {
    Dev,
    Testnet,
    Mainnet,
    /// Integration tests; test builds only.
    #[cfg(feature = "test-feature")]
    Test,
}

impl Env {
    pub fn as_str(self) -> &'static str {
        match self {
            Env::Dev => "dev",
            Env::Testnet => "testnet",
            Env::Mainnet => "mainnet",
            #[cfg(feature = "test-feature")]
            Env::Test => "test",
        }
    }
}

impl Display for Env {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum LogFormat {
    /// Human-readable lines.
    #[default]
    Plain,
    /// GCP Cloud Logging structured lines.
    Json,
}

impl Display for LogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            LogFormat::Plain => "plain",
            LogFormat::Json => "json",
        };
        write!(f, "{str}")
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
        write!(f, "{str}")
    }
}

impl OpenTelemetryLevel {
    fn level_filter(self) -> LevelFilter {
        match self {
            OpenTelemetryLevel::OFF => LevelFilter::OFF,
            OpenTelemetryLevel::INFO => LevelFilter::INFO,
            OpenTelemetryLevel::DEBUG => LevelFilter::DEBUG,
            OpenTelemetryLevel::TRACE => LevelFilter::TRACE,
        }
    }
}

#[derive(Default)]
pub struct OtlpGuard {
    tracer_otlp_provider: Option<SdkTracerProvider>,
    log_otlp_provider: Option<SdkLoggerProvider>,
}

impl Drop for OtlpGuard {
    fn drop(&mut self) {
        if let Some(p) = &self.tracer_otlp_provider {
            p.shutdown().unwrap_or_else(|err| eprintln!("{err:?}"));
        }
        if let Some(p) = &self.log_otlp_provider {
            p.shutdown().unwrap_or_else(|err| eprintln!("{err:?}"));
        }
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
            repr: format!("NodeId({node_id})"),
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

fn get_resource(env: Env, node_id: &str) -> Resource {
    static RESOURCE: OnceLock<Resource> = OnceLock::new();
    RESOURCE
        .get_or_init(|| {
            // OpenTelemetry resource conventions, so shared backends filter by them.
            Resource::builder()
                .with_service_name("mpc")
                .with_attributes([
                    KeyValue::new("deployment.environment.name", env.as_str()),
                    KeyValue::new("service.instance.id", node_id.to_string()),
                ])
                .build()
        })
        .clone()
}

async fn init_otlp_logs(env: Env, node_id: &str, otlp_endpoint: &str) -> SdkLoggerProvider {
    let exporter = LogExporter::builder()
        .with_http()
        .with_endpoint(format!("{otlp_endpoint}/v1/logs"))
        .build()
        .expect("Failed to create log exporter");

    SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(get_resource(env, node_id))
        .build()
}

async fn init_otlp_traces(env: Env, node_id: &str, otlp_endpoint: &str) -> SdkTracerProvider {
    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(format!("{otlp_endpoint}/v1/traces"))
        .build()
        .expect("Failed to create trace exporter");

    SdkTracerProvider::builder()
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            1.0,
        ))))
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(get_resource(env, node_id))
        .with_batch_exporter(exporter)
        .build()
}

pub async fn setup(env: Env, node_id: &str, options: &Options) -> OtlpGuard {
    let (otlp_guard, log_otlp_layer, otlp_tracer) = match options.opentelemetry_level {
        OpenTelemetryLevel::OFF => (OtlpGuard::default(), None, None),
        _ => {
            let log_provider = init_otlp_logs(env, node_id, &options.otlp_endpoint).await;
            let log_layer = OpenTelemetryTracingBridge::new(&log_provider);
            let trace_provider = init_otlp_traces(env, node_id, &options.otlp_endpoint).await;
            let tracer = trace_provider.tracer("mpc");
            (
                OtlpGuard {
                    tracer_otlp_provider: Some(trace_provider),
                    log_otlp_provider: Some(log_provider),
                },
                Some(log_layer),
                Some(tracer),
            )
        }
    };
    let otlp_filter = options.opentelemetry_level.level_filter();

    let json = options.log_format == LogFormat::Json;
    let log_fmt_layer = (!json).then(|| {
        tracing_subscriber::fmt::layer()
            .with_ansi(std::io::stderr().is_terminal())
            .with_line_number(true)
            .with_thread_names(true)
            .event_format(NodeIdFormatter::new(node_id))
            .with_filter(EnvFilter::from_default_env())
    });
    let log_gcp_layer = json.then(|| {
        stackdriver_layer()
            .with_writer(std::io::stderr)
            .with_filter(EnvFilter::from_default_env())
    });

    tracing_subscriber::registry()
        .with(log_fmt_layer)
        .with(log_gcp_layer)
        .with(log_otlp_layer.with_filter(otlp_filter))
        .with(
            otlp_tracer
                .map(OpenTelemetryLayer::new)
                .with_filter(otlp_filter),
        )
        .init();
    // Panics go through tracing so the line explaining a restart reaches OTLP.
    // The default hook still runs afterwards, so `RUST_BACKTRACE` keeps working.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = %info, "task panicked");
        default_hook(info);
    }));
    // Not logging the endpoint: it may carry a token.
    tracing::info!(
        %env,
        node_id,
        otel_level = ?options.opentelemetry_level,
        otlp = !matches!(options.opentelemetry_level, OpenTelemetryLevel::OFF),
        log_format = %options.log_format,
        "logging configured"
    );

    otlp_guard
}

#[cfg(test)]
mod tests {
    use super::{Env, LogFormat, Options};
    use clap::{CommandFactory as _, Parser as _};

    fn parse(extra: &[&str]) -> Result<Options, clap::Error> {
        Options::try_parse_from(["test"].into_iter().chain(extra.iter().copied()))
    }

    /// The declared defaults, pinned: a change here changes every deployment that
    /// sets nothing. Read from the command so `MPC_*` variables in the shell do not
    /// leak in.
    #[test]
    fn defaults_are_pinned() {
        let command = Options::command();
        let default = |id: &str| {
            let arg = command
                .get_arguments()
                .find(|arg| arg.get_id() == id)
                .unwrap_or_else(|| panic!("{id} exists"));
            arg.get_default_values()[0].to_string_lossy().into_owned()
        };
        assert_eq!(default("log_format"), "plain");
        assert_eq!(default("opentelemetry_level"), "off");
        assert_eq!(default("otlp_endpoint"), "http://localhost:4318");
    }

    #[test]
    fn log_format_accepts_plain_and_json_only() {
        assert_eq!(
            parse(&["--log-format", "json"]).unwrap().log_format,
            LogFormat::Json
        );
        assert_eq!(
            parse(&["--log-format", "plain"]).unwrap().log_format,
            LogFormat::Plain
        );
        assert!(parse(&["--log-format", "gcp"]).is_err());
    }

    /// The old negative flag is gone, not silently ignored.
    #[test]
    fn disable_gcp_logs_is_rejected() {
        assert!(parse(&["--disable-gcp-logs"]).is_err());
    }

    /// The `--env` values, pinned: deployments set these names.
    #[test]
    fn env_values_are_pinned() {
        use clap::ValueEnum as _;
        let names: Vec<_> = Env::value_variants()
            .iter()
            .map(|env| env.as_str())
            .collect();
        let expected: &[&str] = if cfg!(feature = "test-feature") {
            &["dev", "testnet", "mainnet", "test"]
        } else {
            &["dev", "testnet", "mainnet"]
        };
        assert_eq!(names, expected);
        for env in Env::value_variants() {
            assert_eq!(Env::from_str(env.as_str(), false).unwrap(), *env);
        }
    }
}
