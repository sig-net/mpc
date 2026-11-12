use alloy::transports::{
    RpcError as AlloyRpcError, TransportError as AlloyTransportError, TransportErrorKind,
};
use http::StatusCode;
use std::time::Duration;

/// Whether an HTTP status makes an RPC call worth retrying: 408/429 are
/// transient, 402 stays retryable (pairs with the cooldown gate — providers
/// refill credits on their own schedule), 5xx are the server's fault, and
/// everything else — other 4xx, but also redirects — is terminal. A redirect
/// loop never fixes itself by retrying, so it must not be retried to exhaustion.
pub fn http_status_retryable(status: StatusCode) -> bool {
    if matches!(
        status,
        StatusCode::PAYMENT_REQUIRED | StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
    ) {
        return true;
    }
    status.is_server_error()
}

/// Reads counterpart: only classic client errors are terminal — reads are
/// cheap and a retry can land on a healthy LB backend.
pub fn http_status_read_retryable(status: StatusCode) -> bool {
    !matches!(
        status,
        StatusCode::BAD_REQUEST
            | StatusCode::UNAUTHORIZED
            | StatusCode::FORBIDDEN
            | StatusCode::NOT_FOUND
            | StatusCode::METHOD_NOT_ALLOWED
    )
}

/// Typed RPC failure chain for classifying errors in the retry logic.
// TODO: two-step transition — the string fallbacks in `is_retryable`/
// `is_provider_throttled` go once every chain attaches typed failures; the
// carrier and chain-side classify helpers go once retry/publish boundaries
// return typed verdict enums (variant matching, not chain walks).
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct RpcFailure {
    /// Human-readable error message.
    message: String,
    /// HTTP status code associated with the failure, if any.
    status: Option<StatusCode>,
    /// JSON-RPC error code identifying the failure, if any.
    code: Option<i64>,
    /// Whether this failure is considered terminal.
    terminal: bool,
    /// Provider-advertised pause (`Retry-After`), read by the gate on
    /// throttles.
    retry_after: Option<Duration>,
}

impl RpcFailure {
    /// Send-path verdict for a status, per [`http_status_retryable`].
    pub fn send_status(status: StatusCode, message: String) -> Self {
        Self::with_verdict(status, !http_status_retryable(status), message)
    }

    /// Read-path verdict for a status, per [`http_status_read_retryable`].
    pub fn read_status(status: StatusCode, message: String) -> Self {
        Self::with_verdict(status, !http_status_read_retryable(status), message)
    }

    /// Retryable verdict that keeps the status — throttle detection still
    /// reads it — for a chain error code overruling the envelope (a
    /// concurrent-submission 409, a mempool rejection riding a 4xx).
    pub fn retryable_with_status(status: StatusCode, message: String) -> Self {
        Self::with_verdict(status, false, message)
    }

    /// Constructs an `RpcFailure` with the given status, terminal flag, and message.
    fn with_verdict(status: StatusCode, terminal: bool, message: String) -> Self {
        Self {
            message,
            status: Some(status),
            code: None,
            terminal,
            retry_after: None,
        }
    }

    /// Constructs a new terminal `RpcFailure` with the given message.
    pub fn terminal(message: String) -> Self {
        Self {
            message,
            status: None,
            code: None,
            terminal: true,
            retry_after: None,
        }
    }

    /// Terminal failure carrying its JSON-RPC error code for consumers that act on it.
    pub fn terminal_code(code: i64, message: String) -> Self {
        Self {
            message,
            status: None,
            code: Some(code),
            terminal: true,
            retry_after: None,
        }
    }

    /// Constructs a new retryable `RpcFailure` with the given message.
    pub fn retryable(message: String) -> Self {
        Self {
            message,
            status: None,
            code: None,
            terminal: false,
            retry_after: None,
        }
    }

    /// Returns the HTTP status code associated with this failure, if any.
    pub fn status(&self) -> Option<StatusCode> {
        self.status
    }

    /// Returns the JSON-RPC error code associated with this failure, if any.
    pub fn code(&self) -> Option<i64> {
        self.code
    }

    /// Returns true if this failure is considered terminal.
    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Sets the advertised pause.
    pub fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.retry_after = Some(retry_after);
        self
    }

    /// The advertised pause, if any.
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// Carrier reproducing `e`'s classification — verdict carrier or first
    /// typed status — with the full chain render as its message, so fan-out
    /// copies keep outer contexts. `None` when `e` has no typed signal.
    /// The bare-status fallback is send-partitioned; read-side fan-outs
    /// rebuild with `read_status`.
    pub fn from_chain(e: &anyhow::Error) -> Option<Self> {
        let (failure, status) = typed_signals(e);
        if let Some(failure) = failure {
            return Some(Self {
                message: format!("{e:#}"),
                status: failure.status,
                code: failure.code,
                terminal: failure.terminal,
                retry_after: failure.retry_after,
            });
        }
        status.map(|status| Self::send_status(status, format!("{e:#}")))
    }
}

/// Typed signals from one walk of the anyhow chain: the first [`RpcFailure`]`/
/// its verdict, and the first typed HTTP status (on a [`RpcFailure`] or an
/// alloy transport error wrapping an HTTP response).
fn typed_signals(e: &anyhow::Error) -> (Option<&RpcFailure>, Option<StatusCode>) {
    e.chain().fold((None, None), |(failure, status), cause| {
        (
            failure.or_else(|| cause.downcast_ref::<RpcFailure>()),
            status.or_else(|| cause_status(cause)),
        )
    })
}

/// HTTP status carried by a single error cause, if any. A bare `HttpError`
/// is accepted too: `#[error(transparent)]` forwards `source()` through the
/// field, so wrapper enums (alloy-contract's `Error`) collapse onto the
/// `HttpError`, hiding the `RpcError` level.
fn cause_status(cause: &(dyn std::error::Error + 'static)) -> Option<StatusCode> {
    if let Some(failure) = cause.downcast_ref::<RpcFailure>() {
        return failure.status;
    }
    if let Some(http) = cause.downcast_ref::<alloy::transports::HttpError>() {
        return StatusCode::from_u16(http.status).ok();
    }
    // `status()` is Some only for error_for_status() products (reqwest 0.12.28
    // error.rs:174). Only bare reqwest causes reach this: solana's
    // `Box<ErrorKind>` nesting hides the inner error from the walk, so its
    // publisher carries the status explicitly.
    if let Some(status) = cause
        .downcast_ref::<reqwest::Error>()
        .and_then(|e| e.status())
    {
        return Some(status);
    }
    let err = cause.downcast_ref::<AlloyTransportError>()?;
    let AlloyRpcError::Transport(TransportErrorKind::HttpError(http)) = err else {
        return None;
    };
    StatusCode::from_u16(http.status).ok()
}

/// Returns true if the error looks like the provider throttling us: HTTP 429
/// (rate limited) or 402 (payment required, e.g. exhausted credits).
pub fn is_provider_throttled(e: &anyhow::Error) -> bool {
    let (failure, status) = typed_signals(e);
    // Typed status is authoritative over body text (if present).
    if let Some(status) = status {
        return status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::PAYMENT_REQUIRED;
    }
    // A carrier is a typed boundary's deliberate verdict: no status means no
    // throttle, regardless of embedded text.
    if failure.is_some() {
        return false;
    }
    // TODO: last-resort fallback for chains surfacing statuses only as text;
    // Delete once every chain client attaches typed statuses.
    // `{:#}` renders the full context chain — a 429 can sit under `with_context`
    let s = format!("{e:#}");
    contains_status_code(&s, "429") || contains_status_code(&s, "402")
}

/// Returns true if `s` contains `code` as a standalone number, i.e. not
/// embedded in a longer digit run. Prevents ports, slots, or request ids from
/// being mistaken for HTTP status codes (e.g. "127.0.0.1:40329" contains "403").
fn contains_status_code(s: &str, code: &str) -> bool {
    let bytes = s.as_bytes();
    let mut start = 0;
    while let Some(pos) = s[start..].find(code) {
        let i = start + pos;
        let end = i + code.len();
        // alphanumeric boundaries: hex/base58 runs (…a429f…) must not read as status codes
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        let after_ok = end >= bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        start = i + 1;
    }
    false
}

/// Helper to identify whether an RPC error should be retried.
/// Protects against endlessly retrying terminal client errors (4xx).
pub fn is_retryable(e: &anyhow::Error) -> bool {
    // Explicit typed verdict wins over any message text; otherwise the first
    // typed HTTP status decides.
    let (failure, status) = typed_signals(e);
    if let Some(f) = failure {
        return !f.terminal;
    }
    if let Some(status) = status {
        return http_status_retryable(status);
    }

    // TODO: last-resort fallback for chains surfacing statuses only as text;
    // Delete once every chain client attaches typed statuses.
    let s = e.to_string();
    // 408 Request Timeout and 429 Too Many Requests are retryable.
    if contains_status_code(&s, "408") || contains_status_code(&s, "429") {
        return true;
    }
    // Other 4xx errors are generally client errors and should not be retried.
    if contains_status_code(&s, "400")
        || contains_status_code(&s, "401")
        || contains_status_code(&s, "403")
        || contains_status_code(&s, "404")
        || contains_status_code(&s, "405")
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_errors_are_not_retryable() {
        for code in ["400", "401", "403", "404", "405"] {
            let e = anyhow::anyhow!(
                "HTTP status client error ({code} Some Reason) for url (http://127.0.0.1:1234/)"
            );
            assert!(!is_retryable(&e), "{code} should not be retryable");
        }
    }

    #[test]
    fn detects_provider_throttling_errors() {
        assert!(is_provider_throttled(&anyhow::anyhow!(
            "HTTP status client error (429 Too Many Requests) for url (http://x/)"
        )));
        assert!(is_provider_throttled(&anyhow::anyhow!(
            "rpc: the server returned a non-OK (200) status code: [402 Payment Required]"
        )));
        // Port 42900 contains "429"; the 500 must not be mistaken for throttling.
        assert!(!is_provider_throttled(&anyhow::anyhow!(
            "HTTP status server error (500) for url (http://127.0.0.1:42900/)"
        )));
        assert!(!is_provider_throttled(&anyhow::anyhow!(
            "HTTP status client error (403 Forbidden)"
        )));
        // a 429 underneath `with_context` still engages (full chain scanned)
        assert!(is_provider_throttled(
            &anyhow::anyhow!(
                "HTTP status client error (429 Too Many Requests) for url (http://x/)"
            )
            .context("submitting the midnight respond intent built over the chain at 0x9c1f")
        ));
        // hex fragments must not read as throttles (alphanumeric boundaries)
        assert!(!is_provider_throttled(&anyhow::anyhow!(
            "submitting the midnight respond intent built over the chain at 0xa429f"
        )));
        assert!(!is_provider_throttled(&anyhow::anyhow!(
            "no spendable dust for transfer c402e5819d2b"
        )));
    }

    #[test]
    fn retryable_errors() {
        for msg in [
            // Regression: port 40329 contains "403"; the 500 must still be retried.
            "HTTP status server error (500 Internal Server Error) for url (http://127.0.0.1:40329/)",
            // Digits embedded in longer numbers (ports, slots) are not status codes.
            "server error (500) for url (http://host:14290/)",
            "error at slot 14005",
            // 408/429 are explicitly retryable.
            "HTTP status client error (408 Request Timeout)",
            "HTTP status client error (429 Too Many Requests)",
        ] {
            assert!(is_retryable(&anyhow::anyhow!(msg)), "{msg:?} should be retryable");
        }
    }

    #[test]
    fn http_status_retryable_table() {
        let status = |n: u16| StatusCode::from_u16(n).unwrap();
        // 402 pairs with the cooldown gate (credit refill), 408/429 are transient by definition
        for n in [402, 408, 429] {
            assert!(http_status_retryable(status(n)), "{n} should be retryable");
        }
        // every other 4xx is a client error another attempt cannot fix, and
        // redirects (a redirect loop cannot be retried out of) are terminal too
        for n in [400, 401, 403, 404, 405, 409, 410, 422, 499, 301, 308] {
            assert!(!http_status_retryable(status(n)), "{n} should be terminal");
        }
        // 5xx default to retryable
        for n in [500, 502, 503, 504, 599] {
            assert!(http_status_retryable(status(n)), "{n} should be retryable");
        }
    }

    #[test]
    fn http_status_read_retryable_table() {
        let status = |n: u16| StatusCode::from_u16(n).unwrap();
        // classic client errors are properties of the request: terminal
        for n in [400, 401, 403, 404, 405] {
            assert!(!http_status_read_retryable(status(n)), "{n}");
        }
        // everything else — including table-terminal 409/410/redirects — gets
        // another cheap read attempt
        for n in [402, 408, 409, 410, 422, 429, 301, 500] {
            assert!(http_status_read_retryable(status(n)), "{n}");
        }
    }

    #[test]
    fn read_status_derives_the_verdict_from_the_read_partition() {
        let status = |n: u16| StatusCode::from_u16(n).unwrap();
        let throttled: anyhow::Error =
            RpcFailure::read_status(status(429), "rate limited".into()).into();
        assert!(is_retryable(&throttled));
        assert!(is_provider_throttled(&throttled));
        // 402 keeps both load-bearing: read-retryable, yet the carried
        // status still engages the credit-refill gate
        let payment: anyhow::Error =
            RpcFailure::read_status(status(402), "payment required".into()).into();
        assert!(is_retryable(&payment));
        assert!(is_provider_throttled(&payment));
        // 409 is send-terminal but read-retryable
        let conflict: anyhow::Error =
            RpcFailure::read_status(status(409), "conflict".into()).into();
        assert!(is_retryable(&conflict));
        assert!(!is_provider_throttled(&conflict));
        let not_found: anyhow::Error =
            RpcFailure::read_status(status(404), "not found".into()).into();
        assert!(!is_retryable(&not_found));
    }

    #[test]
    fn terminal_code_carries_the_code_through_contexts() {
        let err = anyhow::Error::new(RpcFailure::terminal_code(-32007, "Slot was skipped".into()))
            .context("get_block");
        assert!(!is_retryable(&err));
        let code = err
            .chain()
            .find_map(|c| c.downcast_ref::<RpcFailure>())
            .and_then(|f| f.code());
        assert_eq!(code, Some(-32007));
        // from_chain rebuilds preserve the code for fan-outs
        assert_eq!(RpcFailure::from_chain(&err).unwrap().code(), Some(-32007));
    }

    #[test]
    fn rpc_failure_verdict_is_authoritative_over_message_text() {
        // send_status derives the verdict from the status, not the message
        let throttled: anyhow::Error = RpcFailure::send_status(
            StatusCode::TOO_MANY_REQUESTS,
            "nothing suspicious in this text".into(),
        )
        .into();
        assert!(is_retryable(&throttled));
        assert!(is_provider_throttled(&throttled));

        // 409 is terminal by status, even though the body text mentions 429
        let terminal: anyhow::Error = RpcFailure::send_status(
            StatusCode::CONFLICT,
            "conflict; body says 429 retry now".into(),
        )
        .into();
        assert!(!is_retryable(&terminal));
        assert!(!is_provider_throttled(&terminal));

        // status-less verdicts work in both directions
        let explicit_terminal: anyhow::Error =
            RpcFailure::terminal("already accepted".into()).into();
        assert!(!is_retryable(&explicit_terminal));
        let explicit_retryable: anyhow::Error =
            RpcFailure::retryable("transient downstream hiccup".into()).into();
        assert!(is_retryable(&explicit_retryable));
        // no status → no throttle signal
        assert!(!is_provider_throttled(&explicit_retryable));
        // ... not even from embedded text: a standalone "429" in an id must
        // not engage the gate
        let id_tripwire: anyhow::Error =
            RpcFailure::retryable("route to upstream node-429 reset".into()).into();
        assert!(!is_provider_throttled(&id_tripwire));
    }

    #[test]
    fn rpc_failure_under_context_still_classifies() {
        // context wrappers must not hide the typed carrier
        let err = anyhow::Error::new(RpcFailure::send_status(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limited".into(),
        ))
        .context("submitting transaction");
        assert!(is_retryable(&err));
        assert!(is_provider_throttled(&err));
    }

    #[test]
    fn from_chain_reproduces_the_effective_classification() {
        // carrier present: verdict kept, outer contexts survive the rebuild
        let err = anyhow::Error::new(RpcFailure::terminal("already accepted".into()))
            .context("exhausted after 3 attempts");
        let rebuilt = RpcFailure::from_chain(&err).unwrap();
        assert!(rebuilt.is_terminal());
        assert!(!is_retryable(
            &anyhow::Error::new(rebuilt.clone()).context("fan-out")
        ));
        assert!(rebuilt.to_string().contains("exhausted after 3 attempts"));

        // no carrier, but a typed status: verdict derives from the status
        let err: anyhow::Error = {
            let err: AlloyTransportError = AlloyRpcError::Transport(TransportErrorKind::HttpError(
                alloy::transports::HttpError {
                    status: 409,
                    body: String::new(),
                },
            ));
            anyhow::Error::new(err)
        };
        let err = err.context("exhausted after 1 attempts");
        let rebuilt = RpcFailure::from_chain(&err).unwrap();
        assert!(!is_retryable(
            &anyhow::Error::new(rebuilt).context("fan-out")
        ));

        // no typed signal at all
        assert!(RpcFailure::from_chain(&anyhow::anyhow!("plain failure")).is_none());
    }

    #[test]
    fn alloy_http_error_classifies_typed() {
        // simulate alloy HTTP errors and check their classification
        let alloy_http_error = |status: u16| {
            let kind = TransportErrorKind::HttpError(alloy::transports::HttpError {
                status,
                body: String::new(),
            });
            let err: AlloyTransportError = AlloyRpcError::Transport(kind);
            anyhow::Error::new(err)
        };
        assert!(is_retryable(&alloy_http_error(429)));
        assert!(is_provider_throttled(&alloy_http_error(429)));
        assert!(!is_retryable(&alloy_http_error(404)));
        assert!(!is_provider_throttled(&alloy_http_error(404)));
        // 409 arrives typed from alloy transports and classifies as terminal
        assert!(!is_retryable(&alloy_http_error(409)));
        // a synthetic invalid status cannot become a StatusCode, so the typed
        // path yields no status and the default (retryable) applies
        assert!(is_retryable(&alloy_http_error(0)));
    }

    #[test]
    fn transparent_wrappers_collapse_onto_the_http_error_and_still_classify() {
        // thiserror `#[error(transparent)]` forwards source() through the
        // field, so wrapper enums hide the RpcError level (alloy-contract's
        // Error does exactly this) — the bare HttpError must still classify
        #[derive(Debug, thiserror::Error)]
        #[error(transparent)]
        struct Wrapper(AlloyTransportError);

        let wrapped = |status: u16| {
            let kind = TransportErrorKind::HttpError(alloy::transports::HttpError {
                status,
                body: String::new(),
            });
            anyhow::Error::new(Wrapper(AlloyRpcError::Transport(kind)))
        };
        assert_eq!(wrapped(409).chain().count(), 2, "fixture must collapse");
        assert!(!is_retryable(&wrapped(409)));
        assert!(is_retryable(&wrapped(429)));
        assert!(is_provider_throttled(&wrapped(429)));
    }

    #[tokio::test]
    async fn reqwest_status_errors_classify_by_status() {
        // real transport round trip: only error_for_status() errors carry a status
        let mut server = mockito::Server::new_async().await;
        let client = reqwest::Client::new();

        let throttled = server
            .mock("GET", "/")
            .with_status(429)
            .create_async()
            .await;
        let err = anyhow::Error::new(
            client
                .get(server.url())
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap_err(),
        )
        .context("getSlot");
        assert!(is_retryable(&err));
        assert!(is_provider_throttled(&err));
        throttled.assert();

        let conflict = server
            .mock("GET", "/")
            .with_status(409)
            .create_async()
            .await;
        let err = anyhow::Error::new(
            client
                .get(server.url())
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap_err(),
        )
        .context("getSlot");
        assert!(!is_retryable(&err));
        conflict.assert();

        // no status seen (connection refused): no typed signal, no gate
        let err = anyhow::Error::new(client.get("http://127.0.0.1:1").send().await.unwrap_err());
        assert!(err
            .downcast_ref::<reqwest::Error>()
            .and_then(|e| e.status())
            .is_none());
        assert!(!is_provider_throttled(&err));
    }
}
