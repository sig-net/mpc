use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use sha3::{Digest, Sha3_256};

pub const CHECKPOINT_CHUNK_SIZE: usize = 512 * 1024;

fn etag_for(bytes: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    let hash = hasher.finalize();
    format!("\"{}\"", hex::encode(hash))
}

fn hv(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn hv_owned(value: String) -> HeaderValue {
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn build_200(bytes: Vec<u8>, etag: String) -> Response {
    let len = bytes.len();
    let len_str = len.to_string();
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, hv("application/cbor")),
            (axum::http::header::CONTENT_LENGTH, hv(&len_str)),
            (axum::http::header::ETAG, hv_owned(etag)),
            (axum::http::header::ACCEPT_RANGES, hv("bytes")),
        ],
        bytes,
    )
        .into_response()
}

fn build_206(bytes: Vec<u8>, etag: String, start: usize, end: usize, total: u64) -> Response {
    let slice = bytes[start..=end].to_vec();
    let len_str = slice.len().to_string();
    let content_range = format!("bytes {start}-{end}/{total}");
    (
        StatusCode::PARTIAL_CONTENT,
        [
            (axum::http::header::CONTENT_TYPE, hv("application/cbor")),
            (axum::http::header::CONTENT_LENGTH, hv(&len_str)),
            (axum::http::header::ETAG, hv_owned(etag)),
            (axum::http::header::ACCEPT_RANGES, hv("bytes")),
            (axum::http::header::CONTENT_RANGE, hv(&content_range)),
        ],
        slice,
    )
        .into_response()
}

fn build_416(total: u64) -> Response {
    let content_range = format!("bytes */{total}");
    (
        StatusCode::RANGE_NOT_SATISFIABLE,
        [(axum::http::header::CONTENT_RANGE, hv(&content_range))],
        Vec::<u8>::new(),
    )
        .into_response()
}

fn build_412(etag: String) -> Response {
    (
        StatusCode::PRECONDITION_FAILED,
        [(axum::http::header::ETAG, hv_owned(etag))],
        Vec::<u8>::new(),
    )
        .into_response()
}

fn build_400(msg: String) -> Response {
    (StatusCode::BAD_REQUEST, msg).into_response()
}

#[derive(Debug)]
enum RangeError {
    BadRequest(String),
    Unsatisfiable,
}

fn parse_range(header: &str, total: u64) -> Result<(u64, u64), RangeError> {
    let trimmed = header.trim();
    if !trimmed.starts_with("bytes=") {
        return Err(RangeError::BadRequest("invalid range unit".to_string()));
    }
    let rem = &trimmed["bytes=".len()..];
    let rem = rem.trim();
    if rem.is_empty() {
        return Err(RangeError::BadRequest("empty range".to_string()));
    }
    if rem.contains(',') {
        return Err(RangeError::BadRequest(
            "multiple ranges not supported".to_string(),
        ));
    }
    let dash_count = rem.matches('-').count();
    if dash_count != 1 {
        return Err(RangeError::BadRequest("invalid range format".to_string()));
    }
    let dash = rem.find('-').unwrap_or(0);
    let left = rem[..dash].trim();
    let right = rem[dash + 1..].trim();
    if left.is_empty() {
        return Err(RangeError::BadRequest(
            "suffix range not supported".to_string(),
        ));
    }
    if left.contains(' ') || left.contains('\t') {
        return Err(RangeError::BadRequest("invalid start".to_string()));
    }
    if !right.is_empty() && (right.contains(' ') || right.contains('\t')) {
        return Err(RangeError::BadRequest("invalid end".to_string()));
    }
    let start: u64 = left
        .parse()
        .map_err(|_| RangeError::BadRequest("invalid start".to_string()))?;
    let end: u64 = if right.is_empty() {
        if total == 0 {
            return Err(RangeError::Unsatisfiable);
        }
        total - 1
    } else {
        right
            .parse()
            .map_err(|_| RangeError::BadRequest("invalid end".to_string()))?
    };
    if start >= total {
        return Err(RangeError::Unsatisfiable);
    }
    if start > end {
        return Err(RangeError::Unsatisfiable);
    }
    let end = if end >= total { total - 1 } else { end };
    Ok((start, end))
}

pub fn checkpoint_bytes_response(
    bytes: Vec<u8>,
    range_header: Option<&str>,
    if_match: Option<&str>,
) -> Response {
    let total = bytes.len() as u64;
    let etag = etag_for(&bytes);
    if let Some(ifm) = if_match {
        let trimmed = ifm.trim();
        if trimmed != etag {
            return build_412(etag);
        }
    }
    let Some(range) = range_header else {
        return build_200(bytes, etag);
    };
    let range = range.trim();
    if range.is_empty() {
        return build_200(bytes, etag);
    }
    match parse_range(range, total) {
        Ok((start, end)) => {
            let s = start as usize;
            let e = end as usize;
            build_206(bytes, etag, s, e, total)
        }
        Err(RangeError::BadRequest(msg)) => build_400(msg),
        Err(RangeError::Unsatisfiable) => build_416(total),
    }
}

pub fn parse_content_range(header: &str) -> Result<(u64, u64, u64), String> {
    let h = header.trim();
    if !h.starts_with("bytes ") {
        return Err("invalid content-range unit".to_string());
    }
    let rem = &h["bytes ".len()..];
    let rem = rem.trim();
    let slash = rem.find('/').ok_or("missing slash".to_string())?;
    let left = rem[..slash].trim();
    let right = rem[slash + 1..].trim();
    let dash = left.find('-').ok_or("missing dash".to_string())?;
    let start_str = left[..dash].trim();
    let end_str = left[dash + 1..].trim();
    let start: u64 = start_str.parse().map_err(|_| "invalid start".to_string())?;
    let end: u64 = end_str.parse().map_err(|_| "invalid end".to_string())?;
    let total: u64 = right.parse().map_err(|_| "invalid total".to_string())?;
    if start > end {
        return Err("start > end".to_string());
    }
    if end >= total {
        return Err("end >= total".to_string());
    }
    Ok((start, end, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn etag_is_quoted_hex_and_stable() {
        let data = b"hello world".to_vec();
        let r1 = checkpoint_bytes_response(data.clone(), None, None);
        let etag1 = r1
            .headers()
            .get(axum::http::header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(etag1.starts_with('"') && etag1.ends_with('"'));
        let hex_part = &etag1[1..etag1.len() - 1];
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
        let r2 = checkpoint_bytes_response(data.clone(), None, None);
        let etag2 = r2
            .headers()
            .get(axum::http::header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(etag1, etag2);
        let other = b"different".to_vec();
        let r3 = checkpoint_bytes_response(other, None, None);
        let etag3 = r3
            .headers()
            .get(axum::http::header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_ne!(etag1, etag3);
    }

    #[test]
    fn no_range_returns_200_with_headers() {
        let data = b"abcd1234".to_vec();
        let resp = checkpoint_bytes_response(data.clone(), None, None);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::ACCEPT_RANGES)
                .unwrap(),
            "bytes"
        );
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/cbor"
        );
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_LENGTH)
                .unwrap(),
            "8"
        );
        assert!(resp.headers().get(axum::http::header::ETAG).is_some());
        assert!(resp
            .headers()
            .get(axum::http::header::CONTENT_RANGE)
            .is_none());
    }

    #[test]
    fn range_slice_returns_206_window() {
        let data: Vec<u8> = (0..100).collect();
        let resp = checkpoint_bytes_response(data.clone(), Some("bytes=0-9"), None);
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_RANGE)
                .unwrap(),
            "bytes 0-9/100"
        );
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/cbor"
        );
        assert_eq!(
            resp.headers()
                .get(axum::http::header::ACCEPT_RANGES)
                .unwrap(),
            "bytes"
        );
    }

    #[test]
    fn range_clamps_end_past_total() {
        let data: Vec<u8> = (0..10).collect();
        let resp = checkpoint_bytes_response(data, Some("bytes=5-100"), None);
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_RANGE)
                .unwrap(),
            "bytes 5-9/10"
        );
    }

    #[test]
    fn range_open_end() {
        let data: Vec<u8> = (0..20).collect();
        let resp = checkpoint_bytes_response(data, Some("bytes=10-"), None);
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_RANGE)
                .unwrap(),
            "bytes 10-19/20"
        );
    }

    #[test]
    fn range_unsatisfiable_start_ge_total() {
        let data: Vec<u8> = (0..10).collect();
        let resp = checkpoint_bytes_response(data, Some("bytes=10-20"), None);
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_RANGE)
                .unwrap(),
            "bytes */10"
        );
        let resp2 = checkpoint_bytes_response(vec![1, 2, 3], Some("bytes=5-"), None);
        assert_eq!(resp2.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    }

    #[test]
    fn range_start_gt_end_is_416() {
        let data: Vec<u8> = (0..20).collect();
        let resp = checkpoint_bytes_response(data, Some("bytes=15-10"), None);
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    }

    #[test]
    fn if_match_mismatch_returns_412() {
        let data = b"hello".to_vec();
        let correct_etag = etag_for(&data);
        let wrong = "\"0000000000000000000000000000000000000000000000000000000000000000\"";
        assert_ne!(correct_etag, wrong);
        // first without If-Match -> 200
        let r1 = checkpoint_bytes_response(data.clone(), Some("bytes=0-1"), Some(wrong));
        assert_eq!(r1.status(), StatusCode::PRECONDITION_FAILED);
        // matching should succeed
        let r2 = checkpoint_bytes_response(data.clone(), Some("bytes=0-1"), Some(&correct_etag));
        assert_eq!(r2.status(), StatusCode::PARTIAL_CONTENT);
        // no Range but mismatched If-Match -> also 412 per impl
        let r3 = checkpoint_bytes_response(data, None, Some(wrong));
        assert_eq!(r3.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[test]
    fn parse_reject_suffix_form() {
        let data: Vec<u8> = (0..20).collect();
        let resp = checkpoint_bytes_response(data, Some("bytes=-500"), None);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_reject_multi_range() {
        let data: Vec<u8> = (0..20).collect();
        let resp = checkpoint_bytes_response(data, Some("bytes=0-5,10-15"), None);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_reject_garbage() {
        let data: Vec<u8> = (0..20).collect();
        for bad in [
            "bytes=abc",
            "bytes=0-abc",
            "bytes=",
            "garbage",
            "bytes=0--5",
        ] {
            let resp = checkpoint_bytes_response(data.clone(), Some(bad), None);
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "failed for {bad}");
        }
    }

    #[test]
    fn parse_whitespace_around_numbers() {
        let data: Vec<u8> = (0..20).collect();
        let resp = checkpoint_bytes_response(data, Some("bytes= 1 - 3 "), None);
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_RANGE)
                .unwrap(),
            "bytes 1-3/20"
        );
    }

    #[test]
    fn parse_content_range_ok() {
        let (s, e, t) = parse_content_range("bytes 0-511/1024").unwrap();
        assert_eq!((s, e, t), (0, 511, 1024));
        let (s, e, t) = parse_content_range("bytes 512-1023/1024").unwrap();
        assert_eq!((s, e, t), (512, 1023, 1024));
    }

    #[test]
    fn parse_content_range_reject() {
        assert!(parse_content_range("bytes */1024").is_err());
        assert!(parse_content_range("invalid").is_err());
    }

    #[test]
    fn parse_single_zero() {
        let data: Vec<u8> = (0..10).collect();
        let resp = checkpoint_bytes_response(data, Some("bytes=0-0"), None);
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_RANGE)
                .unwrap(),
            "bytes 0-0/10"
        );
    }
}
