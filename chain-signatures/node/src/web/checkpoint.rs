use super::client::{NodeClient, RequestError};
use super::range::CHECKPOINT_CHUNK_SIZE;

use hyper::StatusCode;
use std::time::Duration;
use url::Url;

const CHUNK_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESTARTS: usize = 3;

enum Retry {
    Restart,
    Error(RequestError),
}

impl From<RequestError> for Retry {
    fn from(e: RequestError) -> Self {
        Self::Error(e)
    }
}

struct PartialChunk {
    start: u64,
    end: u64,
    total: u64,
    etag: Option<String>,
    body: Vec<u8>,
}

enum RangeBody {
    Complete(Vec<u8>),
    Partial(PartialChunk),
}

struct RangeFetch {
    assembled: Vec<u8>,
    etag: Option<String>,
    offset: u64,
    total: Option<u64>,
}

impl RangeFetch {
    fn new() -> Self {
        Self {
            assembled: Vec::new(),
            etag: None,
            offset: 0,
            total: None,
        }
    }

    fn append(&mut self, chunk: PartialChunk) -> Result<(), Retry> {
        if chunk.start != self.offset {
            return Err(Retry::Error(RequestError::Conversion(format!(
                "unexpected start {} != {}",
                chunk.start, self.offset
            ))));
        }
        if let Some(expected) = self.total {
            if expected != chunk.total {
                return Err(Retry::Restart);
            }
        } else {
            self.total = Some(chunk.total);
            self.etag = chunk.etag;
        }
        self.assembled.extend_from_slice(&chunk.body);
        self.offset = chunk.end + 1;
        Ok(())
    }

    fn complete(&self) -> bool {
        let Some(total) = self.total else {
            return false;
        };
        self.assembled.len() as u64 >= total || self.offset >= total
    }
}

fn parse_range(header: &str) -> Result<(u64, u64, u64), RequestError> {
    super::range::parse_content_range(header).map_err(RequestError::Conversion)
}

async fn response_body(resp: reqwest::Response) -> Result<Vec<u8>, Retry> {
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| Retry::Error(RequestError::MalformedBody(e)))?;
    Ok(bytes.to_vec())
}

async fn request_error(resp: reqwest::Response) -> Retry {
    let status = resp.status();
    let request_id = NodeClient::extract_request_id(&resp);
    let bytes = match resp.bytes().await {
        Ok(bytes) => bytes,
        Err(err) => return Retry::Error(RequestError::MalformedBody(err)),
    };
    match std::str::from_utf8(&bytes) {
        Ok(msg) => Retry::Error(RequestError::Unsuccessful(status, msg.into(), request_id)),
        Err(err) => Retry::Error(RequestError::MalformedResponse(err)),
    }
}

async fn parse_partial(resp: reqwest::Response) -> Result<PartialChunk, Retry> {
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let content_range = resp
        .headers()
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Retry::Error(RequestError::Conversion("missing Content-Range".into())))?
        .to_string();
    let (start, end, total) = parse_range(&content_range).map_err(Retry::Error)?;
    let body = response_body(resp).await?;
    let expected = end.saturating_sub(start).saturating_add(1);
    if body.len() as u64 != expected {
        return Err(Retry::Error(RequestError::Conversion(format!(
            "chunk length {} != {expected}",
            body.len()
        ))));
    }
    Ok(PartialChunk {
        start,
        end,
        total,
        etag,
        body,
    })
}

async fn read_range(resp: reqwest::Response, first: bool) -> Result<RangeBody, Retry> {
    let status = resp.status();
    if status == StatusCode::OK {
        return Ok(RangeBody::Complete(response_body(resp).await?));
    }
    if status == StatusCode::PARTIAL_CONTENT {
        return Ok(RangeBody::Partial(parse_partial(resp).await?));
    }
    if status == StatusCode::PRECONDITION_FAILED || status == StatusCode::RANGE_NOT_SATISFIABLE {
        if !first {
            return Err(Retry::Restart);
        }
        return Err(request_error(resp).await);
    }
    if status.is_success() {
        return Ok(RangeBody::Complete(response_body(resp).await?));
    }
    Err(request_error(resp).await)
}

impl NodeClient {
    pub(crate) async fn fetch_bytes(&self, url: Url) -> Result<Vec<u8>, RequestError> {
        for _ in 0..=MAX_RESTARTS {
            match self.fetch_once(url.clone()).await {
                Ok(bytes) => return Ok(bytes),
                Err(Retry::Restart) => continue,
                Err(Retry::Error(err)) => return Err(err),
            }
        }
        Err(RequestError::Conversion("too many restarts".to_string()))
    }

    async fn fetch_once(&self, url: Url) -> Result<Vec<u8>, Retry> {
        let mut fetch = RangeFetch::new();
        loop {
            match self
                .request_range(&url, fetch.offset, fetch.etag.as_deref())
                .await?
            {
                RangeBody::Complete(bytes) => return Ok(bytes),
                RangeBody::Partial(chunk) => fetch.append(chunk)?,
            }
            if fetch.complete() {
                return Ok(fetch.assembled);
            }
        }
    }

    async fn request_range(
        &self,
        url: &Url,
        start: u64,
        etag: Option<&str>,
    ) -> Result<RangeBody, Retry> {
        let end = start + CHECKPOINT_CHUNK_SIZE as u64 - 1;
        let mut req = self
            .http
            .get(url.clone())
            .timeout(CHUNK_TIMEOUT)
            .header("Range", format!("bytes={start}-{end}"));
        if let Some(etag) = etag {
            req = req.header("If-Match", etag);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| Retry::Error(RequestError::ReqwestClient(e)))?;
        read_range(resp, start == 0).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::{BacklogEntry, Checkpoint};
    use crate::web::client::{decode_checkpoint_response, Options};
    use crate::web::range::CHECKPOINT_CHUNK_SIZE;
    use crate::web::CheckpointResponse;
    use mpc_primitives::{Chain, IndexedSignRequest, SignArgs, SignBidirectionalEvent, SignId};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    fn make_response(checkpoints: HashMap<Chain, Checkpoint>) -> Vec<u8> {
        let resp = CheckpointResponse {
            version: crate::CHECKPOINT_VERSION,
            checkpoints,
        };
        let mut body = Vec::new();
        ciborium::into_writer(&resp, &mut body).unwrap();
        body
    }

    fn fat_entry(tx_size: usize, id_byte: u8) -> BacklogEntry {
        let args = SignArgs {
            entropy: [1u8; 32],
            epsilon: k256::Scalar::ONE,
            payload: k256::Scalar::ONE,
            path: "test".into(),
            key_version: 0,
        };
        let event = SignBidirectionalEvent {
            sender: [0; 32],
            serialized_transaction: vec![0u8; tx_size],
            caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
            key_version: 0,
            deposit: 0,
            path: "".to_string(),
            algo: "".to_string(),
            dest: "".to_string(),
            params: "".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            chain: Chain::Ethereum,
            chain_ctx: None,
        };
        let sign_id = SignId::new([id_byte; 32]);
        let req = Arc::new(IndexedSignRequest::sign_bidirectional(
            sign_id,
            args,
            Chain::Ethereum,
            0,
            event,
        ));
        BacklogEntry::new(req)
    }

    fn body_etag(body: &[u8]) -> String {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(body);
        format!("\"{}\"", hex::encode(hasher.finalize()))
    }

    #[test]
    fn test_versioned_checkpoint_responses_decode() {
        let mut checkpoints = HashMap::new();
        checkpoints.insert(Chain::Ethereum, Checkpoint::empty(Chain::Ethereum));

        let versioned = CheckpointResponse {
            version: crate::CHECKPOINT_VERSION,
            checkpoints: checkpoints.clone(),
        };
        let mut versioned_body = Vec::new();
        ciborium::into_writer(&versioned, &mut versioned_body).unwrap();
        assert_eq!(
            decode_checkpoint_response(&versioned_body).unwrap().version,
            crate::CHECKPOINT_VERSION
        );

        #[derive(serde::Serialize)]
        struct MissingVersionResponse {
            checkpoints: HashMap<Chain, Checkpoint>,
        }

        let mut missing_version_body = Vec::new();
        ciborium::into_writer(
            &MissingVersionResponse { checkpoints },
            &mut missing_version_body,
        )
        .unwrap();

        let decoded_missing = decode_checkpoint_response(&missing_version_body).unwrap();
        assert_eq!(decoded_missing.version, 0);

        let mut legacy_body = Vec::new();
        ciborium::into_writer(&HashMap::<Chain, Checkpoint>::new(), &mut legacy_body).unwrap();
        assert!(decode_checkpoint_response(&legacy_body).is_err());
    }

    #[tokio::test]
    async fn test_fetch_checkpoint_reports_newer_version() {
        let mut server = mockito::Server::new_async().await;
        let response = CheckpointResponse {
            version: crate::CHECKPOINT_VERSION + 1,
            checkpoints: HashMap::new(),
        };
        let mut body = Vec::new();
        ciborium::into_writer(&response, &mut body).unwrap();
        let mock = server
            .mock("GET", "/checkpoint")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/cbor")
            .with_body(body)
            .create_async()
            .await;

        let client = NodeClient::new(&Options::default());
        let result = tokio::time::timeout(
            Duration::from_millis(2000),
            client.fetch_checkpoint_by_digest(server.url(), Chain::Ethereum, [0u8; 32]),
        )
        .await
        .expect("newer checkpoint version should not stall");

        assert!(matches!(
            result,
            Err(RequestError::MismatchCheckpointVersion(version))
                if version == crate::CHECKPOINT_VERSION + 1
        ));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_checkpoint_200_fallback() {
        let body = make_response([(Chain::Ethereum, Checkpoint::empty(Chain::Ethereum))].into());
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/checkpoint")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/cbor")
            .with_body(body.clone())
            .create_async()
            .await;
        let client = NodeClient::new(&Options::default());
        let res = client
            .checkpoint(server.url(), &[Chain::Ethereum])
            .await
            .unwrap();
        assert_eq!(
            res.get(&Chain::Ethereum).unwrap(),
            &Checkpoint::empty(Chain::Ethereum)
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_checkpoint_multi_206_reassembly() {
        let mut checkpoints = HashMap::new();
        let entry = fat_entry(600 * 1024, 7);
        let mut cp = Checkpoint::empty(Chain::Ethereum);
        cp.pending_requests = vec![entry];
        cp.block_height = 42;
        checkpoints.insert(Chain::Ethereum, cp.clone());
        let body = make_response(checkpoints.clone());
        assert!(body.len() > CHECKPOINT_CHUNK_SIZE, "body must be fat");
        let etag = body_etag(&body);
        let total = body.len() as u64;
        let chunk0_end = CHECKPOINT_CHUNK_SIZE as u64 - 1;
        let chunk0 = body[0..CHECKPOINT_CHUNK_SIZE].to_vec();
        let chunk1 = body[CHECKPOINT_CHUNK_SIZE..].to_vec();
        let chunk1_end = total - 1;
        let mut server = mockito::Server::new_async().await;
        let m1 = server
            .mock("GET", "/checkpoint")
            .match_header("range", format!("bytes=0-{chunk0_end}").as_str())
            .match_query(mockito::Matcher::Any)
            .with_status(206)
            .with_header("content-type", "application/cbor")
            .with_header(
                "content-range",
                format!("bytes 0-{chunk0_end}/{total}").as_str(),
            )
            .with_header("etag", etag.as_str())
            .with_header("accept-ranges", "bytes")
            .with_body(chunk0)
            .create_async()
            .await;
        let m2 = server
            .mock("GET", "/checkpoint")
            .match_header(
                "range",
                format!(
                    "bytes={}-{}",
                    CHECKPOINT_CHUNK_SIZE,
                    CHECKPOINT_CHUNK_SIZE * 2 - 1
                )
                .as_str(),
            )
            .match_header("if-match", etag.as_str())
            .match_query(mockito::Matcher::Any)
            .with_status(206)
            .with_header("content-type", "application/cbor")
            .with_header(
                "content-range",
                format!("bytes {}-{chunk1_end}/{total}", CHECKPOINT_CHUNK_SIZE).as_str(),
            )
            .with_header("etag", etag.as_str())
            .with_header("accept-ranges", "bytes")
            .with_body(chunk1)
            .create_async()
            .await;
        let client = NodeClient::new(&Options::default());
        let res = client
            .checkpoint(server.url(), &[Chain::Ethereum])
            .await
            .unwrap();
        assert_eq!(res.get(&Chain::Ethereum).unwrap(), &cp);
        m1.assert_async().await;
        m2.assert_async().await;
    }

    #[tokio::test]
    async fn test_checkpoint_412_retry_success() {
        let mut checkpoints = HashMap::new();
        checkpoints.insert(Chain::Ethereum, Checkpoint::empty(Chain::Ethereum));
        let body = make_response(checkpoints.clone());
        let etag = body_etag(&body);
        let big_body = {
            let mut big = body.clone();
            big.extend(vec![0u8; CHECKPOINT_CHUNK_SIZE]);
            big
        };
        let big_total = big_body.len() as u64;
        let chunk0_end = CHECKPOINT_CHUNK_SIZE as u64 - 1;
        let chunk0 = big_body[0..CHECKPOINT_CHUNK_SIZE].to_vec();
        let mut server = mockito::Server::new_async().await;
        let m1 = server
            .mock("GET", "/checkpoint")
            .match_header("range", format!("bytes=0-{chunk0_end}").as_str())
            .match_query(mockito::Matcher::Any)
            .with_status(206)
            .with_header("content-type", "application/cbor")
            .with_header(
                "content-range",
                format!("bytes 0-{chunk0_end}/{big_total}").as_str(),
            )
            .with_header("etag", etag.as_str())
            .with_header("accept-ranges", "bytes")
            .with_body(chunk0)
            .create_async()
            .await;
        let m2 = server
            .mock("GET", "/checkpoint")
            .match_header(
                "range",
                format!(
                    "bytes={}-{}",
                    CHECKPOINT_CHUNK_SIZE,
                    CHECKPOINT_CHUNK_SIZE * 2 - 1
                )
                .as_str(),
            )
            .match_header("if-match", etag.as_str())
            .match_query(mockito::Matcher::Any)
            .with_status(412)
            .with_header("content-range", format!("bytes */{big_total}").as_str())
            .create_async()
            .await;
        let m3 = server
            .mock("GET", "/checkpoint")
            .match_header("range", format!("bytes=0-{chunk0_end}").as_str())
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/cbor")
            .with_body(body.clone())
            .create_async()
            .await;
        let client = NodeClient::new(&Options::default());
        let res = client
            .checkpoint(server.url(), &[Chain::Ethereum])
            .await
            .unwrap();
        assert_eq!(
            res.get(&Chain::Ethereum).unwrap(),
            &Checkpoint::empty(Chain::Ethereum)
        );
        m1.assert_async().await;
        m2.assert_async().await;
        m3.assert_async().await;
    }

    #[tokio::test]
    async fn test_checkpoint_fat_2mib() {
        let mut entries = Vec::new();
        for i in 0..8u8 {
            entries.push(fat_entry(250 * 1024, i));
        }
        let mut cp = Checkpoint::empty(Chain::Ethereum);
        cp.pending_requests = entries.clone();
        cp.block_height = 99;
        let mut checkpoints = HashMap::new();
        checkpoints.insert(Chain::Ethereum, cp.clone());
        let body = make_response(checkpoints.clone());
        assert!(
            body.len() > 1_800_000,
            "fat body len {} not large",
            body.len()
        );
        let etag = body_etag(&body);
        let total = body.len() as u64;
        let mut server = mockito::Server::new_async().await;
        let mut offset = 0u64;
        let mut mocks = Vec::new();
        while offset < total {
            let end = std::cmp::min(offset + CHECKPOINT_CHUNK_SIZE as u64 - 1, total - 1);
            let chunk = body[offset as usize..=end as usize].to_vec();
            let req_end = offset + CHECKPOINT_CHUNK_SIZE as u64 - 1;
            let range_hdr = format!("bytes={offset}-{req_end}");
            let cr = format!("bytes {offset}-{end}/{total}");
            let mut mock_builder = server
                .mock("GET", "/checkpoint")
                .match_header("range", range_hdr.as_str())
                .match_query(mockito::Matcher::Any)
                .with_status(206)
                .with_header("content-type", "application/cbor")
                .with_header("content-range", cr.as_str())
                .with_header("etag", etag.as_str())
                .with_header("accept-ranges", "bytes")
                .with_body(chunk);
            if offset != 0 {
                mock_builder = mock_builder.match_header("if-match", etag.as_str());
            }
            let m = mock_builder.create_async().await;
            mocks.push(m);
            offset = end + 1;
        }
        let client = NodeClient::new(&Options::default());
        let res = client
            .checkpoint(server.url(), &[Chain::Ethereum])
            .await
            .unwrap();
        assert_eq!(res.get(&Chain::Ethereum).unwrap(), &cp);
        for m in mocks {
            m.assert_async().await;
        }
    }

    #[tokio::test]
    async fn test_fetch_by_digest_206_reassembly() {
        let mut cp = Checkpoint::empty(Chain::Solana);
        cp.block_height = 7;
        cp.pending_requests = vec![fat_entry(600 * 1024, 9)];
        let mut map = HashMap::new();
        map.insert(Chain::Solana, cp.clone());
        let body = make_response(map);
        let etag = body_etag(&body);
        let total = body.len() as u64;
        let chunk0_end = CHECKPOINT_CHUNK_SIZE as u64 - 1;
        let chunk0 = body[0..CHECKPOINT_CHUNK_SIZE].to_vec();
        let chunk1 = body[CHECKPOINT_CHUNK_SIZE..].to_vec();
        let chunk1_end = total - 1;
        let mut server = mockito::Server::new_async().await;
        let m1 = server
            .mock("GET", "/checkpoint")
            .match_header("range", format!("bytes=0-{chunk0_end}").as_str())
            .match_query(mockito::Matcher::Any)
            .with_status(206)
            .with_header("content-type", "application/cbor")
            .with_header(
                "content-range",
                format!("bytes 0-{chunk0_end}/{total}").as_str(),
            )
            .with_header("etag", etag.as_str())
            .with_body(chunk0)
            .create_async()
            .await;
        let m2 = server
            .mock("GET", "/checkpoint")
            .match_header(
                "range",
                format!(
                    "bytes={}-{}",
                    CHECKPOINT_CHUNK_SIZE,
                    CHECKPOINT_CHUNK_SIZE * 2 - 1
                )
                .as_str(),
            )
            .match_header("if-match", etag.as_str())
            .match_query(mockito::Matcher::Any)
            .with_status(206)
            .with_header("content-type", "application/cbor")
            .with_header(
                "content-range",
                format!("bytes {}-{chunk1_end}/{total}", CHECKPOINT_CHUNK_SIZE).as_str(),
            )
            .with_header("etag", etag.as_str())
            .with_body(chunk1)
            .create_async()
            .await;
        let client = NodeClient::new(&Options::default());
        let res = client
            .fetch_checkpoint_by_digest(server.url(), Chain::Solana, cp.digest())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(res, cp);
        m1.assert_async().await;
        m2.assert_async().await;
    }
}
