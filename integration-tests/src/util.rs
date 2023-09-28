use std::{fs::File, io::Write};

use anyhow::{Context, Ok};
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use serde::{Deserialize, Serialize};
use workspaces::{types::SecretKey, AccountId};

pub async fn post<U, Req: Serialize, Resp>(
    uri: U,
    request: Req,
) -> anyhow::Result<(StatusCode, Resp)>
where
    Uri: TryFrom<U>,
    <Uri as TryFrom<U>>::Error: Into<hyper::http::Error>,
    for<'de> Resp: Deserialize<'de>,
{
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&request).context("failed to serialize the request body")?,
        ))
        .context("failed to build the request")?;

    let client = Client::new();
    let response = client
        .request(req)
        .await
        .context("failed to send the request")?;
    let status = response.status();

    let data = hyper::body::to_bytes(response)
        .await
        .context("failed to read the response body")?;
    let response: Resp =
        serde_json::from_slice(&data).context("failed to deserialize the response body")?;

    Ok((status, response))
}

#[derive(Deserialize, Serialize)]
struct KeyFile {
    account_id: String,
    public_key: String,
    private_key: String,
}

pub fn create_key_file(
    account_id: &AccountId,
    account_sk: &SecretKey,
    key_path: &str,
) -> anyhow::Result<(), anyhow::Error> {
    let key_file = KeyFile {
        account_id: account_id.to_string(),
        public_key: account_sk.public_key().to_string(),
        private_key: account_sk.to_string(),
    };
    let key_json_str = serde_json::to_string(&key_file).expect("Failed to serialize to JSON");
    let key_json_file_path = format!("{key_path}/{account_id}.json");
    let mut json_key_file =
        File::create(&key_json_file_path).expect("Failed to create JSON key file");
    json_key_file
        .write_all(key_json_str.as_bytes())
        .expect("Failed to write to JSON key file");
    Ok(())
}
