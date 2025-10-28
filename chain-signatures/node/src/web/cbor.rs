use axum::async_trait;
use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use http::{header, HeaderMap};
use serde::{de::DeserializeOwned, Serialize};

use crate::protocol::message::cbor_to_bytes;

pub struct Cbor<T>(pub T);

impl<T> Cbor<T> {
    fn valid_header(headers: &HeaderMap) -> bool {
        let Some(content_type) = headers.get(header::CONTENT_TYPE) else {
            return false;
        };
        let Ok(content_type) = content_type.to_str() else {
            return false;
        };
        let Ok(mime) = content_type.parse::<mime::Mime>() else {
            return false;
        };
        let is_cbor_content_type = mime.type_() == "application"
            && (mime.subtype() == "cbor" || mime.suffix().is_some_and(|name| name == "cbor"));
        is_cbor_content_type
    }
}

impl<T> From<T> for Cbor<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

#[async_trait]
impl<T, S> FromRequest<S> for Cbor<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = CborRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        if !Self::valid_header(req.headers()) {
            return Err(CborRejection {
                status: StatusCode::BAD_REQUEST,
                message: "expecting `content-type: application/cbor`".to_string(),
            });
        }

        let bytes = match Bytes::from_request(req, state).await {
            Ok(bytes) => bytes,
            Err(err) => {
                return Err(CborRejection {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    message: format!("failed to read request body: {err}"),
                });
            }
        };

        match ciborium::from_reader(bytes.as_ref()) {
            Ok(data) => Ok(Cbor(data)),
            Err(err) => Err(CborRejection {
                status: StatusCode::BAD_REQUEST,
                message: format!("failed to deserialize CBOR: {err}"),
            }),
        }
    }
}

impl<T> IntoResponse for Cbor<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        let bytes = match cbor_to_bytes(&self.0) {
            Ok(bytes) => bytes,
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to serialize to CBOR: {err}"),
                )
                    .into_response();
            }
        };
        (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/cbor")],
            bytes,
        )
            .into_response()
    }
}

#[derive(Debug)]
pub struct CborRejection {
    status: StatusCode,
    message: String,
}

impl CborRejection {
    pub fn status(&self) -> StatusCode {
        self.status
    }
}

impl IntoResponse for CborRejection {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

impl std::fmt::Display for CborRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CborRejection({}, {})", self.status, self.message)
    }
}

impl std::error::Error for CborRejection {}
