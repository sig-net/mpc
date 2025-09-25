use axum::extract::rejection::JsonRejection;
use http::StatusCode;

use crate::protocol::message::MessageError;
use crate::protocol::CryptographicError;
use crate::web::cbor::CborRejection;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// This enum error type serves as one true source of all futures in sign-node
/// crate. It is used to unify all errors that can happen in the application.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    JsonExtractorRejection(#[from] JsonRejection),
    #[error(transparent)]
    CborExtractorRejection(#[from] CborRejection),
    #[error(transparent)]
    Cryptography(#[from] CryptographicError),
    #[error(transparent)]
    Message(#[from] MessageError),
    #[error(transparent)]
    Rpc(#[from] near_fetch::Error),
}

impl Error {
    pub fn status(&self) -> StatusCode {
        match self {
            Error::JsonExtractorRejection(rejection) => rejection.status(),
            Error::CborExtractorRejection(rejection) => rejection.status(),
            Error::Cryptography(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Message(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Rpc(_) => StatusCode::BAD_REQUEST,
        }
    }
}

impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let status = self.status();
        let message = match self {
            Error::JsonExtractorRejection(json_rejection) => json_rejection.body_text(),
            err => format!("{err:?}"),
        };

        (status, axum::Json(message)).into_response()
    }
}
