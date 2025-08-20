use axum::async_trait;
use axum::body::{Bytes, HttpBody};
use axum::extract::FromRequest;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{de::DeserializeOwned, Serialize};

use crate::protocol::message::cbor_to_bytes;

pub struct Cbor<T>(pub T);

// #[async_trait]
// impl<T, B> FromRequest<B> for Cbor<T>
// where
//     T: DeserializeOwned + Send,
//     B: axum::body::HttpBody + Send,
//     B::Data: Send,
//     B::Error: std::error::Error + Send + Sync,
// {
//     type Rejection = (StatusCode, String);

//     async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
//         let bytes = match axum::body::to_bytes(req.body_mut()).await {
//             Ok(bytes) => bytes,
//             Err(e) => {
//                 return Err((
//                     StatusCode::INTERNAL_SERVER_ERROR,
//                     format!("Failed to read request body: {}", e),
//                 ));
//             }
//         };

//         let data = match ciborium::from_reader(bytes.as_ref()) {
//             Ok(data) => data,
//             Err(e) => {
//                 return Err((
//                     StatusCode::BAD_REQUEST,
//                     format!("Failed to deserialize CBOR: {}", e),
//                 ));
//             }
//         };

//         Ok(Cbor(data))
//     }
// }

#[async_trait]
impl<S, B> FromRequest<S, B> for Cbor<S>
where
    S: DeserializeOwned + Send + Sync,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = match Bytes::from_request(req, state).await {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to read request body: {e}"),
                ));
            }
        };

        let data = match ciborium::from_reader(bytes.as_ref()) {
            Ok(data) => data,
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("failed to deserialize cbor: {e}"),
                ));
            }
        };

        Ok(Cbor(data))
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
                    format!("failed to serialize to cbor: {err}"),
                )
                    .into_response();
            }
        };
        (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/cbor")],
            Bytes::from(bytes),
        )
            .into_response()
    }
}

// #[async_trait]
// impl<T, S, B> FromRequest<S, B> for Json<T>
// where
//     T: DeserializeOwned,
//     B: HttpBody + Send + 'static,
//     B::Data: Send,
//     B::Error: Into<BoxError>,
//     S: Send + Sync,
// {
//     type Rejection = JsonRejection;

//     async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
//         if json_content_type(req.headers()) {
//             let bytes = Bytes::from_request(req, state).await?;
//             let deserializer = &mut serde_json::Deserializer::from_slice(&bytes);

//             let value = match serde_path_to_error::deserialize(deserializer) {
//                 Ok(value) => value,
//                 Err(err) => {
//                     let rejection = match err.inner().classify() {
//                         serde_json::error::Category::Data => JsonDataError::from_err(err).into(),
//                         serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
//                             JsonSyntaxError::from_err(err).into()
//                         }
//                         serde_json::error::Category::Io => {
//                             if cfg!(debug_assertions) {
//                                 // we don't use `serde_json::from_reader` and instead always buffer
//                                 // bodies first, so we shouldn't encounter any IO errors
//                                 unreachable!()
//                             } else {
//                                 JsonSyntaxError::from_err(err).into()
//                             }
//                         }
//                     };
//                     return Err(rejection);
//                 }
//             };

//             Ok(Json(value))
//         } else {
//             Err(MissingJsonContentType.into())
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Router};
    // use axum::test_helpers::TestClient;
    // use crate::{routing::post, test_helpers::*, Router};
    use serde::Deserialize;
    // use serde_json::{json, Value};

    // #[tokio::test]
    // async fn deserialize_body() {
    //     #[derive(Clone, Debug, Deserialize)]
    //     struct Input {
    //         foo: String,
    //     }

    //     let app = Router::new().route("/", post(|input: Cbor<Input>| async { input.0.foo }));

    //     let client = TestClient::new(app);
    //     // let res = client.post("/").json(&json!({ "foo": "bar" })).send().await;
    //     // let body = res.text().await;

    //     // assert_eq!(body, "bar");
    // }

    // #[crate::test]
    // async fn consume_body_to_json_requires_json_content_type() {
    //     #[derive(Debug, Deserialize)]
    //     struct Input {
    //         foo: String,
    //     }

    //     let app = Router::new().route("/", post(|input: Json<Input>| async { input.0.foo }));

    //     let client = TestClient::new(app);
    //     let res = client.post("/").body(r#"{ "foo": "bar" }"#).send().await;

    //     let status = res.status();

    //     assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // }

    // #[crate::test]
    // async fn json_content_types() {
    //     async fn valid_json_content_type(content_type: &str) -> bool {
    //         println!("testing {content_type:?}");

    //         let app = Router::new().route("/", post(|Json(_): Json<Value>| async {}));

    //         let res = TestClient::new(app)
    //             .post("/")
    //             .header("content-type", content_type)
    //             .body("{}")
    //             .send()
    //             .await;

    //         res.status() == StatusCode::OK
    //     }

    //     assert!(valid_json_content_type("application/json").await);
    //     assert!(valid_json_content_type("application/json; charset=utf-8").await);
    //     assert!(valid_json_content_type("application/json;charset=utf-8").await);
    //     assert!(valid_json_content_type("application/cloudevents+json").await);
    //     assert!(!valid_json_content_type("text/json").await);
    // }

    // #[crate::test]
    // async fn invalid_json_syntax() {
    //     let app = Router::new().route("/", post(|_: Json<serde_json::Value>| async {}));

    //     let client = TestClient::new(app);
    //     let res = client
    //         .post("/")
    //         .body("{")
    //         .header("content-type", "application/json")
    //         .send()
    //         .await;

    //     assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // }

    // #[derive(Deserialize)]
    // struct Foo {
    //     #[allow(dead_code)]
    //     a: i32,
    //     #[allow(dead_code)]
    //     b: Vec<Bar>,
    // }

    // #[derive(Deserialize)]
    // struct Bar {
    //     #[allow(dead_code)]
    //     x: i32,
    //     #[allow(dead_code)]
    //     y: i32,
    // }

    // #[crate::test]
    // async fn invalid_json_data() {
    //     let app = Router::new().route("/", post(|_: Json<Foo>| async {}));

    //     let client = TestClient::new(app);
    //     let res = client
    //         .post("/")
    //         .body("{\"a\": 1, \"b\": [{\"x\": 2}]}")
    //         .header("content-type", "application/json")
    //         .send()
    //         .await;

    //     assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    //     let body_text = res.text().await;
    //     assert_eq!(
    //         body_text,
    //         "Failed to deserialize the JSON body into the target type: b[0]: missing field `y` at line 1 column 23"
    //     );
    // }
}
