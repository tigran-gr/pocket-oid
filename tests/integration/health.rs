use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

use crate::common::test_app;

#[tokio::test]
async fn health_and_readiness_are_available() {
    let app = test_app("config-basic");

    let health_response = app
        .clone()
        .oneshot(
            Request::get("/healthz")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("health request should succeed");
    assert_eq!(health_response.status(), StatusCode::OK);

    let ready_response = app
        .oneshot(
            Request::get("/readyz")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("ready request should succeed");
    assert_eq!(ready_response.status(), StatusCode::OK);
}
