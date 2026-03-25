use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};

use crate::common::{get_json, request, test_app, verify_jwt_with_jwks};

#[tokio::test]
async fn completes_authorization_code_flow() {
    let app = test_app("config-basic");

    let authorize = request(
        app.clone(),
        Request::get("/authorize?response_type=code&client_id=svc-a&redirect_uri=https://app.example.local/callback&scope=default&state=abc")
            .body(Body::empty())
            .expect("request should build"),
    )
    .await;
    assert_eq!(authorize.status(), StatusCode::OK);

    let login = request(
        app.clone(),
        Request::post("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("username=alice&password=password123&return_to=%2Fauthorize%3Fresponse_type%3Dcode%26client_id%3Dsvc-a%26redirect_uri%3Dhttps://app.example.local/callback%26scope%3Ddefault%26state%3Dabc"))
            .expect("request should build"),
    )
    .await;
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let session_cookie = login
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("session cookie should be present")
        .split(';')
        .next()
        .expect("cookie should contain key value")
        .to_string();

    let authorize_with_session = request(
        app.clone(),
        Request::get("/authorize?response_type=code&client_id=svc-a&redirect_uri=https://app.example.local/callback&scope=default&state=abc")
            .header(header::COOKIE, session_cookie.clone())
            .body(Body::empty())
            .expect("request should build"),
    )
    .await;
    assert_eq!(authorize_with_session.status(), StatusCode::OK);

    let consent = request(
        app.clone(),
        Request::post("/consent")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, session_cookie)
            .body(Body::from("decision=approve&return_to=%2Fauthorize%3Fresponse_type%3Dcode%26client_id%3Dsvc-a%26redirect_uri%3Dhttps://app.example.local/callback%26scope%3Ddefault%26state%3Dabc"))
            .expect("request should build"),
    )
    .await;
    assert_eq!(consent.status(), StatusCode::SEE_OTHER);

    let location = consent
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("location should be present");
    let code = location
        .split("code=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("code should be present");

    let token_response = request(
        app.clone(),
        Request::post("/oauth/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "grant_type=authorization_code&client_id=svc-a&client_secret=supersecret&redirect_uri=https://app.example.local/callback&code={code}"
            )))
            .expect("request should build"),
    )
    .await;

    assert_eq!(token_response.status(), StatusCode::OK);
    let body = to_bytes(token_response.into_body(), usize::MAX)
        .await
        .expect("response body should read");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json should parse");

    let token = json["access_token"]
        .as_str()
        .expect("token should be present");
    let (_, jwks) = get_json(app, "/jwks.json").await;
    let claims = verify_jwt_with_jwks(token, &jwks);
    assert_eq!(claims["sub"], "user-alice");
}
