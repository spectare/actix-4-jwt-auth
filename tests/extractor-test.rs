#[cfg(test)]
use actix_4_jwt_auth::{AuthenticatedUser, OIDCValidator, OIDCValidatorConfig};
use actix_web::dev::Service;
use actix_web::{get, http, http::header, test, App, Error};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::task;
mod common;

// Create a struct that will deserialize your claims.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct FoundClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub name: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
}

#[get("/authenticated_user")]
async fn authenticated_user(user: AuthenticatedUser<FoundClaims>) -> String {
    format!("Welcome {}!", user.claims.name)
}

///Test of the Extractor using
#[actix_rt::test]
async fn test_jwt_auth_ok() -> Result<(), Error> {
    let test_issuer = "http://localhost:8080".to_string();

    //Check if spectare/oidc-token-test-service:latest is running on given test_issuer endpoint.
    assert_eq!(common::check_test_idp(test_issuer.clone()).await, Ok(true));

    let validator_config = task::spawn_blocking(move || {
        let created_validator = OIDCValidator::new_from_issuer(test_issuer.clone()).unwrap();
        OIDCValidatorConfig {
            issuer: test_issuer,
            validator: created_validator,
        }
    })
    .await
    .expect("Expected a valid validator config");

    let app = test::init_service(
        App::new()
            .app_data(validator_config.clone())
            .service(authenticated_user),
    )
    .await;
    let test_issuer = "http://localhost:8080".to_string();

    let claims = json!({
      "iss": "http://0.0.0.0:9090",
      "sub": "CgVhZG1pbhIFbG9jYWw",
      "aud": ["cafienne-ui"],
      "email": "admin@example.com",
      "email_verified": true,
      "name": "admin"
    });
    let my_token = common::create_token(&test_issuer, claims)
        .await
        .expect("Valid token string from test-token-service");

    let req = test::TestRequest::get()
        .uri("/authenticated_user")
        .insert_header(header::ContentType::json())
        .insert_header((
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", my_token)).unwrap(),
        ))
        .to_request();
    //let resp = app.call(req).await.unwrap();
    //assert_eq!(resp.status(), http::StatusCode::OK);
    let resp: Bytes = test::call_and_read_body(&app, req).await;

    assert_eq!(resp, Bytes::from_static(b"Welcome admin!"));
    Ok(())
}

// Create a struct that will deserialize your claims.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct DateValidityClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: u64,
}

#[get("/date_validated_user")]
async fn date_validated_user(user: AuthenticatedUser<DateValidityClaims>) -> String {
    format!("Valid {}", user.claims.exp)
}

#[actix_rt::test]
#[should_panic]
async fn test_jwt_auth_expired() -> () {
    let test_issuer = "http://localhost:8080".to_string();

    //Check if spectare/oidc-token-test-service:latest is running on given test_issuer endpoint.
    assert_eq!(common::check_test_idp(test_issuer.clone()).await, Ok(true));

    let validator_config = task::spawn_blocking(move || {
        let created_validator = OIDCValidator::new_from_issuer(test_issuer.clone()).unwrap();
        OIDCValidatorConfig {
            issuer: test_issuer,
            validator: created_validator,
        }
    })
    .await
    .expect("Expected a valid validator config");

    let app = test::init_service(
        App::new()
            .app_data(validator_config.clone())
            .service(date_validated_user),
    )
    .await;
    let test_issuer = "http://localhost:8080".to_string();

    let claims = json!({
      "iss": "http://0.0.0.0:9090",
      "sub": "CgVhZG1pbhIFbG9jYWw",
      "aud": ["cafienne-ui"],
      "exp": 1602324610, //Saturday 10 October 2020 10:10:10 (e.g Expired)
    });
    let my_token = common::create_token(&test_issuer, claims)
        .await
        .expect("Valid token string from test-token-service");

    let req = test::TestRequest::get()
        .uri("/date_validated_user")
        .insert_header(header::ContentType::json())
        .insert_header((
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", my_token)).unwrap(),
        ))
        .to_request();
    let resp = app.call(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    ()
}

#[actix_rt::test]
#[should_panic]
async fn test_jwt_auth_invisible_not_before() -> () {
    let test_issuer = "http://localhost:8080".to_string();

    //Check if spectare/oidc-token-test-service:latest is running on given test_issuer endpoint.
    assert_eq!(common::check_test_idp(test_issuer.clone()).await, Ok(true));

    let validator_config = task::spawn_blocking(move || {
        let created_validator = OIDCValidator::new_from_issuer(test_issuer.clone()).unwrap();
        OIDCValidatorConfig {
            issuer: test_issuer,
            validator: created_validator,
        }
    })
    .await
    .expect("Expected a valid validator config");

    let app = test::init_service(
        App::new()
            .app_data(validator_config.clone())
            .service(date_validated_user),
    )
    .await;
    let test_issuer = "http://localhost:8080".to_string();

    //NOTE that the nbf (Not Before) claim is not valid at this time
    //But is is not explicitly part of the DateValidityClaims and should be validated anyway.
    let claims = json!({
      "iss": "http://0.0.0.0:9090",
      "sub": "CgVhZG1pbhIFbG9jYWw",
      "aud": ["cafienne-ui"],
      "exp": 2147483647, //19 January 2038 03:14:07 -> Max of the i32 expected by the json! macro
      "nbf": 2075623810, // 10 October 2035 10:10:10
    });
    let my_token = common::create_token(&test_issuer, claims)
        .await
        .expect("Valid token string from test-token-service");

    let req = test::TestRequest::get()
        .uri("/date_validated_user")
        .insert_header(header::ContentType::json())
        .insert_header((
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", my_token)).unwrap(),
        ))
        .to_request();
    let resp = app.call(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    ()
}
