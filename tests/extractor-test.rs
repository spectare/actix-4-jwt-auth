#[cfg(test)]
use actix_4_jwt_auth::{AuthenticatedUser, OIDCValidator, OIDCValidatorConfig};
use actix_web::{get, http::header, test, App, Error};
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
  pub aud: String,
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
  let test_issuer = "http://0.0.0.0:9090".to_string();
  let test_issuer_copy = test_issuer.clone();

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

  let claims = json!({
    "iss": "http://0.0.0.0:9090",
    "sub": "CgVhZG1pbhIFbG9jYWw",
    "aud": "cafienne-ui",
    "email": "admin@example.com",
    "email_verified": true,
    "name": "admin"
  });
  let my_token = common::create_token(&test_issuer_copy, claims)
    .await
    .expect("Valid token string from test-token-service");
  println!("{}", my_token);
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
  let resp: Bytes = test::read_response(&app, req).await;

  assert_eq!(resp, Bytes::from_static(b"Welcome admin!"));
  Ok(())
}
