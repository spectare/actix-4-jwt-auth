#[cfg(test)]
use actix_4_jwt_auth::{AuthenticatedUser, OIDCValidator, OIDCValidatorConfig};
use actix_web::{get, http::header, test, App, Error};
use bytes::Bytes;
use serde_json::json;
use tokio::task;
mod common;

#[get("/authenticated_user")]
async fn authenticated_user(user: AuthenticatedUser) -> String {
  format!("Welcome {}!", user.name)
}

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
  //let my_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImMzYjA3NjNiYjc1ZTliYzU4MzY1NTJlMmY5ZDljMTI0ZmJjNzFkYzEifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU1NTYvZGV4Iiwic3ViIjoiQ2dSc1lXNWhFZ1ZzYjJOaGJBIiwiYXVkIjoidG90aGVwb2ludCIsImV4cCI6MTYzMzA5MjY0NSwiaWF0IjoxNjMzMDA2MjQ1LCJub25jZSI6IjM0Y2IzY2VhM2I3ZjRmNWFiNzQ2NjY0N2VlNzQwNmYxIiwiYXRfaGFzaCI6IjM5QzVvTkNJN1l3UFV5VHE2MkN5ekEiLCJuYW1lIjoiTGFuYSBkZWwgUmV5In0.VccekTmXT8s-iKwwuW4ikhy-CM-Pr2yFCVgVXOYDNr09srylmSjaO7njL8gC7C-RLYj74oXRG2SRbwWxxTztUFWF__IfRj0-pna8_tunm_p4srbJRPiF_fL4E_3iczdcIKTF_am6qtN9yms2Sm0qUV_RD6WkqfvqMfNUUzp98GLJ6gsDEam84rWCnv_vY6YKXVcnpqB8Hwlr8hT7ZMtYGdrc5pb_rHyvFavSIpeLfqgPTKnboTgMsSu8dS13Pk3xh6rOWJkggF780VDrH58Nwjn0oqU8ay3pc1MVfMqUcnzphdqbCLjMLePWkNbEe0ZdVPxGlvY7aBvtCSye6UejfQ".to_string();
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
