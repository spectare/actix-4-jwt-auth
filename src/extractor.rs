use super::OIDCValidationError;
use super::OIDCValidator;
use actix_web::{dev, Error, FromRequest, HttpRequest};
use futures_util::future::{ok, ready, Ready};
use log::error;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct OIDCValidatorConfig {
    pub issuer: String,
    pub validator: OIDCValidator,
}

impl Default for OIDCValidatorConfig {
    fn default() -> Self {
        let oidc_issuer = std::env::var("OIDC_ISSUER")
            .map_err(|_e| {
                error!("PLEASE set the OIDC_ISSUER ENV var like: http://localhost:5556/dex")
            })
            .unwrap();
        let created_validator = OIDCValidator::new_from_issuer(oidc_issuer.clone()).unwrap();
        OIDCValidatorConfig {
            issuer: oidc_issuer.clone(),
            validator: created_validator,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub name: String,
}

impl FromRequest for AuthenticatedUser {
    type Config = OIDCValidatorConfig;
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
        let cfg = req
            .app_data::<OIDCValidatorConfig>()
            .expect("Please configure the OIDCValidatorConfig on your App");
        println!("config data?: {:?}", cfg.issuer);

        let authorization = req.headers().get(actix_web::http::header::AUTHORIZATION);

        let jwt = {
            match authorization {
                Some(value) => {
                    let value_str = value.to_str().unwrap().to_string();
                    match value_str.strip_prefix("Bearer ") {
                        Some(token) => match cfg.validator.validate_token(&token) {
                            Ok(jwt) => Some(jwt),
                            Err(e) => {
                                return ready(Err(OIDCValidationError::InvalidBearerAuth(e).into()))
                            }
                        },
                        _ => return ready(Err(OIDCValidationError::BearerNotComplete.into())),
                    }
                }
                None => None,
            }
        };
        match jwt {
            Some(valid_user) => ok(valid_user),
            None => ready(Err(OIDCValidationError::Unauthorized.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{get, http::header, test, App, Error};
    use bytes::Bytes;
    use tokio::task;

    #[get("/authenticated_user")]
    async fn authenticated_user(user: AuthenticatedUser) -> String {
        format!("Welcome {}!", user.name)
    }

    // #[actix_rt::test]
    async fn test_jwt_auth_ok() -> Result<(), Error> {
        let test_issuer = "file://tests".to_string();
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
        let my_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImMzYjA3NjNiYjc1ZTliYzU4MzY1NTJlMmY5ZDljMTI0ZmJjNzFkYzEifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU1NTYvZGV4Iiwic3ViIjoiQ2dSc1lXNWhFZ1ZzYjJOaGJBIiwiYXVkIjoidG90aGVwb2ludCIsImV4cCI6MTYzMzA5MjY0NSwiaWF0IjoxNjMzMDA2MjQ1LCJub25jZSI6IjM0Y2IzY2VhM2I3ZjRmNWFiNzQ2NjY0N2VlNzQwNmYxIiwiYXRfaGFzaCI6IjM5QzVvTkNJN1l3UFV5VHE2MkN5ekEiLCJuYW1lIjoiTGFuYSBkZWwgUmV5In0.VccekTmXT8s-iKwwuW4ikhy-CM-Pr2yFCVgVXOYDNr09srylmSjaO7njL8gC7C-RLYj74oXRG2SRbwWxxTztUFWF__IfRj0-pna8_tunm_p4srbJRPiF_fL4E_3iczdcIKTF_am6qtN9yms2Sm0qUV_RD6WkqfvqMfNUUzp98GLJ6gsDEam84rWCnv_vY6YKXVcnpqB8Hwlr8hT7ZMtYGdrc5pb_rHyvFavSIpeLfqgPTKnboTgMsSu8dS13Pk3xh6rOWJkggF780VDrH58Nwjn0oqU8ay3pc1MVfMqUcnzphdqbCLjMLePWkNbEe0ZdVPxGlvY7aBvtCSye6UejfQ".to_string();

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

        assert_eq!(resp, Bytes::from_static(b"Welcome Lana del Rey!"));
        Ok(())
    }
}
