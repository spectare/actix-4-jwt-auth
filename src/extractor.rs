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
                error!("PLEASE set the OIDC_ISSUER ENV var like: https://accounts.google.com")
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
pub struct AuthenticatedUser<T> {
    pub jwt: String,
    pub claims: T,
}

impl<T: for<'de> Deserialize<'de>> FromRequest for AuthenticatedUser<T> {
    type Config = OIDCValidatorConfig;
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut dev::Payload) -> Self::Future {
        let cfg = req
            .app_data::<OIDCValidatorConfig>()
            .expect("Please configure the OIDCValidatorConfig on your App");

        let authorization = req.headers().get(actix_web::http::header::AUTHORIZATION);

        match authorization {
            Some(value) => {
                let value_str = value.to_str().unwrap().to_string();
                match value_str.strip_prefix("Bearer ") {
                    Some(token) => match cfg.validator.validate_token(&token) {
                        Ok(valid_claims) => ok(AuthenticatedUser {
                            jwt: token.to_string(),
                            claims: valid_claims,
                        }),
                        Err(e) => ready(Err(OIDCValidationError::InvalidBearerAuth(e).into())),
                    },
                    _ => ready(Err(OIDCValidationError::BearerNotComplete.into())),
                }
            }
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
        format!("Welcome {:?}!", user.claims.name)
    }
}
