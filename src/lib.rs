//! Actix 4 JWT Auth is a OIDC based authentication mechanism.
//!
//! # Examples
//! ```no_run
//! use actix_4_jwt_auth::{AuthenticatedUser, OIDCValidator, OIDCValidatorConfig};
//! use actix_web::{get, http::header, test, web, App, Error, HttpResponse, HttpServer};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
//! pub struct FoundClaims {
//!     pub iss: String,
//!     pub sub: String,
//!     pub aud: String,
//!     pub name: String,
//!     pub email: Option<String>,
//!     pub email_verified: Option<bool>,
//! }
//!     
//! #[get("/authenticated_user")]
//! async fn authenticated_user(user: AuthenticatedUser<FoundClaims>) -> String {
//!     format!("Welcome {}!", user.claims.name)
//! }
//!
//! #[actix_rt::main]
//! async fn main() -> std::io::Result<()> {
//!     let test_issuer = "https://a.valid.openid-connect.idp/".to_string();
//!     let created_validator = OIDCValidator::new_from_issuer(test_issuer.clone()).unwrap();
//!     let validator_config = OIDCValidatorConfig {
//!         issuer: test_issuer,
//!         validator: created_validator,
//!     };
//!     
//!     HttpServer::new(move || {
//!       App::new()
//!               .app_data(validator_config.clone())
//!               .service(authenticated_user)
//!       })
//!     .bind("0.0.0.0:8080".to_string())?
//!     .run()
//!     .await
//! }
//! ```
//!
//! Where the new_from_issuer will actually fetch the URL + ./well-known/oidc-configuration in order to find the
//! location of the published keys.
//!
//! # More documentation
//! In addition to this API documentation, several other resources are available:
//!
//! * [Source code and development guidelines](https://github.com/spectare/actix-4-jwt-auth)
#![warn(missing_docs)]
use actix_web::http::StatusCode;
use actix_web::ResponseError;
use biscuit::errors::Error as BiscuitError;
use biscuit::jwa::*;
use biscuit::jwk::JWKSet;
use biscuit::*;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use std::format;
use std::sync::Arc;
use thiserror::Error;

mod extractor;

pub use extractor::{AuthenticatedUser, OIDCValidatorConfig};

/// When a JWT token is received and validated, it may be faulty due to different reasons
#[derive(Error, Debug)]
pub enum OIDCValidationError {
    ///It was not possible to laod the keys used for validation of the signature
    #[error("Failed to load JWKS keystore from {0:?}")]
    FailedToLoadKeystore(reqwest::Error),

    ///It was not possible to retrieve the openid-configuration document and get the jwks_uri
    #[error("Failed to load JWKS keystore from {0:?}")]
    FailedToLoadDiscovery(reqwest::Error),

    ///The Bearer token passed is not valid
    #[error("Bearer authentication token invalid: {0:?}")]
    InvalidBearerAuth(BiscuitError),

    ///The Bearer token passed is not found or faulty
    #[error("Token on bearer header is not found")]
    BearerNotComplete,

    ///The validated token has been validated but is not valid for this situation.
    #[error("No token found or token is not authorized")]
    Unauthorized,
}

impl From<biscuit::errors::Error> for OIDCValidationError {
    fn from(e: biscuit::errors::Error) -> Self {
        OIDCValidationError::InvalidBearerAuth(e)
    }
}

impl ResponseError for OIDCValidationError {
    fn status_code(&self) -> StatusCode {
        match self {
            OIDCValidationError::FailedToLoadKeystore(_) => StatusCode::INTERNAL_SERVER_ERROR,
            OIDCValidationError::FailedToLoadDiscovery(_) => StatusCode::INTERNAL_SERVER_ERROR,
            OIDCValidationError::InvalidBearerAuth(_) => StatusCode::UNAUTHORIZED,
            OIDCValidationError::BearerNotComplete => StatusCode::BAD_REQUEST,
            OIDCValidationError::Unauthorized => StatusCode::UNAUTHORIZED,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct OIDCDiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

/// The OIDCValidator contains the core functionality and needs to be available in order to validate JWT
#[derive(Clone, Debug)]
pub struct OIDCValidator {
    //note that keys may expire based on Cache-Control: max-age=21446, must-revalidate header
    /// Contains the JWK Keys that belong to the issuer
    jwks: Arc<JWKSet<Empty>>,
}

impl OIDCValidator {
    /// Creates a new OIDC Validator based on the base URL of the OIDC Identity Provider (IdP)
    ///
    /// The given issuer_url will be extended with ./well-known/openid-configuration in order to
    /// fetch the configuration and use the jwks_uri property to retrieve the keys used for validation.actix_rt    
    pub fn new_from_issuer(issuer_url: String) -> Result<Self, OIDCValidationError> {
        let discovery_document = OIDCValidator::fetch_discovery(&format!(
            "{}/.well-known/openid-configuration",
            issuer_url.as_str()
        ))
        .map_err(OIDCValidationError::FailedToLoadDiscovery)?;

        OIDCValidator::new_with_keys(discovery_document.jwks_uri)
    }

    /// When you need the validator created with a specifix key URL 
    pub fn new_with_keys(key_url: String) -> Result<Self, OIDCValidationError> {
        let jwks = OIDCValidator::fetch_jwks(&key_url)
        .map_err(OIDCValidationError::FailedToLoadKeystore)?;

        Ok(OIDCValidator {
            jwks: Arc::new(jwks),
        })
    }

    /// Validates the token. This is the complete String without the Bearer part inside the header.
    /// This will return a complete validated claimset that contains all the claims found inside the token
    /// as Serde Json Value.
    pub fn validate_token<T: for<'de> serde::Deserialize<'de>>(
        &self,
        token: &str,
    ) -> Result<T, BiscuitError> {
        let token: biscuit::jws::Compact<biscuit::ClaimsSet<Value>, Empty> =
            JWT::new_encoded(token);
        let decoded_token = token.decode_with_jwks(&self.jwks, Some(SignatureAlgorithm::RS256))?;
        //Validate the token based on default settings.
        let validation_options = ValidationOptions::default();
        decoded_token.validate(validation_options).unwrap();
        let claims_set = decoded_token.payload().unwrap();
        let json_value = serde_json::to_value(claims_set).unwrap();
        let authenticated_user: T = serde_json::from_value(json_value).unwrap();
        Ok(authenticated_user)
    }

    fn fetch_discovery(uri: &str) -> Result<OIDCDiscoveryDocument, reqwest::Error> {
        let res = reqwest::blocking::get(uri)?;
        let val: OIDCDiscoveryDocument = res.json::<OIDCDiscoveryDocument>()?;
        Ok(val)
    }
    
    fn fetch_jwks(uri: &str) -> Result<JWKSet<Empty>, reqwest::Error> {
        //let fetch_uri = match self.
        let res = reqwest::blocking::get(uri)?;
        let val: JWKSet<Empty> = res.json::<JWKSet<Empty>>()?;
        Ok(val)
    }
    
}


#[cfg(test)]
mod tests {
    use super::*;
    use log::debug;
    use tokio::task;

    const TEST_ISSUER: &str = "https://accounts.google.com";

    #[actix_rt::test]
    async fn test_jwks_url() {
        let res = task::spawn_blocking(move || {
            OIDCValidator::new_from_issuer(String::from(TEST_ISSUER)).unwrap();
        })
        .await;
        assert!(res.is_ok());
        let _validator = res.expect("Cannot retrieve");
    }

    #[actix_rt::test]
    async fn test_jwks_url_fail() {
        let res = task::spawn_blocking(move || {
            let _middleware =
                OIDCValidator::new_from_issuer(String::from("https://invalid.url")).unwrap();
            debug!("{:?}", _middleware);
        })
        .await;
        assert!(res.is_err());
    }
}
