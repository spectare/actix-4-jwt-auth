use actix_web::http::StatusCode;
use actix_web::ResponseError;
use biscuit::errors::Error as BiscuitError;
use biscuit::jwa::*;
use biscuit::jwk::JWKSet;
use biscuit::jws::*;
use biscuit::*;
use reqwest;
use serde::{Deserialize, Serialize};
use std::format;
use thiserror::Error;

mod extractor;
mod middleware;

pub use extractor::{AuthenticatedUser, OIDCValidatorConfig};

#[derive(Error, Debug)]
pub enum OIDCValidationError {
    #[error("Failed to load JWKS keystore from {0:?}")]
    FailedToLoadKeystore(reqwest::Error),

    #[error("Failed to load JWKS keystore from {0:?}")]
    FailedToLoadDiscovery(reqwest::Error),

    #[error("Bearer authentication token invalid: {0:?}")]
    InvalidBearerAuth(BiscuitError),

    #[error("Token on bearer header is not found")]
    BearerNotComplete,

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

#[derive(Clone, Debug)]
pub struct OIDCValidator {
    //note that keys may expire based on Cache-Control: max-age=21446, must-revalidate header
    jwks: JWKSet<Empty>,
    issuer: String,
}

impl OIDCValidator {
    pub fn new_from_issuer(issuer_url: String) -> Result<Self, OIDCValidationError> {
        let discovery_document = fetch_discovery(&format!(
            "{}/.well-known/openid-configuration",
            issuer_url.as_str()
        ))
        .map_err(|e| OIDCValidationError::FailedToLoadDiscovery(e))?;
        let jwks = fetch_jwks(&discovery_document.jwks_uri)
            .map_err(|e| OIDCValidationError::FailedToLoadKeystore(e))?;

        Ok(OIDCValidator {
            jwks: jwks,
            issuer: issuer_url.clone(),
        })
    }

    pub fn validate_token(&self, token: &str) -> Result<AuthenticatedUser, BiscuitError> {
        let token: biscuit::jws::Compact<biscuit::ClaimsSet<AuthenticatedUser>, RegisteredClaims> =
            JWT::new_encoded(&token);
        let decoded_token = token.decode_with_jwks(&self.jwks, Some(SignatureAlgorithm::RS256))?;
        let claims = decoded_token.payload().unwrap();
        let json_value = serde_json::to_value(claims).unwrap();
        let authenticated_user: AuthenticatedUser = serde_json::from_value(json_value).unwrap();
        Ok(authenticated_user)
    }
}

fn fetch_discovery(uri: &str) -> Result<OIDCDiscoveryDocument, reqwest::Error> {
    let res = reqwest::blocking::get(uri)?;
    let val: OIDCDiscoveryDocument = res.json::<OIDCDiscoveryDocument>()?;
    return Ok(val);
}

fn fetch_jwks(uri: &str) -> Result<JWKSet<Empty>, reqwest::Error> {
    let res = reqwest::blocking::get(uri)?;
    let val: JWKSet<Empty> = res.json::<JWKSet<Empty>>()?;
    return Ok(val);
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
        let validator = res.expect("Cannot retrieve");
        //assert_eq!(validator.discovery_document.jwks_uri, TEST_KEYSET)
        //assert!(key_url == "bla");
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
