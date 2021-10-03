use actix_web::http::StatusCode;
use actix_web::ResponseError;
use alcoholic_jwt::{token_kid, validate, ValidJWT, Validation, ValidationError, JWKS};
use reqwest;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

mod extractor;
mod middleware;

#[derive(Error, Debug)]
pub enum OIDCValidationError {
    #[error("Failed to load JWKS keystore from {0:?}")]
    FailedToLoadKeystore(reqwest::Error),

    #[error("Failed to load JWKS keystore from {0:?}")]
    FailedToLoadDiscovery(reqwest::Error),

    #[error("Bearer authentication token invalid: {0:?}")]
    InvalidBearerAuth(ValidationError),

    #[error("Token on bearer header is not found")]
    BearerNotComplete,

    #[error("No token found or token is not authorized")]
    Unauthorized,
}

impl From<alcoholic_jwt::ValidationError> for OIDCValidationError {
    fn from(e: alcoholic_jwt::ValidationError) -> Self {
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
    jwks: JWKS,
    discovery_document: OIDCDiscoveryDocument,
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
            jwks,
            discovery_document: discovery_document.clone(),
        })
    }

    pub fn validate_token(&self, token: &str) -> Result<ValidJWT, ValidationError> {
        let validations = vec![
            Validation::Issuer(self.discovery_document.issuer.clone()),
            Validation::SubjectPresent,
        ];
        let kid = match token_kid(&token) {
            Ok(res) => res.expect("failed to decode kid"),
            Err(_) => return Err(ValidationError::InvalidJWK),
        };
        let jwk = self
            .jwks
            .find(&kid)
            .expect("Specified key not found in set");
        validate(token, jwk, validations)
    }
}

fn fetch_discovery(uri: &str) -> Result<OIDCDiscoveryDocument, reqwest::Error> {
    let res = reqwest::blocking::get(uri)?;
    let val: OIDCDiscoveryDocument = res.json::<OIDCDiscoveryDocument>()?;
    return Ok(val);
}

fn fetch_jwks(uri: &str) -> Result<JWKS, reqwest::Error> {
    let res = reqwest::blocking::get(uri)?;
    let val: JWKS = res.json::<JWKS>()?;
    return Ok(val);
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::debug;
    use tokio::task;

    const TEST_ISSUER: &str = "http://localhost:5556/dex";

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
