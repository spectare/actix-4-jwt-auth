/*!
Actix 4 JWT Auth is a OIDC based authentication mechanism.

# Examples
```no_run
use actix_4_jwt_auth::{
    AuthenticatedUser, Oidc, OidcConfig, OidcBiscuitValidator, 
    biscuit::{ValidationOptions, Validation}
};
use actix_web::{get, http::header, test, web, App, Error, HttpResponse, HttpServer};
use serde::{Deserialize, Serialize};

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

#[actix_rt::main]
async fn main() -> std::io::Result<()> {

    let authority = "https://a.valid.openid-connect.idp/".to_string();

    let oidc = Oidc::new(OidcConfig::Issuer(authority.clone().into())).await.unwrap();

    let biscuit_validator = OidcBiscuitValidator { options: ValidationOptions {
            issuer: Validation::Validate(authority),
            ..ValidationOptions::default()
        }
    };

    HttpServer::new(move || {
      App::new()
              .app_data(oidc.clone())
              .wrap(biscuit_validator.clone())
              .service(authenticated_user)
      })
    .bind("0.0.0.0:8080".to_string())?
    .run()
    .await
}
```

Where the new_from_issuer will actually fetch the URL + ./well-known/oidc-configuration in order to find the
location of the published keys.

# More documentation
In addition to this API documentation, several other resources are available:

* [Source code and development guidelines](https://github.com/spectare/actix-4-jwt-auth)
*/
#![warn(missing_docs)]

use actix_web::http::StatusCode;
use actix_web::ResponseError;
use awc::error::{JsonPayloadError, SendRequestError};
use biscuit::errors::Error as BiscuitError;
use biscuit::jwa::*;
use biscuit::jwk::JWKSet;
use biscuit::*;
use futures_util::TryFutureExt;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use std::{borrow::Cow, format, sync::Arc};
use thiserror::Error;

mod extractor;
mod middleware;

#[doc(inline)]
pub use ::biscuit;

pub use extractor::{UserClaims, AuthenticatedUser};
pub use middleware::OidcBiscuitValidator;

/// When a JWT token is received and validated, it may be faulty due to different reasons
#[derive(Error, Debug)]
pub enum OIDCValidationError {
    ///The Bearer token passed is not valid
    #[error("Bearer authentication token invalid: {0:?}")]
    InvalidBearerAuth(awc::error::HttpError),

    ///The token validation fails due to cryptographic issues
    #[error("Crypto handling error: {0:?}")]
    CryptoError(biscuit::errors::Error),

    ///The Bearer token passed is not found or faulty
    #[error("Token on bearer header is not found")]
    BearerNotComplete,

    ///The validated token has been validated but is not valid for this situation.
    #[error("No token found or token is not authorized")]
    Unauthorized,

    ///It was not possible to laod the keys used for validation of the signature
    #[error("Failed to process JWKS json from {0:?}")]
    FailedToParseJsonResponse(awc::error::JsonPayloadError),

    ///It was not possible to fetch the JWKS uri
    #[error("Failed to fetch JWKS keystore from {0:?}")]
    FailedToLoadKeystore(awc::error::HttpError),

    ///It was not possible to retrieve the openid-configuration document and get the jwks_uri
    #[error("Failed to load JWKS keystore from {0:?}")]
    FailedToLoadDiscovery(awc::error::HttpError),

    ///Failed to fetch data from given URI
    #[error("Cannot fetch {0:?}")]
    ConnectivityError(SendRequestError),

    ///Token does not have sufficient rights
    #[error("Token does not have sufficient rights")]
    IvalidAccess,
}

impl From<awc::error::HttpError> for OIDCValidationError {
    fn from(e: awc::error::HttpError) -> Self {
        OIDCValidationError::InvalidBearerAuth(e)
    }
}

impl From<awc::error::JsonPayloadError> for OIDCValidationError {
    fn from(e: JsonPayloadError) -> Self {
        OIDCValidationError::FailedToParseJsonResponse(e)
    }
}

impl From<SendRequestError> for OIDCValidationError {
    fn from(e: SendRequestError) -> Self {
        OIDCValidationError::ConnectivityError(e)
    }
}

impl From<biscuit::errors::Error> for OIDCValidationError {
    fn from(e: BiscuitError) -> Self {
        OIDCValidationError::CryptoError(e)
    }
}

impl ResponseError for OIDCValidationError {
    fn status_code(&self) -> StatusCode {
        match self {
            OIDCValidationError::InvalidBearerAuth(_) => StatusCode::UNAUTHORIZED,
            OIDCValidationError::BearerNotComplete => StatusCode::BAD_REQUEST,
            OIDCValidationError::FailedToLoadKeystore(_) => StatusCode::INTERNAL_SERVER_ERROR,
            OIDCValidationError::FailedToLoadDiscovery(_) => StatusCode::INTERNAL_SERVER_ERROR,
            OIDCValidationError::Unauthorized => StatusCode::UNAUTHORIZED,
            OIDCValidationError::FailedToParseJsonResponse(_) => StatusCode::INTERNAL_SERVER_ERROR,
            OIDCValidationError::ConnectivityError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            OIDCValidationError::CryptoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            OIDCValidationError::IvalidAccess => StatusCode::FORBIDDEN,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct OIDCDiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}


trait TraitDecoder {
    fn decode(
        &self,
        jwks: &JWKSet<Empty>,
        token: &str,
    ) -> Result<jws::Compact<ClaimsSet<Value>, Empty>, OIDCValidationError>;
}

#[derive(Clone)]
struct OidcDecoder;


impl TraitDecoder for OidcDecoder {
    fn decode(
        &self,
        jwks: &JWKSet<Empty>,
        token: &str,
    ) -> Result<jws::Compact<ClaimsSet<Value>, Empty>, OIDCValidationError> {
        let token: biscuit::jws::Compact<biscuit::ClaimsSet<Value>, Empty> =
            JWT::new_encoded(token);
        let decoded_token = token.decode_with_jwks(jwks, Some(SignatureAlgorithm::RS256))?;
        Ok(decoded_token)
    }
}



/// The Oidc contains the core functionality and needs to be available in order to validate JWT
#[derive(Clone)]
pub struct Oidc {
    //note that keys may expire based on Cache-Control: max-age=21446, must-revalidate header
    /// Contains the JWK Keys that belong to the issuer
    jwks: Arc<JWKSet<Empty>>,

    /// Gets the claims from the access token
    /// This will return a complete decoded token that contains all the claims found inside the token
    token_decoder: Arc<dyn TraitDecoder + Send + Sync + 'static>
}

///Oidc configuration
pub enum OidcConfig{
    ///issuer
    Issuer(Cow<'static, str>),
    ///key url
    KeyUrl(Cow<'static, str>),
    ///jwks
    Jwks(JWKSet<Empty>)
}


impl Oidc {

    /// Creates a new Oidc
    pub async fn new(
        config: OidcConfig
    ) -> Result<Self, OIDCValidationError> {
        Oidc::new_with_decoder(config, OidcDecoder).await
    }
    

    /// Creates a new Oidc with decoder
    async fn new_with_decoder(
        config: OidcConfig,
        decoder: impl TraitDecoder + Send + Sync + 'static
    ) -> Result<Self, OIDCValidationError> {
        match config {
            OidcConfig::Issuer(issuer) => Oidc::new_from_issuer(issuer.as_ref(), decoder).await,
            OidcConfig::KeyUrl(key_url) => Oidc::new_with_keys(key_url.as_ref(), decoder).await,
            OidcConfig::Jwks(jwks) => Oidc::new_for_jwks(jwks, decoder).await,
        }
    }

    /// Creates a new Oidc based on the base URL of the Oidc Identity Provider (IdP)
    ///
    /// The given issuer_url will be extended with ./well-known/openid-configuration in order to
    /// fetch the configuration and use the jwks_uri property to retrieve the keys used for validation.actix_rt    
    async fn new_from_issuer(
        issuer_url: &str,
        decoder: impl TraitDecoder + Send + Sync + 'static
    ) -> Result<Self, OIDCValidationError> {
        let discovery_document = Oidc::fetch_discovery(&format!(
            "{}/.well-known/openid-configuration",
            issuer_url.clone()
        ))
        .await?;
        Oidc::new_with_keys(&discovery_document.jwks_uri, decoder).await
    }

    /// When you need the validator created with a specified key URL
    async fn new_with_keys(
        key_url: &str,
        decoder: impl TraitDecoder + Send + Sync + 'static
    ) -> Result<Self, OIDCValidationError> {
        let jwks = Oidc::fetch_jwks(key_url).await?;
        Oidc::new_for_jwks(jwks, decoder).await
    }

    /// Use your own JSWKSet directly
    async fn new_for_jwks(
        jwks: JWKSet<Empty>,
        decoder: impl TraitDecoder + Send + Sync + 'static
    ) -> Result<Self, OIDCValidationError> {
        Ok(Oidc {
            jwks: Arc::new(jwks),
            token_decoder:  Arc::new(decoder)
        })
    }

    async fn fetch_discovery(uri: &str) -> Result<OIDCDiscoveryDocument, OIDCValidationError> {
        let client = awc::Client::default();
        client
            .get(uri)
            .send()
            .await
            .map(|mut res| {
                res.json::<OIDCDiscoveryDocument>()
                    .map_err(|err| OIDCValidationError::FailedToParseJsonResponse(err))
            })?
            .await
    }

    async fn fetch_jwks(uri: &str) -> Result<JWKSet<Empty>, OIDCValidationError> {
        let client = awc::Client::default();
        let req = client.get(uri);
        let mut res = req.send().await?;
        let jwk_set: JWKSet<Empty> = res.json::<JWKSet<Empty>>().await?;
        Ok(jwk_set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_rt::test]
    async fn test_jwks_url() {
        let res =
            Oidc::new(OidcConfig::Issuer("https://accounts.google.com".into())).await;
        assert!(res.is_ok());
    }

    #[actix_rt::test]
    async fn test_jwks_url_fail() {
        let res =
            Oidc::new(OidcConfig::Issuer("https://invalid.url".into())).await;
        assert!(res.is_err());
    }
}
