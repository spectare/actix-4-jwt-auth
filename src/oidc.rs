use biscuit::jwa::*;
use biscuit::jwk::JWKSet;
use biscuit::*;
use futures_util::TryFutureExt;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use std::{borrow::Cow, format, sync::Arc};

use crate::error::OIDCValidationError;

#[derive(Deserialize, Serialize, Debug, Clone)]
struct OIDCDiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

#[derive(Clone, Copy)]
pub(crate) struct OidcDecoder;

impl OidcDecoder {
    pub(crate) fn decode(
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
    pub(crate) jwks: Arc<JWKSet<Empty>>,

    /// Gets the claims from the access token
    /// This will return a complete decoded token that contains all the claims found inside the token
    pub(crate) token_decoder: OidcDecoder,

    /// Use this to override token lookup location
    /// The default location is Header: Authorization
    pub(crate) token_lookup: TokenLookup,
}

///Oidc configuration
pub enum OidcConfig {
    ///issuer
    Issuer(Cow<'static, str>),
    ///key url
    KeyUrl(Cow<'static, str>),
    ///jwks
    Jwks(JWKSet<Empty>),
}

/// Override token lookup location
#[derive(Clone)]
pub enum TokenLookup {
    /// Get access token from a custom header key
    Header(Cow<'static, str>),
    /// Get access token from a custom cookie key
    Cookie(Cow<'static, str>),
}

impl Oidc {
    /// Creates a new Oidc
    pub async fn new(config: OidcConfig) -> Result<Self, OIDCValidationError> {
        Self::new_with_token_lookup(
            config,
            TokenLookup::Header(actix_web::http::header::AUTHORIZATION.as_str().into()),
        )
        .await
    }

    /// Creates a new Oidc with custom token lookup
    pub async fn new_with_token_lookup(
        config: OidcConfig,
        token_lookup: TokenLookup,
    ) -> Result<Self, OIDCValidationError> {
        match config {
            OidcConfig::Issuer(issuer) => {
                Oidc::new_from_issuer(issuer.as_ref(), token_lookup).await
            }
            OidcConfig::KeyUrl(key_url) => {
                Oidc::new_with_keys(key_url.as_ref(), token_lookup).await
            }
            OidcConfig::Jwks(jwks) => Oidc::new_for_jwks(jwks, token_lookup),
        }
    }

    /// Creates a new Oidc based on the base URL of the Oidc Identity Provider (IdP)
    ///
    /// The given issuer_url will be extended with ./well-known/openid-configuration in order to
    /// fetch the configuration and use the jwks_uri property to retrieve the keys used for validation.actix_rt
    async fn new_from_issuer(
        issuer_url: &str,
        token_lookup: TokenLookup,
    ) -> Result<Self, OIDCValidationError> {
        let discovery_document =
            Oidc::fetch_discovery(&format!("{}/.well-known/openid-configuration", issuer_url))
                .await?;
        Oidc::new_with_keys(&discovery_document.jwks_uri, token_lookup).await
    }

    /// When you need the validator created with a specified key URL
    async fn new_with_keys(
        key_url: &str,
        token_lookup: TokenLookup,
    ) -> Result<Self, OIDCValidationError> {
        let jwks = Oidc::fetch_jwks(key_url).await?;
        Oidc::new_for_jwks(jwks, token_lookup)
    }

    /// Use your own JSWKSet directly
    fn new_for_jwks(
        jwks: JWKSet<Empty>,
        token_lookup: TokenLookup,
    ) -> Result<Self, OIDCValidationError> {
        Ok(Oidc {
            jwks: Arc::new(jwks),
            token_decoder: OidcDecoder,
            token_lookup,
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
                    .map_err(OIDCValidationError::FailedToParseJsonResponse)
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
        let res = Oidc::new(OidcConfig::Issuer("https://accounts.google.com".into())).await;
        assert!(res.is_ok());
    }

    #[actix_rt::test]
    async fn test_jwks_url_fail() {
        let res = Oidc::new(OidcConfig::Issuer("https://invalid.url".into())).await;
        assert!(res.is_err());
    }
}
