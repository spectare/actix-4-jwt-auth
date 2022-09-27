use super::OIDCValidationError;
use super::OIDCValidator;
use actix_web::{dev, Error, FromRequest, HttpRequest};
use futures_util::future::{ok, ready, Ready};
use serde::{Deserialize, Serialize};

///The config may be used to create your OIDCValidator programatically
/// When you do not add the app_data with your own config, a default will look for an
/// environment variable named OIDC_ISSUER and use that as base URL to fetch the
/// openid-configuration.
#[derive(Clone)]
pub struct OIDCValidatorConfig {
    ///URL of the issuer as String
    pub issuer: String,
    /// Configured [`OIDCValidator`]
    pub validator: OIDCValidator,
}

/// AuthenticatedUser with your given Claims struct will be extracted data to use in your functions.
/// The struct may contain registered claims, these are validated according to
/// [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1)
///
/// NOTE: It is expected that you create your own struct based on the JWT and claims you like to process.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser<T> {
    /// The complete encoded token (without the Bearer part)
    pub jwt: String,
    /// The claims deserialized to the given struct T
    pub claims: T,
}

impl<T: for<'de> Deserialize<'de>> FromRequest for AuthenticatedUser<T> {
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
                    Some(token) => match cfg.validator.validate_token(token) {
                        Ok(valid_claims) => ok(AuthenticatedUser {
                            jwt: token.to_string(),
                            claims: valid_claims,
                        }),
                        Err(e) => ready(Err(e.into())),
                    },
                    _ => ready(Err(OIDCValidationError::BearerNotComplete.into())),
                }
            }
            None => ready(Err(OIDCValidationError::Unauthorized.into())),
        }
    }
}
