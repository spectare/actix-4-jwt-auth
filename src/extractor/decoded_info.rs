use std::str::FromStr;

use actix_web::{dev::Payload, http::header::HeaderName, Error, FromRequest, HttpRequest};
use biscuit::ClaimsSet;
use futures_util::future::{ok, ready, Ready};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{OIDCValidationError, Oidc, TokenLookup};

/// DecodedInfo with a decorated token will retrieve data for use in your functions
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct DecodedInfo {
    /// The complete encoded token (without the Bearer part)
    pub jwt: String,
    /// The decoded token in ClaimsSet
    pub payload: ClaimsSet<Value>,
}

impl FromRequest for DecodedInfo {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let oidc = req
            .app_data::<Oidc>()
            .expect("Please configure the OIDC on your App");

        let prefix;

        let authorization = match &oidc.token_lookup {
            TokenLookup::Header(key) => {
                prefix = "Bearer ";
                match req.headers().get(HeaderName::from_str(key).unwrap()) {
                    Some(value) => value.to_str().unwrap().to_string(),
                    None => return ready(Err(OIDCValidationError::Unauthorized.into())),
                }
            }
            TokenLookup::Cookie(key) => {
                prefix = "";
                match req.cookie(key) {
                    Some(value) => value.value().to_string(),
                    None => return ready(Err(OIDCValidationError::Unauthorized.into())),
                }
            }
        };

        match authorization.strip_prefix(prefix) {
            Some(token) => match oidc.token_decoder.decode(&oidc.jwks, token) {
                Ok(decoded_token) => match decoded_token.payload() {
                    Ok(payload) => ok(DecodedInfo {
                        jwt: token.to_string(),
                        payload: payload.to_owned(),
                    }),
                    Err(_err) => ready(Err(OIDCValidationError::Unauthorized.into())),
                },
                Err(e) => ready(Err(e.into())),
            },
            _ => ready(Err(OIDCValidationError::BearerNotComplete.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        tests::{create_get_jwt_request, create_jwt_token, create_oidc},
        DecodedInfo,
    };
    use actix_web::{dev::Service, get, http::StatusCode, test, App, Error};
    use bytes::Bytes;

    #[get("/decoder")]
    async fn decoder(claims: DecodedInfo) -> String {
        claims.jwt
    }

    ///Test for decoder entity extractor
    #[actix_rt::test]
    async fn test_extractor_decoder() -> Result<(), Error> {
        let oidc = create_oidc().await;

        let app = test::init_service(App::new().app_data(oidc.clone()).service(decoder)).await;

        let token = create_jwt_token();

        let req = create_get_jwt_request("/decoder", &token).to_request();

        let result: Bytes = test::call_and_read_body(&app, req).await;

        assert_eq!(result, Bytes::from(token));
        Ok(())
    }

    ///Test for decoder entity extractor with bad token
    #[actix_rt::test]
    async fn test_extractor_decoder_bad_token() -> Result<(), Error> {
        let oidc = create_oidc().await;

        let app = test::init_service(App::new().app_data(oidc.clone()).service(decoder)).await;

        let req = create_get_jwt_request("/decoder", "bad_token").to_request();

        let response = app.call(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        Ok(())
    }
}
