

use actix_web::{dev::Payload, Error, FromRequest, HttpRequest};
use biscuit::ClaimsSet;
use futures_util::future::{ok, ready, Ready};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{OIDCValidationError, Oidc};


/// DecodedInfo with a decorated token will retrieve data for use in your functions
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct DecodedInfo {
    /// The complete encoded token (without the Bearer part)
    pub jwt: String,
    /// The decoded token in compact representation of a JWS
    pub decoded_token: biscuit::jws::Compact<ClaimsSet<Value>, biscuit::Empty>,
}


impl FromRequest for DecodedInfo {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let oidc = req
            .app_data::<Oidc>()
            .expect("Please configure the OIDC on your App");

        let authorization = req.headers().get(actix_web::http::header::AUTHORIZATION);

        match authorization {
            Some(value) => {
                let value_str = value.to_str().unwrap().to_string();
                match value_str.strip_prefix("Bearer ") {
                    Some(token) => match oidc.token_decoder.decode(&oidc.jwks, token)  {
                        Ok(decoded_token) => ok(DecodedInfo {
                                jwt: token.to_string(),
                                decoded_token,
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



#[cfg(test)]
mod tests {
    use crate::{DecodedInfo, tests::{create_oidc, create_get_jwt_request, create_jwt_token}};
    use actix_web::{get, test, App, Error, dev::Service, http::StatusCode};
    use bytes::Bytes;

    #[get("/decoder")]
    async fn decoder(claims: DecodedInfo) -> String {
        claims.jwt
    }

    ///Test for decoder entity extractor
    #[actix_rt::test]
    async fn test_extractor_decoder() -> Result<(), Error> {

        let oidc = create_oidc().await;

        let app = test::init_service(
            App::new()
                .app_data(oidc.clone())
                .service(decoder),
        )
        .await;

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
    
            let app = test::init_service(
                App::new()
                    .app_data(oidc.clone())
                    .service(decoder),
            )
            .await;
    
            let req = create_get_jwt_request("/decoder", "bad_token").to_request();
    
            let response = app.call(req).await.unwrap();
    
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            Ok(())
        }
}