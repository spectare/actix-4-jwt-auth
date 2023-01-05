
use super::OIDCValidationError;
use super::Oidc;
use actix_web::{dev::Payload, Error, FromRequest, HttpRequest};
use biscuit::ClaimsSet;
use futures::future::LocalBoxFuture;
use futures_util::future::{ok, ready, Ready};
use serde::{Deserialize, Serialize};
use serde_json::Value;


/// UserClaims with a decorated token will retrieve data for use in your functions
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct UserClaims {
    /// The complete encoded token (without the Bearer part)
    pub jwt: String,
    /// The decoded token in compact representation of a JWS
    pub decoded_token: biscuit::jws::Compact<ClaimsSet<Value>, biscuit::Empty>,
}


impl FromRequest for UserClaims {
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
                        Ok(decoded_token) => ok(UserClaims {
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

impl<T: for<'de> Deserialize<'de>> AuthenticatedUser<T> {
    /// Gets the claims from the access token
    /// This will return a complete claimset that contains all the claims found inside the token
    /// as Serde Json Value.
    fn get_claims(
        claims_set: &ClaimsSet<Value>
    ) -> T
    {
        let json_value = serde_json::to_value(claims_set).unwrap();
        let authenticated_user: T = serde_json::from_value(json_value).unwrap();
        authenticated_user
    }
}

impl<T: for<'de> Deserialize<'de>> FromRequest for AuthenticatedUser<T> {
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let req_local = req.clone();
        let mut payload_local = payload.take();
        Box::pin(async move {
            let user_claims = UserClaims::from_request(&req_local, &mut payload_local).await?;

            match user_claims.decoded_token.payload() {
                Ok(claims_set) => {
                    let claims = AuthenticatedUser::<T>::get_claims(claims_set);
                    Ok(AuthenticatedUser {
                        jwt: user_claims.jwt.clone(),
                        claims,
                    })
                },
                Err(_err)  => {
                    Err(OIDCValidationError::Unauthorized.into())
                }
            }
        }) 
    }



}