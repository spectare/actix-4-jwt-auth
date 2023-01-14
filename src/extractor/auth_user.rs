
use actix_web::{dev::Payload, Error, FromRequest, HttpRequest};
use biscuit::ClaimsSet;
use futures::future::LocalBoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::DecodedInfo;

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
            let decoded_info = DecodedInfo::from_request(&req_local, &mut payload_local).await?;

            let claims = AuthenticatedUser::<T>::get_claims(&decoded_info.payload);
            Ok(AuthenticatedUser {
                jwt: decoded_info.jwt.clone(),
                claims,
            })
        }) 
    }



}


#[cfg(test)]
mod tests {
    
    use crate::{AuthenticatedUser, tests::{create_oidc, create_get_jwt_request, create_jwt_token}};
    use actix_web::{get, test, App, Error};
    use bytes::Bytes;
    use serde::{Deserialize, Serialize};
    


    // Create a struct that will deserialize your claims.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct FoundClaims {
        pub iss: String,
        pub sub: String,
        pub aud: Vec<String>,
        pub name: String,
        pub email: Option<String>,
        pub email_verified: Option<bool>,
    }

    #[get("/authenticated_user")]
    async fn authenticated_user(user: AuthenticatedUser<FoundClaims>) -> String {
        format!("Welcome {}!", user.claims.name)
    }

    ///Test for getting claims from a token using an extractor
    #[actix_rt::test]
    async fn test_extractor_auth_user() -> Result<(), Error> {

        let oidc = create_oidc().await;

        let app = test::init_service(
            App::new()
                .app_data(oidc.clone())
                .service(authenticated_user),
        )
        .await;

        let req = create_get_jwt_request("/authenticated_user", &create_jwt_token()).to_request();

        let resp: Bytes = test::call_and_read_body(&app, req).await;

        assert_eq!(resp, Bytes::from_static(b"Welcome admin!"));
        Ok(())
    }
}