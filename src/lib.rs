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
              // .wrap(OidcBiscuitValidator::default()) //without issuer verification
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

mod error;
mod extractor;
mod middleware;
mod oidc;

#[doc(inline)]
pub use ::biscuit;

pub use error::OIDCValidationError;
pub use extractor::{auth_user::AuthenticatedUser, decoded_info::DecodedInfo};
pub use middleware::OidcBiscuitValidator;
pub use oidc::{Oidc, OidcConfig, TokenLookup};

#[cfg(test)]
mod tests {
    use actix_web::{cookie::Cookie, http::header, test};
    use biscuit::{
        jwa::{self, Algorithm, SignatureAlgorithm},
        jwk::{AlgorithmParameters, CommonParameters, JWKSet, RSAKeyParameters, JWK},
        jws::{RegisteredHeader, Secret},
        ClaimsSet, Empty, RegisteredClaims, JWT,
    };
    use num::BigUint;
    use ring::{rsa::PublicKeyComponents, signature::KeyPair};
    use serde_json::{json, Value};

    use crate::{Oidc, OidcConfig, TokenLookup};

    fn get_secret() -> Secret {
        Secret::rsa_keypair_from_file("private_key.der").unwrap()
    }

    fn create_jwk_set() -> JWKSet<Empty> {
        let secret = get_secret();
        let public_key = match secret {
            Secret::RsaKeyPair(ring_pair) => {
                let cloned_pair = ring_pair.clone();
                let pk = PublicKeyComponents::<Vec<_>>::from(cloned_pair.public_key());
                Some(pk)
            }
            _ => None,
        }
        .expect("There is no RsaKeyPair with a public key found");

        let jwk_set: JWKSet<Empty> = JWKSet {
            keys: vec![JWK {
                common: CommonParameters {
                    algorithm: Some(Algorithm::Signature(jwa::SignatureAlgorithm::RS256)),
                    key_id: Some("2020-01-29".to_string()),
                    ..Default::default()
                },
                algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                    n: BigUint::from_bytes_be(public_key.n.as_slice()),
                    e: BigUint::from_bytes_be(public_key.e.as_slice()),
                    ..Default::default()
                }),
                additional: Default::default(),
            }],
        };
        jwk_set
    }

    pub(crate) async fn create_oidc() -> Oidc {
        Oidc::new(OidcConfig::Jwks(create_jwk_set())).await.unwrap()
    }

    pub(crate) async fn create_oidc_with_token_lookup(token_lookup: TokenLookup) -> Oidc {
        Oidc::new_with_token_lookup(OidcConfig::Jwks(create_jwk_set()), token_lookup)
            .await
            .unwrap()
    }

    pub(crate) fn create_token(tokenize: Value) -> String {
        let signing_secret = get_secret();
        let decoded_token = JWT::new_decoded(
            From::from(RegisteredHeader {
                algorithm: SignatureAlgorithm::RS256,
                key_id: Some("2020-01-29".to_string()),
                ..Default::default()
            }),
            ClaimsSet::<Value> {
                registered: RegisteredClaims {
                    issuer: None,
                    subject: None,
                    audience: None,
                    not_before: None,
                    expiry: None,
                    id: None,
                    issued_at: None,
                },
                private: tokenize,
            },
        );
        decoded_token
            .encode(&signing_secret)
            .unwrap()
            .unwrap_encoded()
            .to_string()
    }

    pub(crate) fn create_jwt_token() -> String {
        let claims = json!({
        "iss": "http://0.0.0.0:9090",
        "sub": "CgVhZG1pbhIFbG9jYWw",
        "aud": ["cafienne-ui"],
        "email": "admin@example.com",
        "email_verified": true,
        "name": "admin"
        });
        create_token(claims)
    }

    pub(crate) fn create_get_jwt_request(url: &str, token: &str) -> test::TestRequest {
        test::TestRequest::get()
            .uri(url)
            .insert_header(header::ContentType::json())
            .insert_header((
                header::AUTHORIZATION,
                header::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            ))
    }

    pub(crate) fn create_get_jwt_request_custom_header(
        url: &str,
        token: &str,
    ) -> test::TestRequest {
        test::TestRequest::get()
            .uri(url)
            .insert_header(header::ContentType::json())
            .insert_header((
                "x-header-token-key",
                header::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            ))
    }

    pub(crate) fn create_get_jwt_request_custom_cookie(
        url: &str,
        token: &str,
    ) -> test::TestRequest {
        test::TestRequest::get()
            .uri(url)
            .insert_header(header::ContentType::json())
            .cookie(Cookie::new("x-cookie-token-key", token))
    }
}
