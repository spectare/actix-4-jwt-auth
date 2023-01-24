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

mod extractor;
mod middleware;
mod error;
mod oidc;

#[doc(inline)]
pub use ::biscuit;

pub use extractor::{decoded_info::DecodedInfo, auth_user::AuthenticatedUser};
pub use middleware::OidcBiscuitValidator;
pub use oidc::{Oidc, OidcConfig};
pub use error::OIDCValidationError;

#[cfg(test)]
mod tests {
    use actix_web::{test, http::header};
    use biscuit::{jwk::{JWKSet, JWK, CommonParameters, AlgorithmParameters, RSAKeyParameters}, Empty, jws::{Secret, RegisteredHeader}, JWT, jwa::{SignatureAlgorithm, Algorithm, self}, ClaimsSet, RegisteredClaims};
    use num::BigUint;
    use ring::signature::{KeyPair};
    use serde_json::{Value, json};

    use crate::{OidcConfig, Oidc};

    fn get_secret() -> Secret{
        Secret::rsa_keypair_from_file("private_key.der").unwrap()
    }

    fn create_jwk_set() -> JWKSet<Empty> {
        let secret = get_secret();
        let public_key = match secret {
            Secret::RsaKeyPair(ring_pair) => {
                let s = ring_pair.clone();
                let pk = s.public_key().clone();
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
                    n: BigUint::from_bytes_be(public_key.modulus().big_endian_without_leading_zero()),
                    e: BigUint::from_bytes_be(public_key.exponent().big_endian_without_leading_zero()),
                    ..Default::default()
                }),
                additional: Default::default(),
            }],
        };
        jwk_set
    }

    pub(crate) async fn create_oidc() -> Oidc {
        Oidc::new(OidcConfig::Jwks(create_jwk_set()))
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
}