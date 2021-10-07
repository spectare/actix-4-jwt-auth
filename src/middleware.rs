use super::OIDCValidationError;
use super::OIDCValidator;
use actix_web::dev::{MessageBody, Service, Transform};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::Error;
use biscuit::errors::Error as BiscuitError;
use biscuit::jwa::*;
use biscuit::jwk::JWKSet;
use biscuit::jws::*;
use biscuit::*;
use serde_json::Value;
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct JwtValidationHandler<S> {
    service: S,
    jwks: JWKSet<Empty>,
    issuer: String,
}

impl<S, B> Transform<S, ServiceRequest> for OIDCValidator
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
    B: 'static,
    S::Future: 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Transform = JwtValidationHandler<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtValidationHandler {
            service,
            jwks: self.jwks.clone(),
            issuer: self.issuer.clone(),
        }))
    }
}

impl<S> JwtValidationHandler<S> {
    pub fn validate_token(&self, token: &str) -> Result<Value, BiscuitError> {
        let token: biscuit::jws::Compact<biscuit::ClaimsSet<Empty>, RegisteredClaims> =
            JWT::new_encoded(&token);
        let decoded_token = token.decode_with_jwks(&self.jwks, Some(SignatureAlgorithm::RS256))?;
        let claims = decoded_token.payload().unwrap();
        let json_value = serde_json::to_value(claims).unwrap();
        Ok(json_value)
    }
}

impl<S, B> Service<ServiceRequest> for JwtValidationHandler<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: MessageBody,
    B: 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let authorization = req.headers().get(actix_web::http::header::AUTHORIZATION);

        let _jwt = {
            match authorization {
                Some(value) => {
                    let value_str = value.to_str().unwrap().to_string();
                    match value_str.strip_prefix("Bearer ") {
                        Some(token) => match self.validate_token(&token) {
                            Ok(jwt) => Some(jwt),
                            Err(e) => {
                                return Box::pin(ready(Err(
                                    OIDCValidationError::InvalidBearerAuth(e).into(),
                                )))
                            }
                        },
                        _ => {
                            return Box::pin(ready(Err(
                                OIDCValidationError::BearerNotComplete.into()
                            )))
                        }
                    }
                }
                None => None,
            }
        };

        //if (true)(&req, &jwt) {
        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;

            Ok(res)
        })
        // } else {
        //   Box::pin(ready(Err(OIDCValidationError::Unauthorised.into())))
        // }
    }
}
