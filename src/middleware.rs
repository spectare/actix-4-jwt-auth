use super::OIDCDiscoveryDocument;
use super::OIDCValidationError;
use super::OIDCValidator;
use actix_web::dev::{MessageBody, Service, Transform};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{Error};
use alcoholic_jwt::{token_kid, validate, ValidJWT, Validation, ValidationError, JWKS};
use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct JwtValidationHandler<S> {
    service: S,
    jwks: JWKS,
    discovery_document: OIDCDiscoveryDocument,
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
            discovery_document: self.discovery_document.clone(),
        }))
    }
}

impl<S> JwtValidationHandler<S> {
    fn validate_token(&self, token: &str) -> Result<ValidJWT, ValidationError> {
        let validations = vec![
            Validation::Issuer(self.discovery_document.issuer.clone()),
            Validation::SubjectPresent,
        ];
        let kid = match token_kid(&token) {
            Ok(res) => res.expect("failed to decode kid"),
            Err(_) => return Err(ValidationError::InvalidJWK),
        };
        let jwk = self
            .jwks
            .find(&kid)
            .expect("Specified key not found in set");
        validate(token, jwk, validations)
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
