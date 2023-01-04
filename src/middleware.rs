
use std::{future::{ready, Ready}, rc::Rc};

use crate::{extractor::UserClaims, OIDCValidationError};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures_util::future::LocalBoxFuture;
use biscuit::ValidationOptions;




/// Middleware with standard biscuit validation
#[derive(PartialEq, Clone, Default)]
pub struct OidcBiscuitValidator{
    /// Biscuit validation options
    pub options: ValidationOptions
}

impl<S, B> Transform<S, ServiceRequest> for OidcBiscuitValidator
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = OidcBiscuitValidatorMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(OidcBiscuitValidatorMiddleware { service: Rc::new(service), validation_options: self.options.clone() }))
    }
}

pub struct OidcBiscuitValidatorMiddleware<S> {
    service: Rc<S>,
    validation_options:ValidationOptions,
}

impl<S, B> Service<ServiceRequest> for OidcBiscuitValidatorMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let validation_options = self.validation_options.clone();

        Box::pin(async move {
            let user = req.extract::<UserClaims>().await?.clone();

            match user.decoded_token.validate(validation_options) {
                Ok(()) => {
                    let fut = svc.call(req);
                    let res = fut.await?;
                    Ok(res)
                },
                Err(_err)  => {
                    Err(OIDCValidationError::IvalidAccess.into())
                }
            }
        })
    }
}


