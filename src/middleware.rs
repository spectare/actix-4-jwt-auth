
use std::{future::{ready, Ready}, rc::Rc};

use crate::{DecodedInfo, OIDCValidationError};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, body::{EitherBody, BoxBody},
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
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
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
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let validation_options = self.validation_options.clone();

        Box::pin(async move {
            let user = req.extract::<DecodedInfo>().await?.clone();

            match user.decoded_token.validate(validation_options) {
                Ok(()) => {
                    let fut = svc.call(req);
                    let res = fut.await?;
                    Ok(res.map_into_left_body())
                },
                Err(_err)  => {
                    let res: actix_web::Error = OIDCValidationError::IvalidAccess.into();
                    Ok(req.error_response(res).map_into_right_body())
                }
            }
        })
    }
}


#[cfg(test)]
mod tests {
    use crate::{DecodedInfo, tests::{create_oidc, create_get_jwt_request, create_jwt_token, create_token}, OidcBiscuitValidator};
    use actix_web::{get, test, App, Error, http::StatusCode, dev::Service, HttpResponse};
    use biscuit::{ValidationOptions, Validation};
    use bytes::Bytes;
    use serde_json::json;

    #[get("/decoder")]
    async fn decoder(claims: DecodedInfo) -> HttpResponse {
        HttpResponse::Ok().body(claims.jwt)
    }

    ///Test in middleware for a valid issuer
    #[actix_rt::test]
    async fn test_biscuit_middleware_issuer_valid() -> Result<(), Error> {

        let oidc = create_oidc().await;

        let biscuit_validator = OidcBiscuitValidator { 
            options: ValidationOptions {
                issuer: Validation::Validate("http://0.0.0.0:9090".to_string()),
                ..ValidationOptions::default()
            }
        };

        let app = test::init_service(
            App::new()
                .app_data(oidc.clone())
                .wrap(biscuit_validator)
                .service(decoder),
        )
        .await;

        let token = create_jwt_token();

        let req = create_get_jwt_request("/decoder", &token).to_request();

        let result: Bytes = test::call_and_read_body(&app, req).await;

        assert_eq!(result, Bytes::from(token));
        Ok(())
    }

    ///Test in middleware for invalid issuer
    #[actix_rt::test]
    async fn test_biscuit_middleware_issuer_invalid() -> Result<(), Error> {

        let oidc = create_oidc().await;

        let biscuit_validator = OidcBiscuitValidator { 
            options: ValidationOptions {
                issuer: Validation::Validate("http://0.0.0.0:9091".to_string()),
                ..ValidationOptions::default()
            }
        };

        let app = test::init_service(
            App::new()
                .app_data(oidc.clone())
                .wrap(biscuit_validator)
                .service(decoder),
        )
        .await;

        let token = create_jwt_token();

        let req = create_get_jwt_request("/decoder", &token).to_request();

        let response = app.call(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    ///Test in middleware for valid expired date
    #[actix_rt::test]
    async fn test_biscuit_middleware_expired_valid() -> Result<(), Error> {

        let oidc = create_oidc().await;

        let app = test::init_service(
            App::new()
                .app_data(oidc.clone())
                .wrap(OidcBiscuitValidator::default())
                .service(decoder),
        )
        .await;
        let claims = json!({
            "iss": "http://0.0.0.0:9090",
            "sub": "CgVhZG1pbhIFbG9jYWw",
            "aud": ["cafienne-ui"],
            "exp": 2147483647, //19 January 2038 03:14:07 -> Max of the i32 expected by the json! macro
            });


        let token = create_token(claims);

        let req = create_get_jwt_request("/decoder", &token).to_request();

        let response = app.call(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }
    
    ///Test in middleware for invalid expired date
    #[actix_rt::test]
    async fn test_biscuit_middleware_expired_invalid() -> Result<(), Error> {

        let oidc = create_oidc().await;

        let app = test::init_service(
            App::new()
                .app_data(oidc.clone())
                .wrap(OidcBiscuitValidator::default())
                .service(decoder),
        )
        .await;
        let claims = json!({
            "iss": "http://0.0.0.0:9090",
            "sub": "CgVhZG1pbhIFbG9jYWw",
            "aud": ["cafienne-ui"],
            "exp": 1602324610, //Saturday 10 October 2020 10:10:10 (e.g Expired)
          });


        let token = create_token(claims);

        let req = create_get_jwt_request("/decoder", &token).to_request();

        let response = app.call(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    ///Test in middleware for valid expired date
    #[actix_rt::test]
    async fn test_biscuit_middleware_invisible_not_before_valid() -> Result<(), Error> {

        let oidc = create_oidc().await;

        let app = test::init_service(
            App::new()
                .app_data(oidc.clone())
                .wrap(OidcBiscuitValidator::default())
                .service(decoder),
        )
        .await;
        let claims = json!({
            "iss": "http://0.0.0.0:9090",
            "sub": "CgVhZG1pbhIFbG9jYWw",
            "aud": ["cafienne-ui"],
            "exp": 2147483647, //19 January 2038 03:14:07 -> Max of the i32 expected by the json! macro
            "nbf": 1602324610, //Saturday 10 October 2020 10:10:10
            });


        let token = create_token(claims);

        let req = create_get_jwt_request("/decoder", &token).to_request();

        let response = app.call(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }
    
    ///Test in middleware for invalid expired date
    #[actix_rt::test]
    async fn test_biscuit_middleware_invisible_not_before_invalid() -> Result<(), Error> {

        let oidc = create_oidc().await;

        let app = test::init_service(
            App::new()
                .app_data(oidc.clone())
                .wrap(OidcBiscuitValidator::default())
                .service(decoder),
        )
        .await;
        let claims = json!({
            "iss": "http://0.0.0.0:9090",
            "sub": "CgVhZG1pbhIFbG9jYWw",
            "aud": ["cafienne-ui"],
            "exp": 2147483647, //19 January 2038 03:14:07 -> Max of the i32 expected by the json! macro
            "nbf": 2075623810, // 10 October 2035 10:10:10
          });


        let token = create_token(claims);

        let req = create_get_jwt_request("/decoder", &token).to_request();

        let response = app.call(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }
}