use actix_web::http::StatusCode;
use actix_web::ResponseError;
use awc::error::{JsonPayloadError, SendRequestError};
use biscuit::errors::Error as BiscuitError;
use thiserror::Error;

/// When a JWT token is received and validated, it may be faulty due to different reasons
#[derive(Error, Debug)]
pub enum OIDCValidationError {
    ///The Bearer token passed is not valid
    #[error("Bearer authentication token invalid: {0:?}")]
    InvalidBearerAuth(awc::error::HttpError),

    ///The token validation fails due to cryptographic issues
    #[error("Crypto handling error: {0:?}")]
    CryptoError(biscuit::errors::Error),

    ///The Bearer token passed is not found or faulty
    #[error("Token on bearer header is not found")]
    BearerNotComplete,

    ///The validated token has been validated but is not valid for this situation.
    #[error("No token found or token is not authorized")]
    Unauthorized,

    ///It was not possible to laod the keys used for validation of the signature
    #[error("Failed to process JWKS json from {0:?}")]
    FailedToParseJsonResponse(awc::error::JsonPayloadError),

    ///It was not possible to fetch the JWKS uri
    #[error("Failed to fetch JWKS keystore from {0:?}")]
    FailedToLoadKeystore(awc::error::HttpError),

    ///It was not possible to retrieve the openid-configuration document and get the jwks_uri
    #[error("Failed to load JWKS keystore from {0:?}")]
    FailedToLoadDiscovery(awc::error::HttpError),

    ///Failed to fetch data from given URI
    #[error("Cannot fetch {0:?}")]
    ConnectivityError(SendRequestError),

    ///Token does not have sufficient rights
    #[error("Token does not have sufficient rights")]
    IvalidAccess,
}

impl From<awc::error::HttpError> for OIDCValidationError {
    fn from(e: awc::error::HttpError) -> Self {
        OIDCValidationError::InvalidBearerAuth(e)
    }
}

impl From<awc::error::JsonPayloadError> for OIDCValidationError {
    fn from(e: JsonPayloadError) -> Self {
        OIDCValidationError::FailedToParseJsonResponse(e)
    }
}

impl From<SendRequestError> for OIDCValidationError {
    fn from(e: SendRequestError) -> Self {
        OIDCValidationError::ConnectivityError(e)
    }
}

impl From<biscuit::errors::Error> for OIDCValidationError {
    fn from(e: BiscuitError) -> Self {
        OIDCValidationError::CryptoError(e)
    }
}

impl ResponseError for OIDCValidationError {
    fn status_code(&self) -> StatusCode {
        match self {
            OIDCValidationError::InvalidBearerAuth(_) => StatusCode::UNAUTHORIZED,
            OIDCValidationError::BearerNotComplete => StatusCode::BAD_REQUEST,
            OIDCValidationError::FailedToLoadKeystore(_) => StatusCode::INTERNAL_SERVER_ERROR,
            OIDCValidationError::FailedToLoadDiscovery(_) => StatusCode::INTERNAL_SERVER_ERROR,
            OIDCValidationError::Unauthorized => StatusCode::UNAUTHORIZED,
            OIDCValidationError::FailedToParseJsonResponse(_) => StatusCode::INTERNAL_SERVER_ERROR,
            OIDCValidationError::ConnectivityError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            OIDCValidationError::CryptoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            OIDCValidationError::IvalidAccess => StatusCode::FORBIDDEN,
        }
    }
}