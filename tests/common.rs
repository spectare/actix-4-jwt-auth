use futures_util::TryFutureExt;
use reqwest;
use serde_json::Value;
use std::format;

//Expecting the spectare/oidc-token-test-service:latest running bound to port given in the issuer string
//like http://localhost:8080
pub async fn check_test_idp(issuer: String) -> Result<bool, String> {
    reqwest::get(format!("{}/health", issuer))
        .map_err(|e| e.to_string())
        .await
        .map(|r| r.status() == 200)
}

pub async fn create_token(issuer: &str, tokenize: Value) -> Result<String, String> {
    let client = reqwest::Client::new();
    let call = client
        .post(format!("{}/token", issuer.to_string()))
        .json(&tokenize)
        .send()
        .map_err(|e| e.to_string())
        .await?;
    call.text().map_err(|e| e.to_string()).await
}
