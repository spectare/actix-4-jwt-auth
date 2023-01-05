use futures_util::TryFutureExt;
use serde_json::Value;
use std::format;

//Expecting the spectare/oidc-token-test-service:latest running bound to port given in the issuer string
//like http://localhost:8080
pub async fn check_test_idp(issuer: String) -> Result<bool, String> {
    let client = awc::Client::default();
    client.get(format!("{}/health", issuer))
        .send()
        .map_err(|e| e.to_string())
        .await
        .map(|r| r.status() == 200)
}

pub async fn create_token(issuer: &str, tokenize: Value) -> Result<String, String> {
    let client = awc::Client::default();
    let mut call = client
        .post(format!("{}/token", issuer.to_string()))
        .send_json(&tokenize)
        .map_err(|e| e.to_string())
        .await?;

    let body = call.body().await.unwrap();
    match std::str::from_utf8(&body) {
        Ok(str) => Ok(str.to_owned()),
        Err(err) => Err(err.to_string())
    }
}
