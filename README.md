# Actix 4 compatible JWT authentication

Works with extractors 

```rust
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct FoundClaims {
        pub iss: String,
        pub sub: String,
        pub aud: String,
        pub name: String,
        pub email: Option<String>,
        pub email_verified: Option<bool>,
    }

    async fn authenticated_user(user: AuthenticatedUser<FoundClaims>) -> String {
        format!("Welcome {}!", user.claims.name)
    }
```

Is a Actix endpoint URL that extracts the AuthenticatedUser from the JWT based Authorization Bearer header. 

You can wire your application like 

```rust
      let test_issuer = "https://accounts.google.com/".to_string();
      let created_validator = OIDCValidator::new_from_issuer(test_issuer.clone()).unwrap();
      OIDCValidatorConfig {
          issuer: test_issuer,
          validator: created_validator,
      }

      HttpServer::new(move || {
        App::new()
                .app_data(validator_config.clone())
                .service(authenticated_user),
        })
      .bind("0.0.0.0:8080".to_string())?
      .run()
      .await
```

# Development of this crate

In order to run the integration tests, it is neccesary to run a service that mocks OIDC requests. 
