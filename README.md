# Actix 4 compatible JWT authentication

Works with extraxtors 

```rust
    async fn authenticated_user(user: AuthenticatedUser) -> String {
        format!("Welcome {}!", user.name)
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
