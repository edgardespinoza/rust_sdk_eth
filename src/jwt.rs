use std::error::Error;

pub fn decode(jwt: &str) -> Result<[serde_json::Value; 2], Box<dyn Error>> {
    let splitted_jwt_strings: Vec<_> = jwt.split('.').collect();

    let jwt_header = splitted_jwt_strings
        .get(0)
        .expect("split always returns at least one element");
    let jwt_body = splitted_jwt_strings.get(1).ok_or(Box::<dyn Error>::from(
        "Could not find separator in jwt string.",
    ))?;

    let decoded_jwt_header = base64::decode(jwt_header)?;
    let decoded_jwt_body = base64::decode(jwt_body)?;

    let converted_jwt_header = String::from_utf8(decoded_jwt_header)?;
    let converted_jwt_body = String::from_utf8(decoded_jwt_body)?;

    let parsed_jwt_header = serde_json::from_str::<serde_json::Value>(&converted_jwt_header)?;
    let parsed_jwt_body = serde_json::from_str::<serde_json::Value>(&converted_jwt_body)?;

    Ok([parsed_jwt_header, parsed_jwt_body])
}

#[cfg(test)]
mod test_super {
    use std::error::Error;

    use super::*;

    use jwt_simple::prelude::*;

    #[test]
    fn test_validate_credential() -> Result<(), Box<dyn Error>> {
        let jwt = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJkaWQ6ZXY6Y3dNTE51UnR1c1RIQUQxUXdDZ2Q2QUFvcUhzYUNNUEs0VldMTSIsImlzcyI6IjJjNDkyMDcwMzA0NWFjNDBmZTU3NGNjN2Y4NTJiMGNiM2ZhZWU0MTA4MDA4YTQyYzllYjVlZThiNzAzNjZhNGQzYTc4MTI2N2Y2NTNmMjk3NjFlMDZjYTg4NzdmYmI0M2U1NTAzNWY3NjcwMTkxNjdlYmMwN2NhNTQxMmMyMjc2IiwiaWF0IjoxNjQ5MTI0OTg4LCJleHAiOjE2NDkzMDQ5ODgsImF1ZCI6ImRpZDpldjpjd01MTUw1eW0zRkJWUHdxWXFjRHg3YjdlaFEzVGtDS0Iyd0F0IiwicHJlc2VudGF0aW9uIjp7IkBjb250ZXh0IjoiaHR0cHM6Ly93My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsIkBpZCI6IjYyNGJhNjdjNjk2MGNmMjAyZDk3NTc2OSIsIkB0eXBlIjoiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiIsInZlcmlmaWFibGVDcmVkZW50aWFsIjpbeyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiQGlkIjoiNjI0NzI4ZDAwYTk0YzkyZjY1MTkwZDljIiwiQHR5cGUiOiJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7Im5hbWUiOnsiZ2l2ZW5OYW1lIjoiRWRnYXJkIiwiZmFtaWx5TmFtZSI6IkVzcGlub3phIn0sIkBpZCI6ImRpZDpldjpjd01MTnVSdHVzVEhBRDFRd0NnZDZBQW9xSHNhQ01QSzRWV0xNIn0sImlzc3VlciI6ImRpZDpldjpjd01MTnVSdHVzVEhBRDFRd0NnZDZBQW9xSHNhQ01QSzRWV0xNIiwiaXNzdWFuY2VEYXRlIjoiMjAyMi0wNC0wMVQxNjozMToxMi4wNTBaIiwicHJvb2YiOnsiY29udHJhY3RBZGRyZXNzIjoiMHg5ZjhjMWUxOTZGNTY5NmUwMTRGNGQxRTQ5NjFCOTJkYjg2NkJFMjcxIiwibmV0d29ya0lkIjo2NDg1MjksInR5cGUiOiJFdGhlcmV1bUF0dGVzdGF0aW9uUmVnaXN0cnkyMDE5In19LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsIkBpZCI6IjYyNGI2MDljZDliY2VkYzZkZDdkNDA2ZSIsIkB0eXBlIjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJlbWFpbCI6IkVkZ2FyZC5lc3Bpbm96YS5yaXZhc0BnbWFpbC5jb20iLCJAaWQiOiJkaWQ6ZXY6Y3dNTE51UnR1c1RIQUQxUXdDZ2Q2QUFvcUhzYUNNUEs0VldMTSJ9LCJpc3N1ZXIiOiJkaWQ6ZXY6Y3dNTE51UnR1c1RIQUQxUXdDZ2Q2QUFvcUhzYUNNUEs0VldMTSIsImlzc3VhbmNlRGF0ZSI6IjIwMjItMDQtMDRUMjE6MTg6MjAuMjkyWiIsInByb29mIjp7ImNvbnRyYWN0QWRkcmVzcyI6IjB4OWY4YzFlMTk2RjU2OTZlMDE0RjRkMUU0OTYxQjkyZGI4NjZCRTI3MSIsIm5ldHdvcmtJZCI6NjQ4NTI5LCJ0eXBlIjoiRXRoZXJldW1BdHRlc3RhdGlvblJlZ2lzdHJ5MjAxOSJ9fV0sInRlcm1zT2ZVc2UiOnsiaWQiOiJodHRwOi8vY3VzdG9tZXJjb21tb25zLm9yZy9wMmIxYmV0YS1sZWdhbGVzZS8iLCJzdWJqZWN0IjoiZGlkOmV2OmN3TUxNTDV5bTNGQlZQd3FZcWNEeDdiN2VoUTNUa0NLQjJ3QXQifSwicmVjaXBpZW50IjoiZGlkOmV2OmN3TUxNTDV5bTNGQlZQd3FZcWNEeDdiN2VoUTNUa0NLQjJ3QXQifSwidGFnIjoiNjI0YmE2N2M5YjEwOTE5M2Y2Mjc2Y2ZhIn0.enPP1kbXx3MrFPNRyy1D3qVmjem8552vohA2zjhHIy9MmjIMZCpTfSb8GcXDYhMrQLlN21iQYBOqXQjggzhnlw";

        let token = decode(jwt)?;
        let body = &token[1];

        let iss = body.get("iss").unwrap();
        let iss = iss.as_str().unwrap();
        let iss = "04".to_string() + &iss.to_string();

        println!("{}", body.get("presentation").unwrap());

        let iss = hex::decode(iss.as_str()).unwrap();

        let public_key = ES256kPublicKey::from_bytes(iss.as_slice())?;

        let claims = public_key.verify_token::<NoCustomClaims>(jwt, None);

        match claims {
            Ok(d) => println!("{:?}", d),
            Err(types) => println!("{:?}", types),
        }

        Ok(())
    }
}
