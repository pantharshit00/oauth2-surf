#![warn(missing_docs)]
//! HTTP client adapter for [oauth2](https://crates.io/crates/oauth2) using the [surf](https://crates.io/crates/surf) HTTP client
//!
//!
//!# Usage
//!
//! Just import the `http_client` function from this library and pass it into the request_async function when exchanging tokens.
//! (Example taken from oauth2 docs)
//!```rust
//! use anyhow;
//! use oauth2::{
//!     AuthorizationCode,
//!     AuthUrl,
//!     ClientId,
//!     ClientSecret,
//!     CsrfToken,
//!     PkceCodeChallenge,
//!     RedirectUrl,
//!     Scope,
//!     TokenResponse,
//!     TokenUrl
//! };
//! use oauth2::basic::BasicClient;
//! use oauth2_surf::http_client;
//! use url::Url;
//!
//! // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
//! // token URL.
//! let client =
//!     BasicClient::new(
//!         ClientId::new("client_id".to_string()),
//!         Some(ClientSecret::new("client_secret".to_string())),
//!         AuthUrl::new("http://authorize".to_string())?,
//!         Some(TokenUrl::new("http://token".to_string())?)
//!     )
//!     // Set the URL the user will be redirected to after the authorization process.
//!     .set_redirect_url(RedirectUrl::new("http://redirect".to_string())?);
//!
//! // Generate a PKCE challenge.
//! let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
//!
//! // Generate the full authorization URL.
//! let (auth_url, csrf_token) = client
//!     .authorize_url(CsrfToken::new_random)
//!     // Set the desired scopes.
//!     .add_scope(Scope::new("read".to_string()))
//!     .add_scope(Scope::new("write".to_string()))
//!     // Set the PKCE code challenge.
//!     .set_pkce_challenge(pkce_challenge)
//!     .url();
//!
//! // This is the URL you should redirect the user to, in order to trigger the authorization
//! // process.
//! println!("Browse to: {}", auth_url);
//!
//! // Once the user has been redirected to the redirect URL, you'll have access to the
//! // authorization code. For security reasons, your code should verify that the `state`
//! // parameter returned by the server matches `csrf_state`.
//!
//! // Now you can trade it for an access token.
//! let token_result = client
//!     .exchange_code(AuthorizationCode::new("some authorization code".to_string()))
//!     // Set the PKCE code verifier.
//!     .set_pkce_verifier(pkce_verifier)
//!     .request_async(http_client)
//!     .await?;
//!
//! // Unwrapping token_result will either produce a Token or a RequestTokenError.
//!```
//!

use anyhow::anyhow;
use http::HeaderMap;
use oauth2::{HttpRequest, HttpResponse};
use thiserror::Error;

///
/// Error type used by failed surf requests
///
#[derive(Debug, Error)]
pub enum Error {
    // TODO: change type when surf error implements std::error::Error
    /// Error returned by surf crate.
    #[error("surf request failed")]
    Surf(#[source] anyhow::Error),
    /// Non-surf HTTP error.
    #[error("HTTP error")]
    Http(#[source] http::Error),
    /// Other error.
    #[error("Other error: {}", _0)]
    Other(String),
}

///
/// Creates a http_client which is compatible with oauth2 crate
///
pub async fn http_client(request: HttpRequest) -> Result<HttpResponse, Error> {
    let client = surf::client();

    // Surf doesn't follow redirects by default so this is safe to SSRF
    // Following redirects opens the client up to SSRF vulnerabilities.
    let mut req_builder =
        surf::Request::builder(surf::http::Method::Get, request.url).body(request.body);
    for (name, value) in &request.headers {
        req_builder = req_builder.header(
            name.as_str(),
            value
                .to_str()
                .map_err(|_e| Error::Other("Unable to convert header".into()))?,
        );
    }
    let request = req_builder.build();

    let mut response = client
        .send(request)
        .await
        .map_err(|e| Error::Surf(anyhow!(e)))?;

    let status_code = http::StatusCode::from_u16(response.status().clone().into()).unwrap();

    let chunks = response
        .body_bytes()
        .await
        .map_err(|e| Error::Surf(anyhow!(e)))?;
    Ok(HttpResponse {
        status_code,
        // Oauth2 Library only need content type
        headers: response
            .content_type()
            .map(|ct| {
                Ok(vec![(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_str(ct.essence()).map_err(|e| Error::Http(e.into()))?,
                )]
                .into_iter()
                .collect::<HeaderMap>())
            })
            .transpose()?
            .unwrap_or_else(HeaderMap::new),
        body: chunks.to_vec(),
    })
}
