use anyhow::anyhow;
use http::HeaderMap;
use oauth2::{HttpRequest, HttpResponse};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    // TODO: change type when surf error implements std::error::Error
    /// Error returned by curl crate.
    #[error("surf request failed")]
    Surf(#[source] anyhow::Error),
    /// Non-curl HTTP error.
    #[error("HTTP error")]
    Http(#[source] http::Error),
    /// Other error.
    #[error("Other error: {}", _0)]
    Other(String),
}

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
