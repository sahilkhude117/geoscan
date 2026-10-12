use std::{future::Future, pin::Pin, time::Duration};

use reqwest::{Client, Url, header::HeaderMap};

#[derive(Clone, Debug)]
pub(super) struct Request {
    pub url: Url,
    pub origin: Option<&'static str>,
    pub factory_login: bool,
}

#[derive(Clone)]
pub(super) struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: String,
}

pub(super) type FetchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Response, String>> + Send + 'a>>;

pub(super) trait Fetch: Send + Sync {
    fn get(&self, request: Request) -> FetchFuture<'_>;
}

pub(super) struct Network(Client);

impl Network {
    pub fn new() -> Result<Self, String> {
        Client::builder()
            .user_agent("GeoScan/0.1")
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map(Self)
            .map_err(|_| "Could not initialize configuration-check HTTP client".into())
    }
}

impl Fetch for Network {
    fn get(&self, request: Request) -> FetchFuture<'_> {
        Box::pin(async move {
            let mut call = self.0.get(request.url);
            if let Some(origin) = request.origin {
                call = call.header("Origin", origin);
            }
            if request.factory_login {
                // Exactly one known factory pair; never use the operator's login.
                call = call.basic_auth("admin", Some("geoserver"));
            }
            let mut response = call
                .send()
                .await
                .map_err(|_| "HTTP request failed or timed out".to_owned())?;
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| "Could not read HTTP response".to_owned())?
            {
                if body.len() + chunk.len() > 64 * 1024 {
                    return Err("Response exceeded the 64 KiB probe limit".into());
                }
                body.extend_from_slice(&chunk);
            }
            Ok(Response {
                status,
                headers,
                body: String::from_utf8_lossy(&body).into_owned(),
            })
        })
    }
}
