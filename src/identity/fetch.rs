use std::future::Future;
use std::pin::Pin;

/// A boxed future, as [`Fetch`] and the tower services return.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// identity did not answer: its keys or its introspection could not be had.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unavailable(pub String);

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "identity could not be asked: {}", self.0)
    }
}

impl std::error::Error for Unavailable {}

/// Sends a request to identity and returns its answer, whatever its status.
pub trait Fetch: Send + Sync + 'static {
    /// identity's answer to request, or [`Unavailable`] when identity does not answer at all.
    fn fetch(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> BoxFuture<'_, Result<http::Response<Vec<u8>>, Unavailable>>;
}

/// The default [`Fetch`], over reqwest with rustls.
#[cfg(feature = "reqwest")]
#[derive(Clone, Debug, Default)]
pub struct ReqwestFetch(pub reqwest::Client);

#[cfg(feature = "reqwest")]
impl Fetch for ReqwestFetch {
    fn fetch(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> BoxFuture<'_, Result<http::Response<Vec<u8>>, Unavailable>> {
        Box::pin(async move {
            let url = request.uri().to_string();
            let sent = reqwest::Request::try_from(request.map(reqwest::Body::from))
                .map_err(|e| Unavailable(format!("{url}: {e}")))?;
            let answer = self
                .0
                .execute(sent)
                .await
                .map_err(|e| Unavailable(format!("{url}: {e}")))?;
            let status = answer.status();
            let body = answer
                .bytes()
                .await
                .map_err(|e| Unavailable(format!("{url}: {e}")))?;
            let mut response = http::Response::new(body.to_vec());
            *response.status_mut() = status;
            Ok(response)
        })
    }
}
