use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use http::header::LOCATION;
use http::{Request, Response, StatusCode, Uri};
use tower_layer::Layer;
use tower_service::Service;

use super::fetch::BoxFuture;
use super::principal::{Kind, Principal, Via};
use super::reader::{PrincipalReader, ReadError};

/// The Gate's step-up on the app's own host, which proves two-factor again and comes back.
pub const STEP_UP_PATH: &str = "/.auth/step-up";

/// Reads each request's Principal and passes it on in the request's extensions, where axum's
/// `Extension<Principal>` finds it. A request whose Principal is refused is answered 401, and one
/// identity could not be asked about 503.
#[derive(Clone)]
pub struct PrincipalLayer {
    reader: Arc<PrincipalReader>,
}

impl PrincipalLayer {
    /// The layer reading Principals with reader.
    #[must_use]
    pub fn new(reader: PrincipalReader) -> Self {
        Self {
            reader: Arc::new(reader),
        }
    }
}

impl<S> Layer<S> for PrincipalLayer {
    type Service = PrincipalService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PrincipalService {
            reader: self.reader.clone(),
            inner,
        }
    }
}

/// The service [`PrincipalLayer`] wraps around an app.
#[derive(Clone)]
pub struct PrincipalService<S> {
    reader: Arc<PrincipalReader>,
    inner: S,
}

impl<S, B, R> Service<Request<B>> for PrincipalService<S>
where
    S: Service<Request<B>, Response = Response<R>> + Clone + Send + 'static,
    S::Future: Send,
    B: Send + 'static,
    R: Default,
{
    type Response = Response<R>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response<R>, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let reader = self.reader.clone();
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            match reader.read(request.headers()).await {
                Ok(principal) => {
                    request.extensions_mut().insert(principal);
                    inner.call(request).await
                }
                Err(ReadError::Refused(_)) => Ok(answer(StatusCode::UNAUTHORIZED, None)),
                Err(ReadError::Unavailable(_)) => Ok(answer(StatusCode::SERVICE_UNAVAILABLE, None)),
            }
        })
    }
}

/// What a policy answers a request it does not let through.
enum Turned {
    Away(StatusCode),
    ToStepUp(String),
}

type Decide = dyn Fn(&Principal, &Uri) -> Result<(), Turned> + Send + Sync;

/// A policy helper: it lets a request through when its Principal passes, answers 403 or sends it
/// to step-up when it does not, and 401 when the request carries no Principal.
#[derive(Clone)]
pub struct PolicyLayer {
    decide: Arc<Decide>,
}

impl<S> Layer<S> for PolicyLayer {
    type Service = PolicyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PolicyService {
            decide: self.decide.clone(),
            inner,
        }
    }
}

/// The service a [`PolicyLayer`] wraps around a route.
#[derive(Clone)]
pub struct PolicyService<S> {
    decide: Arc<Decide>,
    inner: S,
}

impl<S, B, R> Service<Request<B>> for PolicyService<S>
where
    S: Service<Request<B>, Response = Response<R>> + Clone + Send + 'static,
    S::Future: Send,
    B: Send + 'static,
    R: Default,
{
    type Response = Response<R>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response<R>, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let decided = match request.extensions().get::<Principal>() {
            None => Err(Turned::Away(StatusCode::UNAUTHORIZED)),
            Some(principal) => (self.decide)(principal, request.uri()),
        };
        match decided {
            Ok(()) => {
                let clone = self.inner.clone();
                let mut inner = std::mem::replace(&mut self.inner, clone);
                Box::pin(async move { inner.call(request).await })
            }
            Err(Turned::Away(status)) => Box::pin(async move { Ok(answer(status, None)) }),
            Err(Turned::ToStepUp(location)) => {
                Box::pin(async move { Ok(answer(StatusCode::SEE_OTHER, Some(location))) })
            }
        }
    }
}

fn guard(allow: impl Fn(&Principal) -> bool + Send + Sync + 'static) -> PolicyLayer {
    PolicyLayer {
        decide: Arc::new(move |principal, _| {
            if allow(principal) {
                Ok(())
            } else {
                Err(Turned::Away(StatusCode::FORBIDDEN))
            }
        }),
    }
}

/// Lets through a caller holding role on the app's Client. It takes the App Roles deploy-kit
/// generates as readily as a plain string.
pub fn require_role(role: impl AsRef<str>) -> PolicyLayer {
    let role = role.as_ref().to_owned();
    guard(move |p| p.roles.contains(&role))
}

/// Turns away a tool acting for a User, so a tool can read but never, say, delete.
#[must_use]
pub fn refuse_tools() -> PolicyLayer {
    guard(|p| p.via != Via::Tool)
}

/// Lets through only a person, never a Machine Identity.
#[must_use]
pub fn require_user() -> PolicyLayer {
    guard(|p| p.kind == Kind::User)
}

/// Lets through only a Machine Identity, never a person.
#[must_use]
pub fn require_machine() -> PolicyLayer {
    guard(|p| p.kind == Kind::Machine)
}

/// Lets through a session that proved two-factor within minutes. A session whose proof is older,
/// or that has none, is sent to the Gate's step-up on the app's own host and comes back to the
/// same page; a Personal Token, a tool or a machine, which no browser carries through a step-up,
/// is answered 403.
#[must_use]
pub fn require_recent_two_factor(minutes: u64) -> PolicyLayer {
    require_recent_two_factor_at(minutes, SystemTime::now)
}

/// [`require_recent_two_factor`], reading the time from now.
pub fn require_recent_two_factor_at(
    minutes: u64,
    now: impl Fn() -> SystemTime + Send + Sync + 'static,
) -> PolicyLayer {
    let window = Duration::from_secs(minutes * 60);
    PolicyLayer {
        decide: Arc::new(move |principal, uri| {
            let fresh = principal
                .two_factor_at
                .is_some_and(|at| now().duration_since(at).unwrap_or_default() <= window);
            if fresh {
                return Ok(());
            }
            if principal.via != Via::Session {
                return Err(Turned::Away(StatusCode::FORBIDDEN));
            }
            let rd = uri.path_and_query().map_or("/", |pq| pq.as_str());
            let query = form_urlencoded::Serializer::new(String::new())
                .append_pair("minutes", &minutes.to_string())
                .append_pair("rd", rd)
                .finish();
            Err(Turned::ToStepUp(format!("{STEP_UP_PATH}?{query}")))
        }),
    }
}

fn answer<R: Default>(status: StatusCode, location: Option<String>) -> Response<R> {
    let mut response = Response::new(R::default());
    *response.status_mut() = status;
    if let Some(location) = location.and_then(|l| l.parse().ok()) {
        response.headers_mut().insert(LOCATION, location);
    }
    response
}
