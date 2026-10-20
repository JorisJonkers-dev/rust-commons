//! The Principal as tower middleware, and the policy helpers guarding the routes they wrap.

mod support;

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::header::LOCATION;
use http::{Request, Response, StatusCode};
use jorisjonkers_commons::identity::{
    Actor, BoxFuture, Config, Fetch, Kind, PolicyLayer, Principal, PrincipalLayer, PrincipalReader,
    Unavailable, Via, refuse_tools, require_machine, require_recent_two_factor,
    require_recent_two_factor_at, require_role, require_user,
};
use std::task::{Context, Poll};
use support::{bearer, vector};
use tower::{Layer, ServiceExt};

const NOW: u64 = 1_792_497_630;

fn ada() -> Principal {
    Principal {
        subject: "ada".into(),
        kind: Kind::User,
        email: Some("ada@example.org".into()),
        name: Some("Ada".into()),
        roles: vec!["user".into()],
        via: Via::Session,
        actor: None,
        two_factor: false,
        two_factor_at: None,
        sid: Some("s".into()),
        ver: "1.1".into(),
    }
}

fn machine() -> Principal {
    Principal {
        kind: Kind::Machine,
        via: Via::Machine,
        sid: None,
        ..ada()
    }
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

/// A handler recording the Principal it is passed.
#[derive(Clone, Default)]
struct Handler(Arc<Mutex<Option<Principal>>>);

impl tower::Service<Request<()>> for Handler {
    type Response = Response<()>;
    type Error = Infallible;
    type Future = std::future::Ready<Result<Response<()>, Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<()>) -> Self::Future {
        *self.0.lock().unwrap() = request.extensions().get::<Principal>().cloned();
        std::future::ready(Ok(Response::new(())))
    }
}

/// What layer, wrapped around a handler, did with request: the status and Location it answered,
/// and the Principal the handler saw if it was passed on.
async fn serve<L>(layer: L, request: Request<()>) -> (StatusCode, Option<String>, Option<Principal>)
where
    L: Layer<Handler>,
    L::Service: tower::Service<Request<()>, Response = Response<()>, Error = Infallible>,
{
    let handler = Handler::default();
    let response = layer.layer(handler.clone()).oneshot(request).await.unwrap();
    let location = response
        .headers()
        .get(LOCATION)
        .map(|l| l.to_str().unwrap().to_owned());
    let principal = handler.0.lock().unwrap().take();
    (response.status(), location, principal)
}

fn carrying(principal: Option<Principal>, uri: &str) -> Request<()> {
    let mut request = Request::builder().uri(uri).body(()).unwrap();
    if let Some(p) = principal {
        request.extensions_mut().insert(p);
    }
    request
}

async fn status(policy: PolicyLayer, principal: Option<Principal>) -> StatusCode {
    serve(policy, carrying(principal, "/")).await.0
}

/// identity that cannot be asked.
struct Down;

impl Fetch for Down {
    fn fetch(
        &self,
        _: http::Request<Vec<u8>>,
    ) -> BoxFuture<'_, Result<http::Response<Vec<u8>>, Unavailable>> {
        Box::pin(async { Err(Unavailable("down".into())) })
    }
}

fn reading(fetch: impl Fetch, now: SystemTime) -> PrincipalLayer {
    let config = Config {
        issuer: "https://auth.example.test".into(),
        client_id: "wiki".into(),
        ..Config::default()
    };
    PrincipalLayer::new(
        PrincipalReader::with_fetch(config, fetch)
            .unwrap()
            .with_clock(move || now),
    )
}

fn signed_session() -> Request<()> {
    let v = vector("signed-header", "session");
    let mut request = Request::builder().uri("/").body(()).unwrap();
    for (name, value) in v["headers"].as_object().unwrap() {
        request.headers_mut().insert(
            http::HeaderName::try_from(name.as_str()).unwrap(),
            value.as_str().unwrap().parse().unwrap(),
        );
    }
    request
}

#[tokio::test]
async fn the_middleware_passes_the_principal_on_to_the_handler() {
    let now = support::time(vector("signed-header", "session")["now"].as_str().unwrap());

    let (_, _, seen) = serve(reading(support::Identity::default(), now), signed_session()).await;

    assert_eq!(
        seen.map(|p| p.subject),
        Some("00000000-0000-4000-8000-0000000000a1".into())
    );
}

#[tokio::test]
async fn the_middleware_answers_401_to_a_refused_request() {
    let (status, _, seen) = serve(reading(Down, at(NOW)), carrying(None, "/")).await;

    assert_eq!((status, seen), (StatusCode::UNAUTHORIZED, None));
}

#[tokio::test]
async fn the_middleware_answers_503_when_identity_cannot_be_asked() {
    let mut request = carrying(None, "/");
    *request.headers_mut() = bearer(vector("access-token", "session")["token"].as_str().unwrap());

    let (status, _, seen) = serve(reading(Down, at(NOW)), request).await;

    assert_eq!((status, seen), (StatusCode::SERVICE_UNAVAILABLE, None));
}

#[tokio::test]
async fn require_role_lets_through_a_caller_holding_the_generated_role() {
    let editor = Principal {
        roles: vec!["editor".into()],
        ..ada()
    };

    assert_eq!(
        status(require_role("editor"), Some(editor)).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn require_role_answers_403_to_a_caller_without_the_role() {
    assert_eq!(
        status(require_role("editor"), Some(ada())).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn refuse_tools_answers_403_to_a_tool_acting_for_a_user() {
    let tool = Principal {
        via: Via::Tool,
        actor: Some(Actor {
            id: "mcp_1".into(),
            name: "Claude Code".into(),
        }),
        sid: None,
        ..ada()
    };

    assert_eq!(
        status(refuse_tools(), Some(tool)).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn refuse_tools_lets_the_user_themselves_through() {
    assert_eq!(status(refuse_tools(), Some(ada())).await, StatusCode::OK);
}

#[tokio::test]
async fn require_user_answers_403_to_a_machine() {
    assert_eq!(
        status(require_user(), Some(machine())).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn require_user_lets_a_person_through() {
    assert_eq!(status(require_user(), Some(ada())).await, StatusCode::OK);
}

#[tokio::test]
async fn require_machine_answers_403_to_a_person() {
    assert_eq!(
        status(require_machine(), Some(ada())).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn require_machine_lets_a_machine_through() {
    assert_eq!(
        status(require_machine(), Some(machine())).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_policy_answers_401_without_a_principal() {
    let mut statuses = Vec::new();
    for policy in [
        require_role("user"),
        refuse_tools(),
        require_user(),
        require_machine(),
        require_recent_two_factor(5),
    ] {
        statuses.push(status(policy, None).await);
    }

    assert_eq!(statuses, [StatusCode::UNAUTHORIZED; 5]);
}

#[tokio::test]
async fn require_recent_two_factor_lets_a_fresh_enough_proof_through() {
    let proved = Principal {
        two_factor: true,
        two_factor_at: Some(at(NOW - 240)),
        ..ada()
    };

    assert_eq!(
        status(require_recent_two_factor_at(5, || at(NOW)), Some(proved)).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn require_recent_two_factor_sends_a_stale_session_to_step_up_and_back_to_the_same_page() {
    let stale = Principal {
        two_factor: true,
        two_factor_at: Some(at(NOW - 360)),
        ..ada()
    };

    let (status, location, _) = serve(
        require_recent_two_factor_at(5, || at(NOW)),
        carrying(Some(stale), "/pay?amount=3"),
    )
    .await;

    assert_eq!(
        (status, location.as_deref()),
        (
            StatusCode::SEE_OTHER,
            Some("/.auth/step-up?minutes=5&rd=%2Fpay%3Famount%3D3")
        )
    );
}

#[tokio::test]
async fn require_recent_two_factor_sends_a_session_with_no_proof_to_step_up() {
    let (_, location, _) = serve(require_recent_two_factor(5), carrying(Some(ada()), "/")).await;

    assert_eq!(location.as_deref(), Some("/.auth/step-up?minutes=5&rd=%2F"));
}

#[tokio::test]
async fn require_recent_two_factor_answers_403_to_a_personal_token_it_cannot_step_up() {
    let token = Principal {
        via: Via::PersonalToken,
        sid: None,
        ..ada()
    };

    assert_eq!(
        status(require_recent_two_factor(5), Some(token)).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn require_recent_two_factor_reads_the_real_time_when_given_no_clock() {
    let proved = Principal {
        two_factor: true,
        two_factor_at: Some(SystemTime::now()),
        ..ada()
    };

    assert_eq!(
        status(require_recent_two_factor(5), Some(proved)).await,
        StatusCode::OK
    );
}
