//! How the reader asks identity: its keys, its introspection, and the answers it keeps.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::AUTHORIZATION;
use jorisjonkers_commons::identity::{
    BoxFuture, Config, Fetch, PrincipalReader, ReadError, Refusal, Unavailable,
};
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair, RsaPublicKeyComponents};
use serde_json::{Value, json};
use support::{bearer, headers};

const SIGNED_AT: u64 = 1_792_497_600;

fn key() -> RsaKeyPair {
    RsaKeyPair::from_pkcs8(include_bytes!("testdata/signing-key.pk8.der")).unwrap()
}

fn jwks() -> Value {
    let public = RsaPublicKeyComponents::<Vec<u8>>::from(key().public());
    let b64 = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
    json!({"keys": [{"kty": "RSA", "kid": "k", "alg": "RS256", "n": b64(&public.n), "e": b64(&public.e)}]})
}

fn claims(edit: impl FnOnce(&mut serde_json::Map<String, Value>)) -> Value {
    let mut c = json!({
        "iss": "https://auth.example.test", "sub": "ada", "aud": "web", "client_id": "web",
        "exp": SIGNED_AT + 60, "ver": "1.1", "kind": "user", "via": "personal-token",
        "roles": ["user"], "two_factor": false,
    });
    edit(c.as_object_mut().unwrap());
    c
}

fn sign_with(header: &Value, payload: &[u8]) -> String {
    let head = URL_SAFE_NO_PAD.encode(header.to_string());
    let body = URL_SAFE_NO_PAD.encode(payload);
    let mut signature = vec![0; key().public().modulus_len()];
    key()
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            format!("{head}.{body}").as_bytes(),
            &mut signature,
        )
        .unwrap();
    format!("{head}.{body}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn sign(payload: &Value) -> String {
    sign_with(
        &json!({"alg": "RS256", "typ": "JWT", "kid": "k"}),
        payload.to_string().as_bytes(),
    )
}

/// identity as a Fetch, counting each question and answering what a test sets.
#[derive(Clone)]
struct Identity(Arc<State>);

struct State {
    keys: Mutex<(u16, Vec<u8>)>,
    introspection: Mutex<(u16, Vec<u8>)>,
    fails: Mutex<bool>,
    keys_fetched: AtomicUsize,
    asked: AtomicUsize,
    urls: Mutex<Vec<String>>,
}

impl Identity {
    fn new() -> Self {
        Self(Arc::new(State {
            keys: Mutex::new((200, jwks().to_string().into_bytes())),
            introspection: Mutex::new((200, br#"{"active":false}"#.to_vec())),
            fails: Mutex::new(false),
            keys_fetched: AtomicUsize::new(0),
            asked: AtomicUsize::new(0),
            urls: Mutex::default(),
        }))
    }

    fn keys(self, status: u16, body: &[u8]) -> Self {
        *self.0.keys.lock().unwrap() = (status, body.to_vec());
        self
    }

    fn introspection(&self, status: u16, body: &Value) {
        *self.0.introspection.lock().unwrap() = (status, body.to_string().into_bytes());
    }

    fn keys_fetched(&self) -> usize {
        self.0.keys_fetched.load(Ordering::SeqCst)
    }

    fn asked(&self) -> usize {
        self.0.asked.load(Ordering::SeqCst)
    }
}

impl Fetch for Identity {
    fn fetch(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> BoxFuture<'_, Result<http::Response<Vec<u8>>, Unavailable>> {
        let state = self.0.clone();
        Box::pin(async move {
            state.urls.lock().unwrap().push(request.uri().to_string());
            if *state.fails.lock().unwrap() {
                return Err(Unavailable("down".into()));
            }
            let (status, body) = if request.uri().path().ends_with("/oidc/keys") {
                state.keys_fetched.fetch_add(1, Ordering::SeqCst);
                state.keys.lock().unwrap().clone()
            } else {
                state.asked.fetch_add(1, Ordering::SeqCst);
                state.introspection.lock().unwrap().clone()
            };
            let mut response = http::Response::new(body);
            *response.status_mut() = http::StatusCode::from_u16(status).unwrap();
            Ok(response)
        })
    }
}

#[derive(Clone)]
struct Clock(Arc<Mutex<SystemTime>>);

impl Clock {
    fn at(seconds: u64) -> Self {
        Self(Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(seconds),
        )))
    }

    fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }
}

fn reader_with(identity: &Identity, clock: &Clock, secret: Option<&str>) -> PrincipalReader {
    let config = Config {
        issuer: "https://auth.example.test".into(),
        client_id: "web".into(),
        client_secret: secret.map(str::to_owned),
        ..Config::default()
    };
    let clock = clock.clone();
    PrincipalReader::with_fetch(config, identity.clone())
        .unwrap()
        .with_clock(move || *clock.0.lock().unwrap())
}

fn reader(identity: &Identity) -> PrincipalReader {
    reader_with(identity, &Clock::at(SIGNED_AT + 30), Some("s3cret"))
}

fn refusal(read: Result<jorisjonkers_commons::identity::Principal, ReadError>) -> String {
    match read.err() {
        None => "read".into(),
        Some(ReadError::Refused(r)) => r.as_str().into(),
        Some(ReadError::Unavailable(_)) => "unavailable".into(),
    }
}

fn active(edit: impl FnOnce(&mut serde_json::Map<String, Value>)) -> Value {
    claims(|c| {
        c.insert("active".into(), json!(true));
        edit(c);
    })
}

#[tokio::test]
async fn the_issuers_keys_are_fetched_once_for_every_token_they_sign() {
    let identity = Identity::new();
    let r = reader(&identity);

    for _ in 0..3 {
        r.read(&bearer(&sign(&claims(|_| {})))).await.unwrap();
    }

    assert_eq!(identity.keys_fetched(), 1);
}

#[tokio::test]
async fn the_issuers_keys_are_fetched_again_for_an_unknown_key_at_most_once_a_minute() {
    let identity = Identity::new();
    let clock = Clock::at(SIGNED_AT + 30);
    let r = reader_with(&identity, &clock, None);
    let rotated = |exp: u64| {
        let mut c = claims(|_| {});
        c["exp"] = json!(exp);
        sign_with(
            &json!({"alg": "RS256", "typ": "JWT", "kid": "rotated"}),
            c.to_string().as_bytes(),
        )
    };
    r.read(&bearer(&sign(&claims(|_| {})))).await.unwrap();
    let _ = r.read(&bearer(&rotated(SIGNED_AT + 60))).await;
    let _ = r.read(&bearer(&rotated(SIGNED_AT + 60))).await;
    clock.advance(Duration::from_secs(60));
    let _ = r.read(&bearer(&rotated(SIGNED_AT + 180))).await;

    assert_eq!(identity.keys_fetched(), 2);
}

#[tokio::test]
async fn a_key_id_the_issuer_does_not_publish_is_refused() {
    let forged = sign_with(
        &json!({"alg": "RS256", "typ": "JWT", "kid": "forged"}),
        b"{}",
    );

    assert_eq!(
        refusal(reader(&Identity::new()).read(&bearer(&forged)).await),
        "unknown-key"
    );
}

#[tokio::test]
async fn a_token_naming_no_key_id_is_refused_without_fetching_the_keys() {
    let identity = Identity::new();
    let anonymous = sign_with(&json!({"alg": "RS256", "typ": "JWT"}), b"{}");

    assert_eq!(
        refusal(reader(&identity).read(&bearer(&anonymous)).await),
        "unknown-key"
    );
    assert_eq!(identity.keys_fetched(), 0);
}

#[tokio::test]
async fn issuer_keys_that_answer_an_error_are_no_refusal() {
    let identity = Identity::new().keys(500, b"");

    assert_eq!(
        refusal(
            reader(&identity)
                .read(&bearer(&sign(&claims(|_| {}))))
                .await
        ),
        "unavailable"
    );
}

#[tokio::test]
async fn issuer_keys_that_are_no_json_are_no_refusal() {
    let identity = Identity::new().keys(200, b"not json");

    assert_eq!(
        refusal(
            reader(&identity)
                .read(&bearer(&sign(&claims(|_| {}))))
                .await
        ),
        "unavailable"
    );
}

#[tokio::test]
async fn an_rsa_key_without_its_numbers_is_no_refusal() {
    let identity = Identity::new().keys(200, br#"{"keys":[{"kty":"RSA","kid":"k"}]}"#);

    assert_eq!(
        refusal(
            reader(&identity)
                .read(&bearer(&sign(&claims(|_| {}))))
                .await
        ),
        "unavailable"
    );
}

#[tokio::test]
async fn an_rsa_key_whose_numbers_are_no_base64_is_no_refusal() {
    let identity = Identity::new().keys(
        200,
        br#"{"keys":[{"kty":"RSA","kid":"k","n":"!","e":"AQAB"}]}"#,
    );

    assert_eq!(
        refusal(
            reader(&identity)
                .read(&bearer(&sign(&claims(|_| {}))))
                .await
        ),
        "unavailable"
    );
}

#[tokio::test]
async fn issuer_keys_that_cannot_be_reached_are_no_refusal() {
    let identity = Identity::new();
    *identity.0.fails.lock().unwrap() = true;

    assert_eq!(
        refusal(
            reader(&identity)
                .read(&bearer(&sign(&claims(|_| {}))))
                .await
        ),
        "unavailable"
    );
}

#[tokio::test]
async fn issuer_keys_may_be_published_without_a_keys_list() {
    let identity = Identity::new().keys(200, b"{}");

    assert_eq!(
        refusal(
            reader(&identity)
                .read(&bearer(&sign(&claims(|_| {}))))
                .await
        ),
        "unknown-key"
    );
}

#[tokio::test]
async fn issuer_keys_that_are_not_rsa_are_passed_over() {
    let identity = Identity::new().keys(200, br#"{"keys":[{"kty":"EC","kid":"k"}]}"#);

    assert_eq!(
        refusal(
            reader(&identity)
                .read(&bearer(&sign(&claims(|_| {}))))
                .await
        ),
        "unknown-key"
    );
}

#[tokio::test]
async fn an_access_token_that_is_no_jws_is_refused() {
    assert_eq!(
        refusal(reader(&Identity::new()).read(&bearer("a.b.c")).await),
        "bad-signature"
    );
}

#[tokio::test]
async fn an_access_token_not_signed_with_rs256_is_refused() {
    let hmac = sign_with(&json!({"alg": "HS256", "typ": "JWT", "kid": "k"}), b"{}");

    assert_eq!(
        refusal(reader(&Identity::new()).read(&bearer(&hmac)).await),
        "bad-signature"
    );
}

#[tokio::test]
async fn an_access_token_whose_signature_does_not_verify_is_refused() {
    let token = sign(&claims(|_| {}));
    let tampered = format!(
        "{}.{}",
        token.rsplit_once('.').unwrap().0,
        URL_SAFE_NO_PAD.encode(b"x")
    );

    assert_eq!(
        refusal(reader(&Identity::new()).read(&bearer(&tampered)).await),
        "bad-signature"
    );
}

#[tokio::test]
async fn an_access_token_whose_signature_is_no_base64_is_refused() {
    let token = sign(&claims(|_| {}));
    let mangled = format!("{}.!", token.rsplit_once('.').unwrap().0);

    assert_eq!(
        refusal(reader(&Identity::new()).read(&bearer(&mangled)).await),
        "bad-signature"
    );
}

#[tokio::test]
async fn an_access_token_whose_signed_payload_is_no_json_object_is_refused() {
    let token = sign_with(&json!({"alg": "RS256", "typ": "JWT", "kid": "k"}), b"[1]");

    assert_eq!(
        refusal(reader(&Identity::new()).read(&bearer(&token)).await),
        "bad-signature"
    );
}

#[tokio::test]
async fn an_access_token_whose_audience_lists_only_the_apps_client_is_read() {
    let token = sign(&claims(|c| {
        c.insert("aud".into(), json!(["web"]));
    }));

    assert_eq!(
        reader(&Identity::new())
            .read(&bearer(&token))
            .await
            .unwrap()
            .subject,
        "ada"
    );
}

#[tokio::test]
async fn an_access_token_whose_audience_is_neither_a_string_nor_a_list_is_refused() {
    let token = sign(&claims(|c| {
        c.insert("aud".into(), json!(7));
    }));

    assert_eq!(
        refusal(reader(&Identity::new()).read(&bearer(&token)).await),
        "wrong-audience"
    );
}

#[tokio::test]
async fn an_access_token_stating_a_kind_v1_does_not_know_is_refused() {
    let token = sign(&claims(|c| {
        c.insert("kind".into(), json!("robot"));
    }));

    assert_eq!(
        refusal(reader(&Identity::new()).read(&bearer(&token)).await),
        "unknown-major"
    );
}

#[tokio::test]
async fn an_access_token_stating_no_roles_or_subject_holds_empty_ones() {
    let token = sign(&claims(|c| {
        c.remove("roles");
        c.remove("sub");
    }));

    let p = reader(&Identity::new())
        .read(&bearer(&token))
        .await
        .unwrap();

    assert_eq!((p.roles, p.subject), (Vec::<String>::new(), String::new()));
}

#[tokio::test]
async fn an_access_token_stating_no_ver_is_refused() {
    let token = sign(&claims(|c| {
        c.remove("ver");
    }));

    assert_eq!(
        refusal(reader(&Identity::new()).read(&bearer(&token)).await),
        "unknown-major"
    );
}

#[tokio::test]
async fn an_access_token_stating_no_expiry_is_refused() {
    let token = sign(&claims(|c| {
        c.remove("exp");
    }));

    assert_eq!(
        refusal(reader(&Identity::new()).read(&bearer(&token)).await),
        "expired"
    );
}

#[tokio::test]
async fn an_opaque_token_that_is_revoked_stops_working_within_thirty_seconds() {
    let identity = Identity::new();
    identity.introspection(200, &active(|_| {}));
    let clock = Clock::at(SIGNED_AT);
    let r = reader_with(&identity, &clock, Some("s3cret"));
    r.read(&bearer("idapp_tool")).await.unwrap();
    identity.introspection(200, &json!({"active": false}));
    clock.advance(Duration::from_secs(29));
    r.read(&bearer("idapp_tool")).await.unwrap();
    clock.advance(Duration::from_secs(1));

    assert_eq!(refusal(r.read(&bearer("idapp_tool")).await), "inactive");
}

#[tokio::test]
async fn an_opaque_token_is_asked_about_once_per_thirty_seconds() {
    let identity = Identity::new();
    identity.introspection(200, &active(|_| {}));
    let r = reader(&identity);

    for _ in 0..5 {
        r.read(&bearer("idapp_tool")).await.unwrap();
    }

    assert_eq!(identity.asked(), 1);
}

#[tokio::test]
async fn an_opaque_token_refused_once_is_refused_again_without_asking() {
    let identity = Identity::new();
    let r = reader(&identity);
    let _ = r.read(&bearer("idpat_gone")).await;

    assert_eq!(
        (
            refusal(r.read(&bearer("idpat_gone")).await),
            identity.asked()
        ),
        ("inactive".into(), 1)
    );
}

#[tokio::test]
async fn an_opaque_token_is_refused_without_asking_by_an_app_without_a_client_secret() {
    let identity = Identity::new();
    let r = reader_with(&identity, &Clock::at(SIGNED_AT), None);

    assert_eq!(
        (
            refusal(r.read(&bearer("idpat_script")).await),
            identity.asked()
        ),
        ("inactive".into(), 0)
    );
}

#[tokio::test]
async fn an_opaque_token_that_cannot_be_asked_about_is_no_refusal_and_is_asked_about_again() {
    let identity = Identity::new();
    identity.introspection(502, &json!(null));
    let r = reader(&identity);
    assert_eq!(refusal(r.read(&bearer("idapp_tool")).await), "unavailable");
    identity.introspection(200, &active(|_| {}));

    assert_eq!(r.read(&bearer("idapp_tool")).await.unwrap().subject, "ada");
}

#[tokio::test]
async fn an_introspection_answer_that_is_no_json_object_is_no_refusal() {
    let identity = Identity::new();
    identity.introspection(200, &json!([]));

    assert_eq!(
        refusal(reader(&identity).read(&bearer("idapp_tool")).await),
        "unavailable"
    );
}

#[tokio::test]
async fn the_answers_kept_are_dropped_once_ten_thousand_are_kept_so_the_first_is_asked_about_again()
{
    let identity = Identity::new();
    identity.introspection(200, &active(|_| {}));
    let r = reader(&identity);
    for i in 0..=10_000 {
        r.read(&bearer(&format!("idapp_{i}"))).await.unwrap();
    }
    let asked = identity.asked();

    r.read(&bearer("idapp_0")).await.unwrap();

    assert_eq!(identity.asked(), asked + 1);
}

#[tokio::test]
async fn a_request_without_a_bearer_token_carries_no_principal() {
    let r = reader(&Identity::new());
    let mut refusals = Vec::new();
    for authorization in [
        None,
        Some("Basic dXNlcjpwYXNz"),
        Some("Bearer "),
        Some("Bearer"),
    ] {
        let h = authorization.map_or_else(http::HeaderMap::new, |a| {
            headers(&[(AUTHORIZATION.as_str(), a)])
        });
        refusals.push(refusal(r.read(&h).await));
    }

    assert_eq!(refusals, ["missing"; 4]);
}

#[tokio::test]
async fn a_reader_asks_the_issuers_own_endpoints_by_default() {
    let identity = Identity::new();
    let config = Config {
        issuer: "https://auth.example.test/".into(),
        client_id: "web".into(),
        client_secret: Some("s3cret".into()),
        ..Config::default()
    };
    let r = PrincipalReader::with_fetch(config, identity.clone()).unwrap();
    let _ = r.read(&bearer("idpat_script")).await;
    let _ = r.read(&bearer(&sign(&claims(|_| {})))).await;

    assert_eq!(
        *identity.0.urls.lock().unwrap(),
        [
            "https://auth.example.test/oidc/introspect",
            "https://auth.example.test/oidc/keys"
        ]
    );
}

#[test]
fn a_reader_names_its_issuer_and_its_client() {
    let config = Config {
        client_id: "web".into(),
        ..Config::default()
    };

    assert!(PrincipalReader::with_fetch(config, Identity::new()).is_err());
}

#[test]
fn a_refusal_is_named_as_the_contract_names_it() {
    let refused = ReadError::Refused(Refusal::NotAnAccessToken);

    assert_eq!(
        refused.to_string(),
        "the request's Principal is refused: not-an-access-token"
    );
}

#[tokio::test]
async fn a_signed_header_that_is_no_jws_is_refused() {
    let signed = headers(&[(jorisjonkers_commons::identity::HEADER, "a.b.c.d")]);

    assert_eq!(
        refusal(reader(&Identity::new()).read(&signed).await),
        "bad-signature"
    );
}

#[tokio::test]
async fn an_empty_signed_header_is_read_as_none() {
    let signed = headers(&[(jorisjonkers_commons::identity::HEADER, "")]);

    assert_eq!(
        refusal(reader(&Identity::new()).read(&signed).await),
        "missing"
    );
}

#[test]
fn identity_being_unavailable_says_so() {
    let unavailable = ReadError::Unavailable(Unavailable("introspection answered 502".into()));

    assert_eq!(
        unavailable.to_string(),
        "identity could not be asked: introspection answered 502"
    );
}

#[cfg(feature = "reqwest")]
#[test]
fn a_reader_asks_identity_over_reqwest_by_default() {
    let config = Config {
        issuer: "https://auth.example.test".into(),
        client_id: "web".into(),
        ..Config::default()
    };

    assert!(PrincipalReader::new(config).is_ok());
}
