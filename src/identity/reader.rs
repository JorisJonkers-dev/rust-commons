use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, Method, StatusCode};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde_json::{Map, Value};

use super::fetch::{Fetch, Unavailable};
use super::principal::{Actor, Kind, Principal, Via};

/// The Gate's signed Principal.
pub const HEADER: &str = "X-Identity-Principal";
/// The signed Principal's JWT typ, which no access token carries.
pub const TYPE: &str = "identity-principal+jwt";
/// The contract major version this crate reads.
pub const MAJOR: &str = "1";

// zitadel/oidc signs access and ID tokens alike as JWT; an access token alone names a client_id.
const ACCESS_TOKEN_TYPE: &str = "JWT";
const REFETCH_AFTER: Duration = Duration::from_secs(60);
const ANSWER_LIFETIME: Duration = Duration::from_secs(30);
const MAX_ANSWERS: usize = 10_000;

/// Why a request carries no Principal: one of the contract's refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// Neither the signed header nor a bearer token.
    Missing,
    /// A token of another typ than its channel's.
    WrongTyp,
    /// Stated by another Issuer.
    WrongIssuer,
    /// Stated for another Client than the app's own.
    WrongAudience,
    /// Past its expiry.
    Expired,
    /// Signed by a key the Issuer does not publish.
    UnknownKey,
    /// No RS256 JWS, or one whose signature does not verify.
    BadSignature,
    /// Stated in a contract major version this crate does not read.
    UnknownMajor,
    /// A JWT naming no `client_id`, such as an ID token.
    NotAnAccessToken,
    /// An opaque token identity answers inactive, or one the app has no secret to ask about.
    Inactive,
}

impl Refusal {
    /// The contract's name for this refusal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::WrongTyp => "wrong-typ",
            Self::WrongIssuer => "wrong-issuer",
            Self::WrongAudience => "wrong-audience",
            Self::Expired => "expired",
            Self::UnknownKey => "unknown-key",
            Self::BadSignature => "bad-signature",
            Self::UnknownMajor => "unknown-major",
            Self::NotAnAccessToken => "not-an-access-token",
            Self::Inactive => "inactive",
        }
    }
}

/// Why [`PrincipalReader::read`] returned no Principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The request carries no Principal; answer it 401.
    Refused(Refusal),
    /// identity could not be asked, which is no refusal; answer it 503.
    Unavailable(Unavailable),
}

impl From<Refusal> for ReadError {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

impl From<Unavailable> for ReadError {
    fn from(unavailable: Unavailable) -> Self {
        Self::Unavailable(unavailable)
    }
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(r) => write!(f, "the request's Principal is refused: {}", r.as_str()),
            Self::Unavailable(u) => u.fmt(f),
        }
    }
}

impl std::error::Error for ReadError {}

/// Where the Principals an app reads come from, and which Client the app is.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// identity's URL, as each Principal's iss states it.
    pub issuer: String,
    /// The app's own Client, which each Principal must be stated for.
    pub client_id: String,
    /// The app's Client secret, which it introspects opaque tokens with. An app without one
    /// refuses an opaque token as inactive.
    pub client_secret: Option<String>,
    /// Where the Issuer publishes its keys; the Issuer's `/oidc/keys` when None.
    pub keys_url: Option<String>,
    /// Where the Issuer answers about opaque tokens; the Issuer's `/oidc/introspect` when None.
    pub introspect_url: Option<String>,
}

type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;
type Claims = Map<String, Value>;

#[derive(Default)]
struct Keys {
    by_id: HashMap<String, RsaPublicKeyComponents<Vec<u8>>>,
    fetched: Option<SystemTime>,
}

struct Answer {
    outcome: Result<Principal, Refusal>,
    until: SystemTime,
}

/// Reads Principals for one Client.
pub struct PrincipalReader {
    config: Config,
    keys_url: String,
    introspect_url: String,
    fetch: Arc<dyn Fetch>,
    now: Clock,
    keys: tokio::sync::Mutex<Keys>,
    answers: Mutex<HashMap<[u8; 32], Answer>>,
}

impl PrincipalReader {
    /// A reader for config that asks identity with [`super::ReqwestFetch`].
    ///
    /// # Errors
    /// When config names no Issuer or no Client.
    #[cfg(feature = "reqwest")]
    pub fn new(config: Config) -> Result<Self, String> {
        Self::with_fetch(config, super::ReqwestFetch::default())
    }

    /// A reader for config that asks identity with fetch.
    ///
    /// # Errors
    /// When config names no Issuer or no Client.
    pub fn with_fetch(config: Config, fetch: impl Fetch) -> Result<Self, String> {
        if config.issuer.is_empty() || config.client_id.is_empty() {
            return Err("a PrincipalReader names its Issuer and its Client".into());
        }
        let base = config.issuer.trim_end_matches('/');
        Ok(Self {
            keys_url: config
                .keys_url
                .clone()
                .unwrap_or_else(|| format!("{base}/oidc/keys")),
            introspect_url: config
                .introspect_url
                .clone()
                .unwrap_or_else(|| format!("{base}/oidc/introspect")),
            config,
            fetch: Arc::new(fetch),
            now: Arc::new(SystemTime::now),
            keys: tokio::sync::Mutex::default(),
            answers: Mutex::default(),
        })
    }

    /// This reader, reading expiry and caches against now instead of the system clock.
    #[must_use]
    pub fn with_clock(mut self, now: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        self.now = Arc::new(now);
        self
    }

    /// The Principal a request's headers carry: the Gate's signed header when there is one, or
    /// else its bearer token, a JWT access token verified here or an opaque token introspected.
    ///
    /// # Errors
    /// [`ReadError::Refused`] saying why the request carries no Principal, or
    /// [`ReadError::Unavailable`] when identity could not be asked.
    pub async fn read(&self, headers: &HeaderMap) -> Result<Principal, ReadError> {
        if let Some(signed) = headers.get(HEADER).and_then(|v| v.to_str().ok()) {
            if !signed.is_empty() {
                let claims = self.verified(signed, TYPE).await?;
                return Ok(self.checked(&claims)?);
            }
        }
        let authorization = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let (scheme, token) = authorization.split_once(' ').unwrap_or((authorization, ""));
        if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
            return Err(Refusal::Missing.into());
        }
        if token.matches('.').count() == 2 {
            let claims = self.verified(token, ACCESS_TOKEN_TYPE).await?;
            if claims
                .get("client_id")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(Refusal::NotAnAccessToken.into());
            }
            return Ok(self.checked(&claims)?);
        }
        self.introspected(token).await
    }

    /// The claims of a JWT of typ, signed by one of the Issuer's published keys.
    async fn verified(&self, token: &str, typ: &str) -> Result<Claims, ReadError> {
        let mut parts = token.split('.');
        let (Some(head), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Refusal::BadSignature.into());
        };
        let protected = object(head).ok_or(Refusal::BadSignature)?;
        if protected.get("alg").and_then(Value::as_str) != Some("RS256") {
            return Err(Refusal::BadSignature.into());
        }
        if protected.get("typ").and_then(Value::as_str) != Some(typ) {
            return Err(Refusal::WrongTyp.into());
        }
        let kid = protected
            .get("kid")
            .and_then(Value::as_str)
            .ok_or(Refusal::UnknownKey)?;
        let key = self.key(kid).await?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| Refusal::BadSignature)?;
        key.verify(
            &RSA_PKCS1_2048_8192_SHA256,
            format!("{head}.{payload}").as_bytes(),
            &signature,
        )
        .map_err(|_| Refusal::BadSignature)?;
        Ok(object(payload).ok_or(Refusal::BadSignature)?)
    }

    /// claims' Principal, or why claims state none for this reader's Client.
    fn checked(&self, claims: &Claims) -> Result<Principal, Refusal> {
        if major(claims) != Some(MAJOR) {
            return Err(Refusal::UnknownMajor);
        }
        if claims.get("iss").and_then(Value::as_str) != Some(self.config.issuer.as_str()) {
            return Err(Refusal::WrongIssuer);
        }
        if !only(claims.get("aud"), &self.config.client_id) {
            return Err(Refusal::WrongAudience);
        }
        match claims.get("exp").and_then(Value::as_f64).and_then(instant) {
            Some(exp) if (self.now)() < exp => principal_of(claims),
            _ => Err(Refusal::Expired),
        }
    }

    /// The Issuer's published key with id kid. An id the reader does not know fetches the keys
    /// again, at most once a minute, so a rotated key is picked up and a forged id costs little.
    async fn key(&self, kid: &str) -> Result<RsaPublicKeyComponents<Vec<u8>>, ReadError> {
        let mut keys = self.keys.lock().await;
        if let Some(key) = keys.by_id.get(kid) {
            return Ok(key.clone());
        }
        let now = (self.now)();
        if keys
            .fetched
            .is_some_and(|at| now.duration_since(at).unwrap_or_default() < REFETCH_AFTER)
        {
            return Err(Refusal::UnknownKey.into());
        }
        keys.by_id = self.published_keys().await?;
        keys.fetched = Some(now);
        keys.by_id
            .get(kid)
            .cloned()
            .ok_or_else(|| Refusal::UnknownKey.into())
    }

    async fn published_keys(
        &self,
    ) -> Result<HashMap<String, RsaPublicKeyComponents<Vec<u8>>>, Unavailable> {
        let request = http::Request::get(&self.keys_url)
            .body(Vec::new())
            .map_err(unavailable)?;
        let answer = self.fetch.fetch(request).await?;
        if answer.status() != StatusCode::OK {
            return Err(Unavailable(format!(
                "the Issuer's keys answered {}",
                answer.status()
            )));
        }
        let jwks: Value = serde_json::from_slice(answer.body()).map_err(unavailable)?;
        let mut keys = HashMap::new();
        for key in jwks
            .get("keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let field = |name: &str| key.get(name).and_then(Value::as_str);
            if field("kty") != Some("RSA") {
                continue;
            }
            let (Some(kid), Some(n), Some(e)) = (field("kid"), field("n"), field("e")) else {
                return Err(Unavailable("the Issuer's keys are no JWKS".into()));
            };
            let n = URL_SAFE_NO_PAD.decode(n).map_err(unavailable)?;
            let e = URL_SAFE_NO_PAD.decode(e).map_err(unavailable)?;
            keys.insert(kid.to_owned(), RsaPublicKeyComponents { n, e });
        }
        Ok(keys)
    }

    /// The Principal identity answers for an opaque token, a Personal Token or a Connected App's,
    /// asked at most once per thirty seconds so a revoked token stops working within them.
    async fn introspected(&self, token: &str) -> Result<Principal, ReadError> {
        let Some(secret) = self
            .config
            .client_secret
            .as_deref()
            .filter(|s| !s.is_empty())
        else {
            return Err(Refusal::Inactive.into());
        };
        let mut key = [0; 32];
        key.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, token.as_bytes()).as_ref());
        let now = (self.now)();
        if let Some(kept) = self.answers().get(&key).filter(|a| now < a.until) {
            return Ok(kept.outcome.clone()?);
        }
        let claims = self.ask(token, secret).await?;
        let outcome = self.answered(&claims);
        let mut answers = self.answers();
        if answers.len() >= MAX_ANSWERS {
            answers.clear();
        }
        answers.insert(
            key,
            Answer {
                outcome: outcome.clone(),
                until: now + ANSWER_LIFETIME,
            },
        );
        Ok(outcome?)
    }

    fn answers(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Answer>> {
        self.answers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// identity's introspection answer about token (RFC 7662), the reader authenticating as its
    /// own Client.
    async fn ask(&self, token: &str, secret: &str) -> Result<Claims, Unavailable> {
        let escape = |s: &str| form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
        let credentials = format!("{}:{}", escape(&self.config.client_id), escape(secret));
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .finish();
        let request = http::Request::builder()
            .method(Method::POST)
            .uri(&self.introspect_url)
            .header(
                AUTHORIZATION,
                format!("Basic {}", STANDARD.encode(credentials)),
            )
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.into_bytes())
            .map_err(unavailable)?;
        let answer = self.fetch.fetch(request).await?;
        if answer.status() != StatusCode::OK {
            return Err(Unavailable(format!(
                "introspection answered {}",
                answer.status()
            )));
        }
        match serde_json::from_slice(answer.body()).map_err(unavailable)? {
            Value::Object(claims) => Ok(claims),
            _ => Err(Unavailable("introspection answered no JSON object".into())),
        }
    }

    /// The Principal an introspection answer states for this reader's Client.
    fn answered(&self, claims: &Claims) -> Result<Principal, Refusal> {
        if claims.get("active") != Some(&Value::Bool(true)) {
            return Err(Refusal::Inactive);
        }
        if major(claims) != Some(MAJOR) {
            return Err(Refusal::UnknownMajor);
        }
        if claims.get("client_id").and_then(Value::as_str) != Some(self.config.client_id.as_str())
            || !only(claims.get("aud"), &self.config.client_id)
        {
            return Err(Refusal::WrongAudience);
        }
        principal_of(claims)
    }
}

fn principal_of(claims: &Claims) -> Result<Principal, Refusal> {
    let text = |name: &str| claims.get(name).and_then(Value::as_str).map(str::to_owned);
    let kind = claims
        .get("kind")
        .and_then(Value::as_str)
        .and_then(Kind::from_contract);
    let via = claims
        .get("via")
        .and_then(Value::as_str)
        .and_then(Via::from_contract);
    let (Some(kind), Some(via), Some(ver)) = (kind, via, text("ver")) else {
        return Err(Refusal::UnknownMajor);
    };
    Ok(Principal {
        subject: text("sub").unwrap_or_default(),
        kind,
        email: text("email"),
        name: text("name"),
        roles: claims
            .get("roles")
            .and_then(Value::as_array)
            .map(|roles| {
                roles
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        via,
        actor: claims
            .get("act")
            .and_then(Value::as_object)
            .map(|act| Actor {
                id: act
                    .get("sub")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                name: act
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            }),
        two_factor: claims.get("two_factor") == Some(&Value::Bool(true)),
        two_factor_at: claims
            .get("two_factor_at")
            .and_then(Value::as_f64)
            .filter(|at| *at != 0.0)
            .and_then(instant),
        sid: text("sid"),
        ver,
    })
}

fn major(claims: &Claims) -> Option<&str> {
    claims
        .get("ver")
        .and_then(Value::as_str)
        .and_then(|v| v.split('.').next())
}

/// Whether aud, one Client or a list of them, names client and no other.
fn only(aud: Option<&Value>, client: &str) -> bool {
    match aud {
        Some(Value::String(one)) => one == client,
        Some(Value::Array(many)) => many.len() == 1 && many[0] == client,
        _ => false,
    }
}

fn instant(seconds: f64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::try_from_secs_f64(seconds).ok()?)
}

fn object(part: &str) -> Option<Claims> {
    match serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()? {
        Value::Object(claims) => Some(claims),
        _ => None,
    }
}

fn unavailable(e: impl std::fmt::Display) -> Unavailable {
    Unavailable(e.to_string())
}
