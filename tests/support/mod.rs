//! The pinned contract, vendored by scripts/pin-contract.sh, and identity as a Fetch serving it.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::header::AUTHORIZATION;
use http::{HeaderMap, HeaderName, HeaderValue};
use jorisjonkers_commons::identity::{
    Actor, BoxFuture, Fetch, Kind, Principal, ReadError, Unavailable, Via,
};
use serde_json::Value;

pub fn contract() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("contract")
}

/// Every vector of a channel, by name.
pub fn vectors(channel: &str) -> Vec<(String, Value)> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(contract().join("vectors").join(channel))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let name = path.file_stem().unwrap().to_string_lossy().into_owned();
            (
                name,
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap(),
            )
        })
        .collect()
}

pub fn vector(channel: &str, name: &str) -> Value {
    vectors(channel)
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap()
        .1
}

pub fn time(rfc3339: &str) -> SystemTime {
    humantime::parse_rfc3339(rfc3339).unwrap()
}

/// The Principal a vector states, as the contract's JSON names it.
pub fn principal_from(stated: &Value) -> Principal {
    let text = |name: &str| stated[name].as_str().map(str::to_owned);
    Principal {
        subject: text("subject").unwrap(),
        kind: Kind::from_contract(stated["kind"].as_str().unwrap()).unwrap(),
        email: text("email"),
        name: text("name"),
        roles: stated["roles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_owned())
            .collect(),
        via: Via::from_contract(stated["via"].as_str().unwrap()).unwrap(),
        actor: stated["actor"].as_object().map(|a| Actor {
            id: a["id"].as_str().unwrap().to_owned(),
            name: a["name"].as_str().unwrap().to_owned(),
        }),
        two_factor: stated["twoFactor"].as_bool().unwrap(),
        two_factor_at: stated["twoFactorAt"].as_str().map(time),
        sid: text("sid"),
        ver: text("ver").unwrap(),
    }
}

/// What a vector expects: its Principal, or its refusal's name.
pub fn expected(vector: &Value) -> Result<Principal, String> {
    match vector["refusal"].as_str() {
        Some(refusal) => Err(refusal.to_owned()),
        None => Ok(principal_from(&vector["principal"])),
    }
}

/// What a read came to, in a vector's terms.
pub fn outcome(read: Result<Principal, ReadError>) -> Result<Principal, String> {
    read.map_err(|e| match e {
        ReadError::Refused(r) => r.as_str().to_owned(),
        ReadError::Unavailable(u) => format!("unavailable: {u}"),
    })
}

pub fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    pairs
        .iter()
        .map(|(n, v)| {
            (
                HeaderName::try_from(*n).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            )
        })
        .collect()
}

pub fn bearer(token: &str) -> HeaderMap {
    headers(&[(AUTHORIZATION.as_str(), &format!("Bearer {token}"))])
}

/// identity as a Fetch: its published keys, and an introspection answer for one Client and token.
#[derive(Default)]
pub struct Identity {
    pub client: String,
    pub secret: String,
    pub token: String,
    pub answer: Value,
}

impl Fetch for Identity {
    fn fetch(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> BoxFuture<'_, Result<http::Response<Vec<u8>>, Unavailable>> {
        let credentials = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.client, self.secret))
        );
        let response = if request.uri().path().ends_with("/oidc/keys") {
            http::Response::new(std::fs::read(contract().join("vectors/jwks.json")).unwrap())
        } else {
            let asked = form_urlencoded::parse(request.body())
                .find(|(k, _)| k == "token")
                .map(|(_, v)| v.into_owned());
            if request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                == Some(credentials.as_str())
                && asked.as_deref() == Some(self.token.as_str())
            {
                http::Response::new(serde_json::to_vec(&self.answer).unwrap())
            } else {
                let mut refused = http::Response::new(Vec::new());
                *refused.status_mut() = http::StatusCode::UNAUTHORIZED;
                refused
            }
        };
        Box::pin(async move { Ok(response) })
    }
}
