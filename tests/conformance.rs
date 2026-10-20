//! Every vector of the pinned contract reads as it says, through the one entry point.

mod support;

use jorisjonkers_commons::identity::{Config, HEADER, PrincipalReader};
use serde_json::Value;
use support::{Identity, bearer, expected, headers, outcome, time, vector, vectors};

fn reader_for(vector: &Value) -> PrincipalReader {
    let now = time(vector["now"].as_str().unwrap());
    let config = Config {
        issuer: vector["issuer"].as_str().unwrap().into(),
        client_id: vector["client"].as_str().unwrap().into(),
        ..Config::default()
    };
    PrincipalReader::with_fetch(config, Identity::default())
        .unwrap()
        .with_clock(move || now)
}

fn compare(
    got: &Result<jorisjonkers_commons::identity::Principal, String>,
    v: &Value,
) -> Result<(), String> {
    let want = expected(v);
    if *got == want {
        Ok(())
    } else {
        Err(format!("got {got:?}, want {want:?}"))
    }
}

#[tokio::test]
async fn every_pinned_signed_header_vector_reads_as_the_contract_says() {
    let mut failed = Vec::new();
    for (name, v) in vectors("signed-header") {
        let pairs: Vec<(String, String)> = v["headers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, val)| (k.clone(), val.as_str().unwrap().to_owned()))
            .collect();
        let pairs: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let got = outcome(reader_for(&v).read(&headers(&pairs)).await);
        if let Err(e) = compare(&got, &v) {
            failed.push(format!("{name}: {e}"));
        }
    }

    assert_eq!(failed, Vec::<String>::new());
}

#[tokio::test]
async fn every_pinned_access_token_vector_reads_as_the_contract_says() {
    let mut failed = Vec::new();
    for (name, v) in vectors("access-token") {
        let got = outcome(
            reader_for(&v)
                .read(&bearer(v["token"].as_str().unwrap()))
                .await,
        );
        if let Err(e) = compare(&got, &v) {
            failed.push(format!("{name}: {e}"));
        }
    }

    assert_eq!(failed, Vec::<String>::new());
}

#[tokio::test]
async fn every_pinned_introspection_vector_reads_as_the_contract_says() {
    let mut failed = Vec::new();
    for (name, v) in vectors("introspection") {
        let client = v["client"].as_str().unwrap().to_owned();
        let identity = Identity {
            client: client.clone(),
            secret: "s3cret".into(),
            token: "opaque".into(),
            answer: v["answer"].clone(),
        };
        let config = Config {
            issuer: "https://auth.example.test".into(),
            client_id: client,
            client_secret: Some("s3cret".into()),
            ..Config::default()
        };
        let reader = PrincipalReader::with_fetch(config, identity).unwrap();
        let got = outcome(reader.read(&bearer("opaque")).await);
        if let Err(e) = compare(&got, &v) {
            failed.push(format!("{name}: {e}"));
        }
    }

    assert_eq!(failed, Vec::<String>::new());
}

#[tokio::test]
async fn an_access_token_presented_as_the_signed_header_is_refused() {
    let v = vector("access-token", "session");
    let signed = headers(&[(HEADER, v["token"].as_str().unwrap())]);

    assert_eq!(
        outcome(reader_for(&v).read(&signed).await),
        Err("wrong-typ".into())
    );
}

#[tokio::test]
async fn a_signed_header_presented_as_a_bearer_token_is_refused() {
    let v = vector("signed-header", "session");

    assert_eq!(
        outcome(
            reader_for(&v)
                .read(&bearer(v["headers"][HEADER].as_str().unwrap()))
                .await
        ),
        Err("wrong-typ".into())
    );
}
