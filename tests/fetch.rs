//! The default Fetch, over real HTTP against a local listener.
#![cfg(feature = "reqwest")]

use jorisjonkers_commons::identity::{Fetch, ReqwestFetch};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// identity answering one request with status and body, after echoing what it was sent.
async fn identity(
    status: &'static str,
    body: &'static str,
) -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let served = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut sent = vec![0; 4096];
        let n = socket.read(&mut sent).await.unwrap();
        let answer = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(answer.as_bytes()).await.unwrap();
        String::from_utf8_lossy(&sent[..n]).into_owned()
    });
    (url, served)
}

#[tokio::test]
async fn reqwest_fetch_sends_the_request_and_returns_identitys_answer() {
    let (url, served) = identity("200 OK", r#"{"active":false}"#).await;
    let request = http::Request::post(format!("{url}/oidc/introspect"))
        .header("Authorization", "Basic d2ViOnM=")
        .body(b"token=t".to_vec())
        .unwrap();

    let answer = ReqwestFetch::default().fetch(request).await.unwrap();
    let sent = served.await.unwrap();

    assert_eq!(answer.body(), br#"{"active":false}"#);
    assert!(
        sent.starts_with("POST /oidc/introspect")
            && sent.contains("authorization: Basic d2ViOnM=")
            && sent.ends_with("token=t")
    );
}

#[tokio::test]
async fn reqwest_fetch_returns_an_error_status_as_an_answer() {
    let (url, _served) = identity("404 Not Found", "no such keys").await;

    let answer = ReqwestFetch::default()
        .fetch(
            http::Request::get(format!("{url}/oidc/keys"))
                .body(Vec::new())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        (answer.status(), answer.body().as_slice()),
        (http::StatusCode::NOT_FOUND, b"no such keys".as_slice())
    );
}

#[tokio::test]
async fn reqwest_fetch_is_unavailable_when_nothing_answers() {
    let closed = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();

    let answer = ReqwestFetch::default()
        .fetch(
            http::Request::get(format!("http://{closed}/oidc/keys"))
                .body(Vec::new())
                .unwrap(),
        )
        .await;

    assert!(answer.is_err());
}
