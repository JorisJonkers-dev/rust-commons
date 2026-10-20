# rust-commons

Shared Rust code for estate services, released together as the `jorisjonkers-commons` crate.

| module | what it does |
|---|---|
| `jorisjonkers_commons::identity` | reads who is calling from identity's Principal contract: the Gate's signed header, access tokens and introspected opaque tokens, plus the policy helpers that guard routes |

## Using it

Pin an exact release tag; nothing resolves from `main` (see [VERSIONING.md](VERSIONING.md)):

```toml
[dependencies]
jorisjonkers-commons = { git = "https://github.com/JorisJonkers-dev/rust-commons", tag = "v0.1.0" }
```

## identity

`PrincipalReader::read` is the one entry point: it takes a request's headers and returns the
`Principal`, or `ReadError::Refused` with the contract's reason. It reads the Gate's signed
`X-Identity-Principal` header and never the plain `X-Auth-Request-*` ones; without it, it verifies a
JWT access token against the Issuer's keys or introspects an opaque token, keeping each answer for
30 seconds. `ReadError::Unavailable` means identity could not be asked, which is not a refusal.

The middleware and the policy helpers are tower layers, so they wrap an axum router or any one of
its routes, and a handler takes the Principal as `Extension<Principal>`:

```rust
use jorisjonkers_commons::identity::{Config, PrincipalLayer, PrincipalReader, require_role};

let reader = PrincipalReader::new(Config {
    issuer: "https://auth.jorisjonkers.dev".into(),
    client_id: "wiki".into(),
    client_secret: Some(secret),
    ..Config::default()
})?;
let app = Router::new()
    .route("/admin", get(admin).layer(require_role("admin"))) // 403 without the role
    .layer(PrincipalLayer::new(reader)); // 401 when refused, 503 when identity is down
```

`require_recent_two_factor(minutes)` sends a stale session 303 to the Gate's step-up and answers a
token 403; `refuse_tools`, `require_user` and `require_machine` answer 403 for the case they refuse.

The Principal type is generated from the contract pinned in `contract/`. To move to a new contract
release, pin it and regenerate:

```bash
scripts/pin-contract.sh contract/principal/v1.1.0
PRINCIPAL_UPDATE=true task test
```

## Working on it

```bash
mise install   # the toolchain: Rust, cargo-llvm-cov, task, actionlint, gitleaks
task check     # everything CI runs
```
