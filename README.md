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

## Working on it

```bash
mise install   # the toolchain: Rust (from rust-toolchain.toml), cargo-llvm-cov, task, actionlint, gitleaks
task check     # everything CI runs
```
