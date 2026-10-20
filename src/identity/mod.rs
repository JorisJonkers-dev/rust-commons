//! Reads who is calling an app from identity's Principal contract
//! (github.com/JorisJonkers-dev/identity/contract/principal): the Gate's signed header, verified
//! against the Issuer's published keys, never the plain `X-Auth-Request-*` headers beside it.
//!
//! [`PrincipalReader::read`] is the one entry point. [`PrincipalLayer`] reads each request's
//! Principal as tower middleware, for axum or any tower service, and the policy helpers guard the
//! routes they wrap.

mod fetch;
mod layer;
mod principal;
mod reader;

#[cfg(feature = "reqwest")]
pub use fetch::ReqwestFetch;
pub use fetch::{BoxFuture, Fetch, Unavailable};
pub use layer::{
    PolicyLayer, PolicyService, PrincipalLayer, PrincipalService, STEP_UP_PATH, refuse_tools,
    require_machine, require_recent_two_factor, require_recent_two_factor_at, require_role,
    require_user,
};
pub use principal::{Actor, Kind, Principal, Via};
pub use reader::{Config, HEADER, MAJOR, PrincipalReader, ReadError, Refusal, TYPE};
