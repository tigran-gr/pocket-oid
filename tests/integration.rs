mod common;

#[path = "integration/admin_console.rs"]
mod admin_console;

#[path = "integration/code_flow.rs"]
mod code_flow;
#[path = "integration/email_claims.rs"]
mod email_claims;
#[path = "integration/health.rs"]
mod health;
#[path = "integration/metadata.rs"]
mod metadata;
#[path = "integration/reauth.rs"]
mod reauth;
#[path = "integration/signing.rs"]
mod signing;
#[path = "integration/token_errors.rs"]
mod token_errors;
#[path = "integration/token_success.rs"]
mod token_success;
