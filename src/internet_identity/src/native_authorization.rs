//! Native authorization request lifecycle and validation.
//! This keeps the request state short-lived and reuses existing delegation logic.

use crate::account_management;
use crate::authz_utils::{check_authz_and_record_activity, IdentityUpdateError};
use crate::state;
use crate::state::native_authorization::{
    CompletedNativeAuthorization, NativeAuthorizationRecord, NativeAuthorizationStatus,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ic_cdk::api::time;
use internet_identity_interface::internet_identity::types::{
    CompleteNativeAuthorizationError, CompleteNativeAuthorizationResponse,
    FetchNativeDelegationResponse, GetNativeAuthorizationRequestError, NativeAuthorizationRequest,
    NativeSignedDelegation, PrepareNativeAuthorizationError, PrepareNativeAuthorizationRequest,
    PrepareNativeAuthorizationResponse,
};

const REQUEST_ID_NUM_BYTES: usize = 32;
const HTTPS_URL_MAX_BYTES: usize = 512;

pub async fn prepare(
    request: PrepareNativeAuthorizationRequest,
) -> Result<PrepareNativeAuthorizationResponse, PrepareNativeAuthorizationError> {
    validate_origin(&request.origin).map_err(PrepareNativeAuthorizationError::InvalidOrigin)?;
    validate_ii_origin(&request.ii_origin)
        .map_err(PrepareNativeAuthorizationError::InvalidOrigin)?;
    validate_return_link(&request.return_link)
        .map_err(PrepareNativeAuthorizationError::InvalidReturnLink)?;
    let ii_origin = request.ii_origin.trim_end_matches('/').to_string();

    let request_id = random_request_id().await.map_err(|err| {
        PrepareNativeAuthorizationError::InternalCanisterError(format!(
            "failed to generate request id: {err}"
        ))
    })?;
    let expires_at = time().saturating_add(
        request
            .max_time_to_live
            .unwrap_or(crate::delegation::DEFAULT_EXPIRATION_PERIOD_NS)
            .min(crate::delegation::MAX_EXPIRATION_PERIOD_NS),
    );
    let record = NativeAuthorizationRecord {
        origin: request.origin,
        session_public_key: request.session_public_key,
        return_link: request.return_link,
        max_time_to_live: request.max_time_to_live,
        expires_at,
        status: NativeAuthorizationStatus::Pending,
    };

    state::native_authorizations_mut(|native_authorizations| {
        native_authorizations.prune_expired(time());
        native_authorizations
            .insert(request_id.clone(), record)
            .map_err(|()| PrepareNativeAuthorizationError::TooManyRequests)
    })?;

    Ok(PrepareNativeAuthorizationResponse {
        authorize_url: format!("{ii_origin}/authorize?native_request_id={request_id}"),
        request_id,
        expires_at,
    })
}

pub fn get_request(
    request_id: &str,
) -> Result<NativeAuthorizationRequest, GetNativeAuthorizationRequestError> {
    let now = time();
    let Some(record) = state::native_authorizations(|native_authorizations| {
        native_authorizations.get(request_id).cloned()
    }) else {
        return Err(GetNativeAuthorizationRequestError::NotFound);
    };
    if record.expires_at <= now {
        return Err(GetNativeAuthorizationRequestError::Expired);
    }
    match record.status {
        NativeAuthorizationStatus::Pending => Ok(NativeAuthorizationRequest {
            origin: record.origin,
            session_public_key: record.session_public_key,
            max_time_to_live: record.max_time_to_live,
        }),
        NativeAuthorizationStatus::Completed(_) => {
            Err(GetNativeAuthorizationRequestError::AlreadyCompleted)
        }
    }
}

pub async fn complete(
    anchor_number: u64,
    request_id: &str,
    account_number: Option<u64>,
) -> Result<CompleteNativeAuthorizationResponse, CompleteNativeAuthorizationError> {
    let ii_domain =
        check_authz_and_record_activity(anchor_number).map_err(map_identity_update_err)?;
    let Some(record) = state::native_authorizations(|native_authorizations| {
        native_authorizations.get(request_id).cloned()
    }) else {
        return Err(CompleteNativeAuthorizationError::NotFound);
    };
    if record.expires_at <= time() {
        return Err(CompleteNativeAuthorizationError::Expired);
    }
    if matches!(record.status, NativeAuthorizationStatus::Completed(_)) {
        return Err(CompleteNativeAuthorizationError::AlreadyCompleted);
    }

    let prepared = account_management::prepare_account_delegation(
        anchor_number,
        record.origin.clone(),
        account_number,
        record.session_public_key.clone(),
        record.max_time_to_live,
        &ii_domain,
    )
    .await
    .map_err(|err| CompleteNativeAuthorizationError::InternalCanisterError(format!("{err:?}")))?;

    let redirect_url = format!("{}?native_request_id={request_id}", record.return_link);
    let completed = CompletedNativeAuthorization {
        anchor_number,
        account_number,
        user_key: prepared.user_key,
        expiration: prepared.expiration,
    };

    state::native_authorizations_mut(|native_authorizations| {
        native_authorizations.prune_expired(time());
        let Some(record) = native_authorizations.get_mut(request_id) else {
            return Err(CompleteNativeAuthorizationError::NotFound);
        };
        if record.expires_at <= time() {
            return Err(CompleteNativeAuthorizationError::Expired);
        }
        if matches!(record.status, NativeAuthorizationStatus::Completed(_)) {
            return Err(CompleteNativeAuthorizationError::AlreadyCompleted);
        }
        record.status = NativeAuthorizationStatus::Completed(completed);
        Ok(())
    })?;

    Ok(CompleteNativeAuthorizationResponse { redirect_url })
}

pub fn fetch(request_id: &str) -> FetchNativeDelegationResponse {
    let now = time();
    let Some(record) = state::native_authorizations(|native_authorizations| {
        native_authorizations.get(request_id).cloned()
    }) else {
        return FetchNativeDelegationResponse::NotFound;
    };
    if record.expires_at <= now {
        return FetchNativeDelegationResponse::Expired;
    }
    match record.status {
        NativeAuthorizationStatus::Pending => FetchNativeDelegationResponse::Pending,
        NativeAuthorizationStatus::Completed(completed) => {
            account_management::get_account_delegation(
                completed.anchor_number,
                &record.origin,
                completed.account_number,
                record.session_public_key,
                completed.expiration,
            )
            .map(|signed_delegation| {
                FetchNativeDelegationResponse::SignedDelegation(NativeSignedDelegation {
                    user_key: completed.user_key,
                    signed_delegation,
                })
            })
            .unwrap_or(FetchNativeDelegationResponse::NotFound)
        }
    }
}

fn validate_return_link(return_link: &str) -> Result<(), String> {
    validate_https_url_like(return_link, "return link")
}

fn validate_ii_origin(ii_origin: &str) -> Result<(), String> {
    validate_https_url_like(ii_origin, "ii origin")
}

fn validate_https_url_like(url: &str, field_name: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err(format!("{field_name} must not be empty"));
    }
    if url.len() > HTTPS_URL_MAX_BYTES {
        return Err(format!(
            "{field_name} must not exceed {HTTPS_URL_MAX_BYTES} bytes"
        ));
    }
    if !url.starts_with("https://") {
        return Err(format!("{field_name} must start with `https://`"));
    }
    if url.contains('?') {
        return Err(format!("{field_name} must not contain '?'"));
    }
    if url.contains('#') {
        return Err(format!("{field_name} must not contain '#'"));
    }
    if url.bytes().any(|byte| byte <= b' ') {
        return Err(format!("{field_name} must not contain control characters"));
    }

    let remainder = &url["https://".len()..];
    let authority = remainder.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return Err(format!("{field_name} must include a host"));
    }
    let (host, port) = split_host_and_port(authority)
        .ok_or_else(|| format!("{field_name} must include a valid host"))?;
    if host.is_empty() {
        return Err(format!("{field_name} must include a host"));
    }
    if host == "." || host == ".." {
        return Err(format!("{field_name} must include a valid host"));
    }
    if host.starts_with('.') || host.ends_with('.') {
        return Err(format!("{field_name} must include a valid host"));
    }
    validate_port(port, field_name)?;

    Ok(())
}

fn split_host_and_port(authority: &str) -> Option<(&str, Option<&str>)> {
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    if let Some(stripped) = host_port.strip_prefix('[') {
        let (host, remainder) = stripped.split_once(']')?;
        if remainder.is_empty() {
            return Some((host, None));
        }
        let port = remainder.strip_prefix(':')?;
        return Some((host, Some(port)));
    }
    match host_port.split_once(':') {
        Some((host, port)) => Some((host, Some(port))),
        None => Some((host_port, None)),
    }
}

fn validate_port(port: Option<&str>, field_name: &str) -> Result<(), String> {
    let Some(port) = port else {
        return Ok(());
    };
    if port.is_empty() {
        return Err(format!("{field_name} must include a valid port"));
    }
    if !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{field_name} must include a valid port"));
    }
    let parsed_port = port
        .parse::<u16>()
        .map_err(|_| format!("{field_name} must include a valid port"))?;
    if parsed_port == 0 {
        return Err(format!("{field_name} must include a valid port"));
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<(), String> {
    if origin.is_empty() {
        return Err("origin must not be empty".to_string());
    }
    if origin.len() > 255 {
        return Err("origin must not exceed 255 bytes".to_string());
    }
    Ok(())
}

async fn random_request_id() -> Result<String, String> {
    let randomness = crate::random_salt().await;
    Ok(URL_SAFE_NO_PAD.encode(&randomness[..REQUEST_ID_NUM_BYTES]))
}

fn map_identity_update_err(err: IdentityUpdateError) -> CompleteNativeAuthorizationError {
    match err {
        IdentityUpdateError::Unauthorized(principal) => {
            CompleteNativeAuthorizationError::Unauthorized(principal)
        }
        IdentityUpdateError::StorageError(_, storage_error) => {
            CompleteNativeAuthorizationError::InternalCanisterError(storage_error.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_ii_origin, validate_return_link};

    #[test]
    fn should_reject_invalid_return_links() {
        for return_link in [
            "",
            "http://example.com",
            "https://",
            "https:///callback",
            "https://example.com?foo=bar",
            "https://example.com#foo",
            "https://example.com\nnext",
        ] {
            assert!(validate_return_link(return_link).is_err());
        }
    }

    #[test]
    fn should_accept_https_return_link_without_query_or_fragment() {
        assert!(validate_return_link("https://example.com/native/return").is_ok());
    }

    #[test]
    fn should_reject_invalid_ii_origins() {
        for ii_origin in [
            "",
            "http://example.com",
            "https://",
            "https:///authorize",
            "https://identity.test:notaport",
            "https://identity.test:",
            "https://identity.test:99999",
            "https://[::1]:notaport",
            "https://example.com?foo=bar",
            "https://example.com#foo",
            "https://example.com\nnext",
        ] {
            assert!(validate_ii_origin(ii_origin).is_err());
        }
    }

    #[test]
    fn should_accept_valid_ii_origin() {
        assert!(validate_ii_origin("https://identity.example.com").is_ok());
        assert!(validate_ii_origin("https://identity.example.com:4943").is_ok());
        assert!(validate_ii_origin("https://[::1]:4943").is_ok());
    }

    #[test]
    fn should_reject_invalid_return_link_ports() {
        for return_link in [
            "https://app.example.com:notaport/callback",
            "https://app.example.com:/callback",
            "https://app.example.com:99999/callback",
            "https://[::1]:notaport/callback",
        ] {
            assert!(validate_return_link(return_link).is_err());
        }
    }

    #[test]
    fn should_accept_valid_return_link_ports() {
        assert!(validate_return_link("https://app.example.com:443/callback").is_ok());
        assert!(validate_return_link("https://[::1]:4943/callback").is_ok());
    }

    #[test]
    fn should_reject_invalid_origins() {
        assert!(super::validate_origin("").is_err());
        assert!(super::validate_origin(&"a".repeat(256)).is_err());
    }
}
