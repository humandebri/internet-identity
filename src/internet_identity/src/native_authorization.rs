//! Native browser authorization with OAuth-style code redemption and delegation exchange.

use crate::account_management;
use crate::authz_utils::{check_authorization, ii_domain, record_activity, IdentityUpdateError};
use crate::state;
use crate::state::native_authorization::{
    AuthorizedNativeAuthorization, NativeAccessTokenRecord, NativeAuthorizationRecord,
    NativeAuthorizationStatus,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ic_cdk::api::time;
use internet_identity_interface::internet_identity::types::{
    CompleteNativeAuthorizationError, CompleteNativeAuthorizationResponse,
    ExchangeNativeAccessTokenForDelegationError, ExchangeNativeAccessTokenForDelegationRequest,
    ExchangeNativeAccessTokenForDelegationResponse, GetNativeAuthorizationRequestError,
    NativeAuthorizationRequest, NativeOidcApplicationType, NativeOidcClientConfig,
    NativeOidcTokenEndpointAuthMethod, PrepareNativeAuthorizationError,
    PrepareNativeAuthorizationRequest, PrepareNativeAuthorizationResponse,
    RedeemNativeAuthorizationCodeError, RedeemNativeAuthorizationCodeRequest,
    RedeemNativeAuthorizationCodeResponse,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::BTreeSet;

const REQUEST_ID_NUM_BYTES: usize = 32;
const TOKEN_NUM_BYTES: usize = 32;
const HTTPS_URL_MAX_BYTES: usize = 512;
const LOOPBACK_URL_MAX_BYTES: usize = 512;
const ORIGIN_MAX_BYTES: usize = 255;
const STATE_MAX_BYTES: usize = 512;
const NONCE_MAX_BYTES: usize = 512;
const CLIENT_ID_MAX_BYTES: usize = 255;
const MAX_SCOPES: usize = 16;
const MAX_SCOPE_VALUE_BYTES: usize = 64;
const PKCE_MIN_BYTES: usize = 43;
const PKCE_MAX_BYTES: usize = 128;
const PENDING_REQUEST_TTL_NS: u64 = 5 * 60 * 1_000_000_000;
const CODE_TTL_NS: u64 = 5 * 60 * 1_000_000_000;
const COMPLETED_REQUEST_GRACE_PERIOD_NS: u64 = 10 * 60 * 1_000_000_000;
const ACCESS_TOKEN_TTL_NS: u64 = 5 * 60 * 1_000_000_000;
const DEFAULT_NATIVE_OIDC_ISSUER_ORIGIN: &str = "https://identity.internetcomputer.org";

thread_local! {
    static SIGNING_KEY_CACHE: RefCell<Option<RsaPrivateKey>> = const { RefCell::new(None) };
}

#[derive(Debug, Eq, PartialEq)]
struct CanonicalOrigin {
    scheme: String,
    host: String,
    port: u16,
}

#[derive(Debug, Eq, PartialEq)]
enum RedirectUriKind {
    ClaimedHttps(CanonicalOrigin),
    PrivateScheme,
    Loopback(LoopbackRedirectUri),
}

#[derive(Debug, Eq, PartialEq)]
struct LoopbackRedirectUri {
    host: String,
    path: String,
}

#[derive(Clone)]
struct RegisteredNativeClient {
    client_id: String,
    redirect_uris: Vec<String>,
    allowed_origins: Vec<String>,
}

#[derive(Serialize)]
struct OpenIdConfiguration<'a> {
    issuer: &'a str,
    authorization_endpoint: String,
    token_endpoint: String,
    ic_delegation_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<&'static str>,
    grant_types_supported: Vec<&'static str>,
    subject_types_supported: Vec<&'static str>,
    id_token_signing_alg_values_supported: Vec<&'static str>,
    code_challenge_methods_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: Vec<&'static str>,
}

#[derive(Serialize)]
struct JwksDocument {
    keys: Vec<JwkDocument>,
}

#[derive(Serialize)]
struct JwkDocument {
    kty: &'static str,
    #[serde(rename = "use")]
    use_: &'static str,
    alg: &'static str,
    kid: String,
    n: String,
    e: String,
}

#[derive(Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: String,
    aud: &'a str,
    exp: u64,
    iat: u64,
    auth_time: u64,
    nonce: &'a str,
}

pub async fn prepare(
    request: PrepareNativeAuthorizationRequest,
) -> Result<PrepareNativeAuthorizationResponse, PrepareNativeAuthorizationError> {
    let registered_client = validate_prepare_request(&request)?;
    let origin = canonicalize_native_origin_string(&request.origin)
        .map_err(PrepareNativeAuthorizationError::InvalidOrigin)?;
    let ii_origin = request.ii_origin.trim_end_matches('/').to_string();
    let issuer = configured_issuer_origin();

    let request_id = random_token(REQUEST_ID_NUM_BYTES).await.map_err(|err| {
        PrepareNativeAuthorizationError::InternalCanisterError(format!(
            "failed to generate request id: {err}"
        ))
    })?;
    let expires_at = time().saturating_add(PENDING_REQUEST_TTL_NS);
    let record = NativeAuthorizationRecord {
        origin,
        redirect_uri: request.redirect_uri,
        client_id: request.client_id,
        state: request.state,
        scope: request.scope,
        nonce: request.nonce,
        code_challenge: request.code_challenge,
        code_challenge_method: request.code_challenge_method,
        session_public_key: request.session_public_key,
        max_time_to_live: request.max_time_to_live,
        issuer,
        expires_at,
        status: NativeAuthorizationStatus::Pending,
    };
    debug_assert_eq!(registered_client.client_id, record.client_id);

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
            redirect_uri: record.redirect_uri,
            client_id: record.client_id,
            state: record.state,
            scope: record.scope,
            nonce: record.nonce,
            session_public_key: record.session_public_key,
            max_time_to_live: record.max_time_to_live,
        }),
        NativeAuthorizationStatus::InProgress(_) | NativeAuthorizationStatus::Authorized(_) => {
            Err(GetNativeAuthorizationRequestError::AlreadyCompleted)
        }
    }
}

pub async fn complete(
    anchor_number: u64,
    request_id: &str,
    account_number: Option<u64>,
) -> Result<CompleteNativeAuthorizationResponse, CompleteNativeAuthorizationError> {
    let (anchor, authorization_key) = check_authorization(anchor_number).map_err(map_authz_err)?;
    let record = state::native_authorizations_mut(|native_authorizations| {
        native_authorizations.claim_for_completion(request_id, time())
    })?;
    let ii_domain = ii_domain(&anchor, &authorization_key);
    release_claim_on_error(
        record_activity(anchor_number, anchor, authorization_key)
            .map(|_| ())
            .map_err(map_identity_update_err),
        request_id,
    )?;

    let prepared = release_claim_on_error(
        account_management::prepare_account_delegation(
            anchor_number,
            record.origin.clone(),
            account_number,
            record.session_public_key.clone(),
            record.max_time_to_live,
            &ii_domain,
        )
        .await
        .map_err(|err| CompleteNativeAuthorizationError::InternalCanisterError(format!("{err:?}"))),
        request_id,
    )?;

    let now = time();
    let redirect_url = format_redirect_url(&record.redirect_uri, request_id, &record.state);
    let authorized = AuthorizedNativeAuthorization {
        anchor_number,
        account_number,
        user_key: prepared.user_key,
        expiration: prepared.expiration,
        code_expires_at: now.saturating_add(CODE_TTL_NS),
        redeemed_at: None,
    };

    state::native_authorizations_mut(|native_authorizations| {
        native_authorizations.complete_claimed(
            request_id,
            authorized,
            now.saturating_add(COMPLETED_REQUEST_GRACE_PERIOD_NS),
        )
    })?;

    Ok(CompleteNativeAuthorizationResponse { redirect_url })
}

pub async fn redeem_code(
    request: RedeemNativeAuthorizationCodeRequest,
) -> Result<RedeemNativeAuthorizationCodeResponse, RedeemNativeAuthorizationCodeError> {
    validate_redeem_request(&request)?;
    let registered_client = registered_client(&request.client_id)
        .map_err(RedeemNativeAuthorizationCodeError::InvalidRequest)?;
    let now = time();
    let record = state::native_authorizations_mut(|native_authorizations| {
        native_authorizations.authorized_code(&request.code, now)
    })?;
    if record.redirect_uri != request.redirect_uri {
        return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
            "redirect_uri does not match the prepared request".to_string(),
        ));
    }
    if record.client_id != request.client_id {
        return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
            "client_id does not match the prepared request".to_string(),
        ));
    }
    if !registered_client
        .redirect_uris
        .iter()
        .any(|redirect_uri| redirect_uri_matches_registration(&request.redirect_uri, redirect_uri))
    {
        return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
            "redirect_uri is not registered for client_id".to_string(),
        ));
    }
    if let Err(err) = validate_pkce(
        &record.code_challenge_method,
        &record.code_challenge,
        &request.code_verifier,
    ) {
        state::native_authorizations_mut(|native_authorizations| {
            native_authorizations.invalidate_code(&request.code, now);
        });
        return Err(err);
    }

    let access_token = random_token(TOKEN_NUM_BYTES).await.map_err(|err| {
        RedeemNativeAuthorizationCodeError::InternalCanisterError(format!(
            "failed to generate access token: {err}"
        ))
    })?;
    let NativeAuthorizationStatus::Authorized(authorized) = record.status else {
        return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
            "authorization code is not ready".to_string(),
        ));
    };
    let token_record = NativeAccessTokenRecord {
        anchor_number: authorized.anchor_number,
        account_number: authorized.account_number,
        origin: record.origin.clone(),
        session_public_key: record.session_public_key.clone(),
        user_key: authorized.user_key.clone(),
        expiration: authorized.expiration,
        expires_at: now.saturating_add(ACCESS_TOKEN_TTL_NS),
    };
    let id_token = sign_id_token(
        &record.issuer,
        &record.client_id,
        authorized.anchor_number,
        &record.nonce,
        now,
        token_record.expires_at,
    )
    .await?;

    state::native_authorizations_mut(|native_authorizations| {
        native_authorizations.issue_access_token(
            &request.code,
            access_token.clone(),
            token_record,
            now,
        )
    })?;

    Ok(RedeemNativeAuthorizationCodeResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: nanos_to_secs(ACCESS_TOKEN_TTL_NS),
        id_token,
    })
}

pub fn exchange_delegation(
    request: ExchangeNativeAccessTokenForDelegationRequest,
) -> Result<
    ExchangeNativeAccessTokenForDelegationResponse,
    ExchangeNativeAccessTokenForDelegationError,
> {
    let token_record = state::native_authorizations_mut(|native_authorizations| {
        native_authorizations.access_token(&request.access_token, time())
    })?;
    let signed_delegation = account_management::get_account_delegation(
        token_record.anchor_number,
        &token_record.origin,
        token_record.account_number,
        token_record.session_public_key,
        token_record.expiration,
    )
    .map_err(|_| {
        ExchangeNativeAccessTokenForDelegationError::InvalidToken(
            "delegation is not available for the access token".to_string(),
        )
    })?;
    Ok(ExchangeNativeAccessTokenForDelegationResponse {
        user_key: token_record.user_key,
        signed_delegation,
        expiration: token_record.expiration,
    })
}

pub fn openid_configuration_json() -> Result<Vec<u8>, String> {
    let issuer = configured_issuer_origin();
    let document = OpenIdConfiguration {
        issuer: &issuer,
        authorization_endpoint: format!("{issuer}/authorize"),
        token_endpoint: format!("{issuer}/oauth2/token"),
        ic_delegation_endpoint: format!("{issuer}/oauth2/delegation"),
        jwks_uri: format!("{issuer}/oauth2/jwks"),
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code"],
        subject_types_supported: vec!["pairwise"],
        id_token_signing_alg_values_supported: vec!["RS256"],
        code_challenge_methods_supported: vec!["S256"],
        token_endpoint_auth_methods_supported: vec!["none"],
    };
    serde_json::to_vec(&document).map_err(|err| err.to_string())
}

pub fn jwks_json() -> Result<Vec<u8>, String> {
    let key_pair = signing_key_pair_from_state()?;
    let public_key = key_pair.to_public_key();
    let document = JwksDocument {
        keys: vec![JwkDocument {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: key_id(&public_key),
            n: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
        }],
    };
    serde_json::to_vec(&document).map_err(|err| err.to_string())
}

pub fn prime_signing_key_cache() -> Result<(), String> {
    let _ = signing_key_pair_from_state()?;
    Ok(())
}

pub fn validate_client_configs(configs: &[NativeOidcClientConfig]) -> Result<(), String> {
    for config in configs {
        validate_client_config(config)?;
    }
    Ok(())
}

pub fn validate_issuer_origin(issuer: &str) -> Result<(), String> {
    canonicalize_native_origin_string(issuer)
        .map(|_| ())
        .map_err(|err| format!("native OIDC issuer origin {err}"))
}

fn validate_prepare_request(
    request: &PrepareNativeAuthorizationRequest,
) -> Result<RegisteredNativeClient, PrepareNativeAuthorizationError> {
    validate_origin(&request.origin).map_err(PrepareNativeAuthorizationError::InvalidOrigin)?;
    validate_ii_origin(&request.ii_origin)
        .map_err(PrepareNativeAuthorizationError::InvalidOrigin)?;
    validate_client_id(&request.client_id)
        .map_err(PrepareNativeAuthorizationError::InvalidRequest)?;
    validate_redirect_uri(&request.redirect_uri)
        .map_err(PrepareNativeAuthorizationError::InvalidRedirectUri)?;
    validate_scalar_field("state", &request.state, STATE_MAX_BYTES)
        .map_err(PrepareNativeAuthorizationError::InvalidRequest)?;
    validate_scopes(&request.scope).map_err(PrepareNativeAuthorizationError::InvalidRequest)?;
    validate_scalar_field("nonce", &request.nonce, NONCE_MAX_BYTES)
        .map_err(PrepareNativeAuthorizationError::InvalidRequest)?;
    validate_code_challenge_value(&request.code_challenge)
        .map_err(PrepareNativeAuthorizationError::InvalidRequest)?;
    if request.code_challenge_method != "S256" {
        return Err(PrepareNativeAuthorizationError::InvalidRequest(
            "code_challenge_method must be `S256`".to_string(),
        ));
    }
    if request.response_type != "code" {
        return Err(PrepareNativeAuthorizationError::InvalidRequest(
            "response_type must be `code`".to_string(),
        ));
    }
    if request.response_mode != "query" {
        return Err(PrepareNativeAuthorizationError::InvalidRequest(
            "response_mode must be `query`".to_string(),
        ));
    }
    let registered_client = registered_client(&request.client_id)
        .map_err(PrepareNativeAuthorizationError::InvalidRequest)?;
    if !registered_client
        .redirect_uris
        .iter()
        .any(|redirect_uri| redirect_uri_matches_registration(&request.redirect_uri, redirect_uri))
    {
        return Err(PrepareNativeAuthorizationError::InvalidRedirectUri(
            "redirect_uri is not registered for client_id".to_string(),
        ));
    }
    let redirect_kind = parse_redirect_uri(&request.redirect_uri)
        .map_err(PrepareNativeAuthorizationError::InvalidRedirectUri)?;
    if let RedirectUriKind::ClaimedHttps(redirect_origin) = redirect_kind {
        let origin = canonicalize_native_origin(&request.origin)
            .map_err(PrepareNativeAuthorizationError::InvalidOrigin)?;
        if redirect_origin != origin {
            return Err(PrepareNativeAuthorizationError::InvalidRedirectUri(
                "claimed https redirect_uri must match origin".to_string(),
            ));
        }
    }
    let origin = canonicalize_native_origin_string(&request.origin)
        .map_err(PrepareNativeAuthorizationError::InvalidOrigin)?;
    if !registered_client
        .allowed_origins
        .iter()
        .any(|allowed_origin| allowed_origin == &origin)
    {
        return Err(PrepareNativeAuthorizationError::InvalidOrigin(
            "origin is not registered for client_id".to_string(),
        ));
    }
    Ok(registered_client)
}

fn validate_redeem_request(
    request: &RedeemNativeAuthorizationCodeRequest,
) -> Result<(), RedeemNativeAuthorizationCodeError> {
    if request.grant_type != "authorization_code" {
        return Err(RedeemNativeAuthorizationCodeError::UnsupportedGrantType(
            "grant_type must be `authorization_code`".to_string(),
        ));
    }
    validate_redirect_uri(&request.redirect_uri)
        .map_err(RedeemNativeAuthorizationCodeError::InvalidRequest)?;
    validate_client_id(&request.client_id)
        .map_err(RedeemNativeAuthorizationCodeError::InvalidRequest)?;
    validate_code_verifier_value(&request.code_verifier)
        .map_err(RedeemNativeAuthorizationCodeError::InvalidRequest)?;
    Ok(())
}

fn validate_origin(origin: &str) -> Result<(), String> {
    if origin.len() > ORIGIN_MAX_BYTES {
        return Err(format!("origin must not exceed {ORIGIN_MAX_BYTES} bytes"));
    }
    canonicalize_native_origin(origin).map(|_| ())
}

fn validate_client_id(client_id: &str) -> Result<(), String> {
    validate_scalar_field("client_id", client_id, CLIENT_ID_MAX_BYTES)?;
    if !client_id.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("client_id must use visible ASCII characters".to_string());
    }
    Ok(())
}

fn validate_client_config(config: &NativeOidcClientConfig) -> Result<(), String> {
    if config.application_type != NativeOidcApplicationType::Native {
        return Err("native OIDC client must use application_type `native`".to_string());
    }
    if config.token_endpoint_auth_method != NativeOidcTokenEndpointAuthMethod::None {
        return Err("native OIDC client must use token_endpoint_auth_method `none`".to_string());
    }
    if !config.require_pkce {
        return Err("native OIDC client must require PKCE".to_string());
    }
    validate_client_id(&config.client_id)?;
    if config.redirect_uris.is_empty() {
        return Err("native OIDC client must define at least one redirect_uri".to_string());
    }
    if config.allowed_origins.is_empty() {
        return Err("native OIDC client must define at least one allowed_origin".to_string());
    }
    for redirect_uri in &config.redirect_uris {
        parse_redirect_uri(redirect_uri)?;
    }
    for allowed_origin in &config.allowed_origins {
        canonicalize_native_origin_string(allowed_origin)?;
    }
    Ok(())
}

fn validate_scopes(scope: &[String]) -> Result<(), String> {
    if scope.is_empty() {
        return Err("scope must not be empty".to_string());
    }
    if scope.len() > MAX_SCOPES {
        return Err(format!(
            "scope must not include more than {MAX_SCOPES} values"
        ));
    }
    let mut seen = BTreeSet::new();
    let mut has_openid = false;
    for value in scope {
        validate_scalar_field("scope", value, MAX_SCOPE_VALUE_BYTES)?;
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err("scope values must use visible ASCII characters".to_string());
        }
        if !seen.insert(value) {
            return Err("scope must not contain duplicate values".to_string());
        }
        has_openid |= value == "openid";
    }
    if !has_openid {
        return Err("scope must include `openid`".to_string());
    }
    Ok(())
}

fn validate_scalar_field(field_name: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field_name} must not be empty"));
    }
    if value.len() > max_len {
        return Err(format!("{field_name} must not exceed {max_len} bytes"));
    }
    if value.bytes().any(|byte| byte <= b' ') {
        return Err(format!("{field_name} must not contain control characters"));
    }
    Ok(())
}

fn validate_code_challenge_value(value: &str) -> Result<(), String> {
    validate_pkce_component("code_challenge", value)
}

fn validate_code_verifier_value(value: &str) -> Result<(), String> {
    validate_pkce_component("code_verifier", value)
}

fn validate_pkce_component(field_name: &str, value: &str) -> Result<(), String> {
    validate_scalar_field(field_name, value, PKCE_MAX_BYTES)?;
    if value.len() < PKCE_MIN_BYTES {
        return Err(format!(
            "{field_name} must be at least {PKCE_MIN_BYTES} bytes"
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
    {
        return Err(format!("{field_name} must use unreserved URI characters"));
    }
    Ok(())
}

fn validate_pkce(
    method: &str,
    expected_challenge: &str,
    verifier: &str,
) -> Result<(), RedeemNativeAuthorizationCodeError> {
    if method != "S256" {
        return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
            "unsupported code challenge method".to_string(),
        ));
    }
    let actual = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    if actual != expected_challenge {
        return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
            "code_verifier does not match code_challenge".to_string(),
        ));
    }
    Ok(())
}

fn validate_redirect_uri(redirect_uri: &str) -> Result<(), String> {
    parse_redirect_uri(redirect_uri).map(|_| ())
}

fn redirect_uri_matches_registration(requested: &str, registered: &str) -> bool {
    match (
        parse_redirect_uri(requested),
        parse_redirect_uri(registered),
    ) {
        (Ok(RedirectUriKind::Loopback(requested)), Ok(RedirectUriKind::Loopback(registered))) => {
            requested == registered
        }
        (Ok(_), Ok(_)) => requested == registered,
        _ => false,
    }
}

fn parse_redirect_uri(redirect_uri: &str) -> Result<RedirectUriKind, String> {
    if redirect_uri.is_empty() {
        return Err("redirect_uri must not be empty".to_string());
    }
    if redirect_uri.len() > LOOPBACK_URL_MAX_BYTES {
        return Err(format!(
            "redirect_uri must not exceed {LOOPBACK_URL_MAX_BYTES} bytes"
        ));
    }
    if redirect_uri.contains('#') || redirect_uri.contains('?') {
        return Err("redirect_uri must not contain query or fragment".to_string());
    }
    if redirect_uri.bytes().any(|byte| byte <= b' ') {
        return Err("redirect_uri must not contain control characters".to_string());
    }
    if redirect_uri.starts_with("https://") {
        let origin = canonicalize_https_origin_components(
            extract_https_authority(redirect_uri)?,
            "redirect_uri",
        )?;
        return Ok(RedirectUriKind::ClaimedHttps(origin));
    }
    if redirect_uri.starts_with("http://") {
        return Ok(RedirectUriKind::Loopback(parse_loopback_redirect_uri(
            redirect_uri,
        )?));
    }
    validate_private_scheme_redirect_uri(redirect_uri)?;
    Ok(RedirectUriKind::PrivateScheme)
}

fn validate_private_scheme_redirect_uri(redirect_uri: &str) -> Result<(), String> {
    let (scheme, path) = redirect_uri
        .split_once(':')
        .ok_or_else(|| "private-use redirect_uri must include a scheme".to_string())?;
    if scheme.is_empty() || scheme.len() > ORIGIN_MAX_BYTES {
        return Err("private-use redirect_uri scheme is invalid".to_string());
    }
    if !is_reverse_domain_scheme(scheme) {
        return Err("private-use redirect_uri scheme must use reverse-domain notation".to_string());
    }
    if !path.starts_with('/') || path.starts_with("//") || path.len() == 1 {
        return Err("private-use redirect_uri must use single-slash path form".to_string());
    }
    Ok(())
}

fn parse_loopback_redirect_uri(redirect_uri: &str) -> Result<LoopbackRedirectUri, String> {
    let remainder = redirect_uri
        .strip_prefix("http://")
        .ok_or_else(|| "loopback redirect_uri must start with http://".to_string())?;
    let (authority, path) = remainder
        .split_once('/')
        .ok_or_else(|| "loopback redirect_uri must include a path".to_string())?;
    if authority.is_empty() {
        return Err("loopback redirect_uri must include a host".to_string());
    }
    let (host, port) = split_host_and_port(authority)
        .ok_or_else(|| "loopback redirect_uri must include a valid host and port".to_string())?;
    if !matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
        return Err(
            "loopback redirect_uri host must be localhost, 127.0.0.1, or [::1]".to_string(),
        );
    }
    validate_port(port, "loopback redirect_uri")?;
    Ok(LoopbackRedirectUri {
        host: host.to_ascii_lowercase(),
        path: format!("/{path}"),
    })
}

fn is_reverse_domain_scheme(scheme: &str) -> bool {
    if !matches!(scheme.as_bytes().first(), Some(b'a'..=b'z')) {
        return false;
    }
    if !scheme.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
    }) {
        return false;
    }
    let mut parts = scheme.split('.');
    let count = parts.clone().count();
    count >= 2
        && parts.all(|part| {
            let bytes = part.as_bytes();
            !bytes.is_empty()
                && matches!(bytes.first(), Some(b'a'..=b'z' | b'0'..=b'9'))
                && matches!(bytes.last(), Some(b'a'..=b'z' | b'0'..=b'9'))
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        })
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
    if url.contains('?') || url.contains('#') {
        return Err(format!("{field_name} must not contain query or fragment"));
    }
    if url.bytes().any(|byte| byte <= b' ') {
        return Err(format!("{field_name} must not contain control characters"));
    }
    let authority = extract_https_authority(url)?;
    if authority.contains('@') {
        return Err(format!("{field_name} must not include userinfo"));
    }
    let (host, port) = split_host_and_port(authority)
        .ok_or_else(|| format!("{field_name} must include a valid host"))?;
    validate_host(host, field_name)?;
    validate_port(port, field_name)?;
    Ok(())
}

fn canonicalize_native_origin_string(origin: &str) -> Result<String, String> {
    let canonical = canonicalize_native_origin(origin)?;
    if canonical.port == 443 {
        Ok(format!("{}://{}", canonical.scheme, canonical.host))
    } else {
        Ok(format!(
            "{}://{}:{}",
            canonical.scheme, canonical.host, canonical.port
        ))
    }
}

fn canonicalize_native_origin(origin: &str) -> Result<CanonicalOrigin, String> {
    let (scheme, authority) = origin
        .split_once("://")
        .ok_or_else(|| "origin must include a scheme".to_string())?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" {
        return Err("origin must use https".to_string());
    }
    if authority.contains('/') || authority.contains('?') || authority.contains('#') {
        return Err("origin must not contain path, query, or fragment".to_string());
    }
    canonicalize_origin_components(scheme, authority, "origin")
}

fn canonicalize_https_origin_components(
    authority: &str,
    field_name: &str,
) -> Result<CanonicalOrigin, String> {
    canonicalize_origin_components("https".to_string(), authority, field_name)
}

fn canonicalize_origin_components(
    scheme: String,
    authority: &str,
    field_name: &str,
) -> Result<CanonicalOrigin, String> {
    if authority.is_empty() {
        return Err(format!("{field_name} must include a host"));
    }
    if authority.contains('@') {
        return Err(format!("{field_name} must not include userinfo"));
    }
    let (host, port) = split_host_and_port(authority)
        .ok_or_else(|| format!("{field_name} must include a valid host"))?;
    validate_host(host, field_name)?;
    let port = validate_port(port, field_name)?;
    Ok(CanonicalOrigin {
        scheme,
        host: host.to_ascii_lowercase(),
        port,
    })
}

fn extract_https_authority(url: &str) -> Result<&str, String> {
    let remainder = url
        .strip_prefix("https://")
        .ok_or_else(|| "url must start with https://".to_string())?;
    let authority = remainder.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return Err("url must include a host".to_string());
    }
    Ok(authority)
}

fn split_host_and_port(authority: &str) -> Option<(&str, Option<u16>)> {
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = &authority[..=end];
        let remainder = &authority[end + 1..];
        if remainder.is_empty() {
            return Some((host, None));
        }
        let port = remainder.strip_prefix(':')?.parse().ok()?;
        return Some((host, Some(port)));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port.parse().ok()?)),
        _ => (authority, None),
    };
    Some((host, port))
}

fn validate_host(host: &str, field_name: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err(format!("{field_name} must include a host"));
    }
    if host.starts_with('[') && host.ends_with(']') {
        if host != "[::1]" {
            return Err(format!(
                "{field_name} only supports loopback IPv6 host [::1]"
            ));
        }
        return Ok(());
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
    {
        return Ok(());
    }
    Err(format!("{field_name} must include a valid host"))
}

fn validate_port(port: Option<u16>, field_name: &str) -> Result<u16, String> {
    match port {
        Some(0) => Err(format!("{field_name} must include a valid port")),
        Some(port) => Ok(port),
        None => Ok(443),
    }
}

fn format_redirect_url(redirect_uri: &str, code: &str, state: &str) -> String {
    let code = percent_encode_query_value(code);
    let state = percent_encode_query_value(state);
    format!("{redirect_uri}?code={code}&state={state}")
}

fn configured_issuer_origin() -> String {
    state::persistent_state(|persistent_state| {
        persistent_state
            .native_oidc_issuer_origin
            .clone()
            .unwrap_or_else(|| DEFAULT_NATIVE_OIDC_ISSUER_ORIGIN.to_string())
    })
}

async fn sign_id_token(
    issuer: &str,
    client_id: &str,
    anchor_number: u64,
    nonce: &str,
    issued_at_ns: u64,
    expires_at_ns: u64,
) -> Result<String, RedeemNativeAuthorizationCodeError> {
    state::ensure_salt_set().await;
    let private_key = signing_key_pair_from_state()
        .map_err(RedeemNativeAuthorizationCodeError::InternalCanisterError)?;
    let public_key = private_key.to_public_key();
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": key_id(&public_key),
    });
    let pairwise_sub = pairwise_subject(issuer, client_id, anchor_number);
    let claims = IdTokenClaims {
        iss: issuer,
        sub: pairwise_sub,
        aud: client_id,
        exp: nanos_to_secs(expires_at_ns),
        iat: nanos_to_secs(issued_at_ns),
        auth_time: nanos_to_secs(issued_at_ns),
        nonce,
    };
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|err| {
        RedeemNativeAuthorizationCodeError::InternalCanisterError(err.to_string())
    })?);
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).map_err(|err| {
        RedeemNativeAuthorizationCodeError::InternalCanisterError(err.to_string())
    })?);
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_vec())
    ))
}

fn pairwise_subject(issuer: &str, client_id: &str, anchor_number: u64) -> String {
    pairwise_subject_with_salt(state::salt(), issuer, client_id, anchor_number)
}

fn pairwise_subject_with_salt(
    salt: [u8; 32],
    issuer: &str,
    client_id: &str,
    anchor_number: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update([0u8]);
    hasher.update(issuer.as_bytes());
    hasher.update([0u8]);
    hasher.update(client_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(anchor_number.to_be_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn registered_client(client_id: &str) -> Result<RegisteredNativeClient, String> {
    let Some(config) = state::persistent_state(|persistent_state| {
        persistent_state
            .native_oidc_clients
            .as_ref()
            .and_then(|configs| {
                configs
                    .iter()
                    .find(|config| config.client_id == client_id)
                    .cloned()
            })
    }) else {
        return Err("client_id is not registered".to_string());
    };
    validate_client_config(&config)?;
    let allowed_origins = config
        .allowed_origins
        .iter()
        .map(|origin| canonicalize_native_origin_string(origin))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RegisteredNativeClient {
        client_id: config.client_id,
        redirect_uris: config.redirect_uris,
        allowed_origins,
    })
}

fn signing_key_pair_from_state() -> Result<RsaPrivateKey, String> {
    let maybe_cached = SIGNING_KEY_CACHE.with(|cache| cache.borrow().clone());
    if let Some(private_key) = maybe_cached {
        return Ok(private_key);
    }
    let salt = state::storage_borrow(|storage| storage.salt().cloned())
        .ok_or_else(|| "salt is not initialized".to_string())?;
    let private_key = signing_key_pair_from_salt(&salt)?;
    SIGNING_KEY_CACHE.with(|cache| {
        cache.replace(Some(private_key.clone()));
    });
    Ok(private_key)
}

fn signing_key_pair_from_salt(salt: &[u8; 32]) -> Result<RsaPrivateKey, String> {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&Sha256::digest(
        [salt.as_slice(), b"native-oidc-signing-key"].concat(),
    ));
    let mut rng = ChaCha20Rng::from_seed(seed);
    RsaPrivateKey::new(&mut rng, 2048).map_err(|err| err.to_string())
}

fn key_id(public_key: &rsa::RsaPublicKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key.n().to_bytes_be());
    hasher.update(public_key.e().to_bytes_be());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn nanos_to_secs(value: u64) -> u64 {
    value / 1_000_000_000
}

fn percent_encode_query_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
            encoded.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
        }
    }
    encoded
}

async fn random_token(num_bytes: usize) -> Result<String, String> {
    let mut bytes = vec![0; num_bytes];
    ic_cdk::api::management_canister::main::raw_rand()
        .await
        .map_err(|(code, msg)| format!("raw_rand failed ({code:?}): {msg}"))?
        .0
        .iter()
        .cycle()
        .zip(bytes.iter_mut())
        .for_each(|(source, target)| *target = *source);
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn release_claim_on_error<T>(
    result: Result<T, CompleteNativeAuthorizationError>,
    request_id: &str,
) -> Result<T, CompleteNativeAuthorizationError> {
    if result.is_err() {
        state::native_authorizations_mut(|native_authorizations| {
            native_authorizations.release_claim(request_id);
        });
    }
    result
}

fn map_authz_err(
    error: crate::authz_utils::AuthorizationError,
) -> CompleteNativeAuthorizationError {
    CompleteNativeAuthorizationError::Unauthorized(error.principal)
}

fn map_identity_update_err(error: IdentityUpdateError) -> CompleteNativeAuthorizationError {
    match error {
        IdentityUpdateError::Unauthorized(principal) => {
            CompleteNativeAuthorizationError::Unauthorized(principal)
        }
        IdentityUpdateError::StorageError(_, err) => {
            CompleteNativeAuthorizationError::InternalCanisterError(err.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_derive_stable_pairwise_subject_per_client() {
        let salt = [7u8; 32];
        let issuer = "https://identity.internetcomputer.org";
        let subject_a = pairwise_subject_with_salt(salt, issuer, "com.example.app", 42);
        let subject_a_second = pairwise_subject_with_salt(salt, issuer, "com.example.app", 42);
        let subject_b = pairwise_subject_with_salt(salt, issuer, "com.example.wallet", 42);

        assert_eq!(subject_a, subject_a_second);
        assert_ne!(subject_a, subject_b);
    }

    #[test]
    fn should_validate_native_oidc_allowed_origins() {
        let valid = NativeOidcClientConfig {
            client_id: "com.example.app".to_string(),
            redirect_uris: vec!["com.example.app:/oauth2redirect/ii".to_string()],
            allowed_origins: vec!["https://app.example.com".to_string()],
            application_type: NativeOidcApplicationType::Native,
            token_endpoint_auth_method: NativeOidcTokenEndpointAuthMethod::None,
            require_pkce: true,
        };
        assert!(validate_client_config(&valid).is_ok());

        let mut invalid = valid.clone();
        invalid.allowed_origins = vec![];
        assert!(validate_client_config(&invalid).is_err());

        let mut invalid = valid.clone();
        invalid.allowed_origins = vec!["http://app.example.com".to_string()];
        assert!(validate_client_config(&invalid).is_err());

        let mut invalid = valid;
        invalid.allowed_origins = vec!["https://app.example.com/callback".to_string()];
        assert!(validate_client_config(&invalid).is_err());
    }

    #[test]
    fn should_reject_issuer_origins_with_path() {
        assert!(validate_issuer_origin("https://identity.ic0.app").is_ok());
        assert!(validate_issuer_origin("https://identity.ic0.app:443").is_ok());
        assert!(validate_issuer_origin("https://identity.ic0.app/").is_err());
        assert!(validate_issuer_origin("https://identity.ic0.app/path").is_err());
    }

    #[test]
    fn should_match_loopback_registration_without_port() {
        assert!(redirect_uri_matches_registration(
            "http://127.0.0.1:49152/oauth2redirect/ii",
            "http://127.0.0.1:3000/oauth2redirect/ii"
        ));
        assert!(!redirect_uri_matches_registration(
            "http://127.0.0.1:49152/oauth2redirect/ii",
            "http://127.0.0.1:3000/other"
        ));
    }

    #[test]
    fn should_reject_invalid_private_use_schemes() {
        assert!(is_reverse_domain_scheme("com.example.app"));
        assert!(!is_reverse_domain_scheme("1.example"));
        assert!(!is_reverse_domain_scheme("com.-example.app"));
        assert!(!is_reverse_domain_scheme("com.example-.app"));
        assert!(!is_reverse_domain_scheme("com..example"));
        assert!(!is_reverse_domain_scheme("Com.Example.App"));
        assert!(!is_reverse_domain_scheme("com+example.app"));
    }

    #[test]
    fn should_validate_scopes_strictly() {
        assert!(validate_scopes(&["openid".to_string()]).is_ok());
        assert!(validate_scopes(&[]).is_err());
        assert!(validate_scopes(&["profile".to_string()]).is_err());
        assert!(validate_scopes(&["openid".to_string(), "openid".to_string()]).is_err());
        assert!(validate_scopes(&["openid profile".to_string()]).is_err());
        assert!(validate_scopes(&["openid".to_string(), "x".repeat(65)]).is_err());
        assert!(validate_scopes(
            &std::iter::once("openid".to_string())
                .chain((0..16).map(|i| format!("scope{i}")))
                .collect::<Vec<_>>()
        )
        .is_err());
    }
}
