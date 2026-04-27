//! Tests for native OAuth-style browser authorization.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use canister_tests::api::internet_identity as api;
use canister_tests::flows;
use canister_tests::framework::*;
use ic_cdk::api::management_canister::main::CanisterId;
use internet_identity_interface::internet_identity::types::*;
use pocket_ic::RejectResponse;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::time::Duration;

const NATIVE_REQUEST_TTL_SECS: u64 = 5 * 60;
const DEFAULT_TRUSTED_ISSUER_ORIGIN: &str = "https://identity.internetcomputer.org";
const PKCE_VERIFIER: &str = "native-browser-authorization-pkce-verifier-value";
const WRONG_PKCE_VERIFIER: &str = "wrong-browser-authorization-pkce-verifier-value";

fn native_request() -> PrepareNativeAuthorizationRequest {
    PrepareNativeAuthorizationRequest {
        origin: "https://app.example.com".to_string(),
        ii_origin: "https://identity.test".to_string(),
        session_public_key: ByteBuf::from("native session key"),
        redirect_uri: "https://app.example.com/callback".to_string(),
        client_id: "com.example.app".to_string(),
        state: "state-123".to_string(),
        scope: vec!["openid".to_string()],
        nonce: "nonce-123".to_string(),
        code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(PKCE_VERIFIER.as_bytes())),
        code_challenge_method: "S256".to_string(),
        response_type: "code".to_string(),
        response_mode: "query".to_string(),
        max_time_to_live: None,
    }
}

fn redeem_request(
    code: &str,
    redirect_uri: &str,
    client_id: &str,
) -> RedeemNativeAuthorizationCodeRequest {
    RedeemNativeAuthorizationCodeRequest {
        grant_type: "authorization_code".to_string(),
        code: code.to_string(),
        redirect_uri: redirect_uri.to_string(),
        code_verifier: PKCE_VERIFIER.to_string(),
        client_id: client_id.to_string(),
    }
}

fn native_client_config(client_id: &str, redirect_uris: Vec<String>) -> NativeOidcClientConfig {
    NativeOidcClientConfig {
        client_id: client_id.to_string(),
        redirect_uris,
        allowed_origins: vec!["https://app.example.com".to_string()],
        application_type: NativeOidcApplicationType::Native,
        token_endpoint_auth_method: NativeOidcTokenEndpointAuthMethod::None,
        require_pkce: true,
    }
}

fn install_native_oidc_ii(
    env: &pocket_ic::PocketIc,
    clients: Vec<NativeOidcClientConfig>,
) -> CanisterId {
    install_native_oidc_ii_with_issuer(env, clients, None)
}

fn install_native_oidc_ii_with_issuer(
    env: &pocket_ic::PocketIc,
    clients: Vec<NativeOidcClientConfig>,
    issuer_origin: Option<&str>,
) -> CanisterId {
    let mut init_arg = arg_with_wasm_hash(ARCHIVE_WASM.clone()).unwrap();
    init_arg.native_oidc_clients = Some(clients);
    init_arg.native_oidc_issuer_origin = issuer_origin.map(str::to_string);
    let canister_id = install_ii_canister_with_arg(env, II_WASM.clone(), Some(init_arg));
    api::deploy_archive(env, canister_id, &ARCHIVE_WASM)
        .expect("archive deployment should succeed");
    canister_id
}

#[derive(Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    nonce: String,
    exp: u64,
}

fn decode_query_component(value: &str) -> String {
    let mut bytes = Vec::with_capacity(value.len());
    let mut chars = value.as_bytes().iter().copied();
    while let Some(byte) = chars.next() {
        match byte {
            b'%' => {
                let high = chars.next().expect("high nibble should exist");
                let low = chars.next().expect("low nibble should exist");
                let high = (high as char).to_digit(16).expect("hex high");
                let low = (low as char).to_digit(16).expect("hex low");
                bytes.push(((high << 4) | low) as u8);
            }
            b'+' => bytes.push(b' '),
            _ => bytes.push(byte),
        }
    }
    String::from_utf8(bytes).expect("query component should be UTF-8")
}

fn query_param(url: &str, name: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == name).then(|| decode_query_component(value))
    })
}

#[test]
fn should_complete_redeem_oidc_token_and_exchange_native_authorization(
) -> Result<(), RejectResponse> {
    let env = env();
    let request = native_request();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );
    let anchor_number = flows::register_anchor(&env, canister_id);

    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");
    assert_eq!(
        prepared.authorize_url,
        format!(
            "{}/authorize?native_request_id={}",
            request.ii_origin, prepared.request_id
        )
    );

    let completed = api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?
    .expect("completion should succeed");
    assert_eq!(
        completed.redirect_url,
        format!(
            "{}?code={}&state={}",
            request.redirect_uri, prepared.request_id, request.state
        )
    );

    let token_response = api::redeem_native_authorization_code(
        &env,
        canister_id,
        &redeem_request(
            &prepared.request_id,
            &request.redirect_uri,
            &request.client_id,
        ),
    )?
    .expect("redeem should succeed");
    assert_eq!(token_response.token_type, "Bearer");
    assert!(!token_response.access_token.is_empty());
    assert!(token_response.expires_in > 0);

    let id_token_parts: Vec<_> = token_response.id_token.split('.').collect();
    assert_eq!(id_token_parts.len(), 3);
    let claims: IdTokenClaims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(id_token_parts[1])
            .expect("payload should decode"),
    )
    .expect("claims should parse");
    assert_eq!(claims.iss, DEFAULT_TRUSTED_ISSUER_ORIGIN);
    assert_eq!(claims.aud, request.client_id);
    assert_ne!(claims.sub, anchor_number.to_string());
    assert_eq!(claims.nonce, request.nonce);
    assert!(claims.exp > 0);
    assert_eq!(token_response.token_type, "Bearer");

    let exchanged = api::exchange_native_access_token_for_delegation(
        &env,
        canister_id,
        &ExchangeNativeAccessTokenForDelegationRequest {
            access_token: token_response.access_token,
        },
    )?
    .expect("exchange should succeed");
    verify_delegation(
        &env,
        exchanged.user_key,
        &exchanged.signed_delegation,
        &env.root_key().unwrap(),
    );
    Ok(())
}

#[test]
fn should_support_private_use_redirect_uri() -> Result<(), RejectResponse> {
    let env = env();
    let mut request = native_request();
    request.redirect_uri = "com.example.app:/oauth2redirect/ii".to_string();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );

    api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");
    Ok(())
}

#[test]
fn should_reject_private_use_redirect_uri_with_unregistered_origin() -> Result<(), RejectResponse> {
    let env = env();
    let mut request = native_request();
    request.redirect_uri = "com.example.app:/oauth2redirect/ii".to_string();
    request.origin = "https://evil.example.com".to_string();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(matches!(
        result,
        Err(PrepareNativeAuthorizationError::InvalidOrigin(_))
    ));
    Ok(())
}

#[test]
fn should_reject_claimed_https_redirect_uri_with_mismatched_origin() -> Result<(), RejectResponse> {
    let env = env();
    let mut request = native_request();
    request.origin = "https://evil.example.com".to_string();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(matches!(
        result,
        Err(PrepareNativeAuthorizationError::InvalidRedirectUri(_))
    ));
    Ok(())
}

#[test]
fn should_support_loopback_redirect_uri() -> Result<(), RejectResponse> {
    let env = env();
    let mut request = native_request();
    request.redirect_uri = "http://127.0.0.1:49152/oauth2redirect/ii".to_string();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );

    api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");
    Ok(())
}

#[test]
fn should_accept_loopback_redirect_uri_with_ephemeral_port() -> Result<(), RejectResponse> {
    let env = env();
    let mut request = native_request();
    request.redirect_uri = "http://127.0.0.1:49152/oauth2redirect/ii".to_string();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec!["http://127.0.0.1:3000/oauth2redirect/ii".to_string()],
        )],
    );
    let anchor_number = flows::register_anchor(&env, canister_id);

    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");
    let completed = api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?
    .expect("completion should succeed");
    assert_eq!(
        completed.redirect_url,
        format!(
            "{}?code={}&state={}",
            request.redirect_uri, prepared.request_id, request.state
        )
    );

    api::redeem_native_authorization_code(
        &env,
        canister_id,
        &redeem_request(
            &prepared.request_id,
            &request.redirect_uri,
            &request.client_id,
        ),
    )?
    .expect("redeem should succeed");
    Ok(())
}

#[test]
fn should_reject_loopback_redirect_uri_with_unregistered_origin() -> Result<(), RejectResponse> {
    let env = env();
    let mut request = native_request();
    request.redirect_uri = "http://127.0.0.1:49152/oauth2redirect/ii".to_string();
    request.origin = "https://evil.example.com".to_string();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(matches!(
        result,
        Err(PrepareNativeAuthorizationError::InvalidOrigin(_))
    ));
    Ok(())
}

#[test]
fn should_reject_non_reverse_domain_private_use_scheme() -> Result<(), RejectResponse> {
    let env = env();
    let mut request = native_request();
    request.redirect_uri = "myapp:/callback".to_string();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec!["com.example.app:/oauth2redirect/ii".to_string()],
        )],
    );

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(matches!(
        result,
        Err(PrepareNativeAuthorizationError::InvalidRedirectUri(_))
    ));
    Ok(())
}

#[test]
fn should_reject_unregistered_redirect_uri() -> Result<(), RejectResponse> {
    let env = env();
    let request = native_request();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec!["https://app.example.com/other-callback".to_string()],
        )],
    );

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(matches!(
        result,
        Err(PrepareNativeAuthorizationError::InvalidRedirectUri(_))
    ));
    Ok(())
}

#[test]
fn should_reject_missing_openid_scope() -> Result<(), RejectResponse> {
    let env = env();
    let mut request = native_request();
    request.scope = vec!["profile".to_string()];
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(matches!(
        result,
        Err(PrepareNativeAuthorizationError::InvalidRequest(_))
    ));
    Ok(())
}

#[test]
fn should_reject_short_code_challenge() -> Result<(), RejectResponse> {
    let env = env();
    let mut request = native_request();
    request.code_challenge = "short-challenge".to_string();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(matches!(
        result,
        Err(PrepareNativeAuthorizationError::InvalidRequest(_))
    ));
    Ok(())
}

#[test]
fn should_percent_encode_state_in_redirect_url() -> Result<(), RejectResponse> {
    let env = env();
    let mut request = native_request();
    request.state = "state=1&redirect=/nested-path".to_string();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );
    let anchor_number = flows::register_anchor(&env, canister_id);
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare should succeed");
    let completed = api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?
    .expect("completion should succeed");
    assert_eq!(
        query_param(&completed.redirect_url, "code"),
        Some(prepared.request_id)
    );
    assert_eq!(
        query_param(&completed.redirect_url, "state"),
        Some(request.state)
    );
    Ok(())
}

#[test]
fn should_invalidate_code_after_pkce_mismatch() -> Result<(), RejectResponse> {
    let env = env();
    let request = native_request();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );
    let anchor_number = flows::register_anchor(&env, canister_id);
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare should succeed");
    api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?
    .expect("completion should succeed");

    let invalid = api::redeem_native_authorization_code(
        &env,
        canister_id,
        &RedeemNativeAuthorizationCodeRequest {
            code_verifier: WRONG_PKCE_VERIFIER.to_string(),
            ..redeem_request(
                &prepared.request_id,
                &request.redirect_uri,
                &request.client_id,
            )
        },
    )?;
    assert!(matches!(
        invalid,
        Err(RedeemNativeAuthorizationCodeError::InvalidGrant(_))
    ));

    let retry = api::redeem_native_authorization_code(
        &env,
        canister_id,
        &redeem_request(
            &prepared.request_id,
            &request.redirect_uri,
            &request.client_id,
        ),
    )?;
    assert!(matches!(
        retry,
        Err(RedeemNativeAuthorizationCodeError::InvalidGrant(_))
    ));
    Ok(())
}

#[test]
fn should_reject_short_pkce_verifier() -> Result<(), RejectResponse> {
    let env = env();
    let request = native_request();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );
    let anchor_number = flows::register_anchor(&env, canister_id);
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare should succeed");
    api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?
    .expect("completion should succeed");

    let result = api::redeem_native_authorization_code(
        &env,
        canister_id,
        &RedeemNativeAuthorizationCodeRequest {
            code_verifier: "short-verifier".to_string(),
            ..redeem_request(
                &prepared.request_id,
                &request.redirect_uri,
                &request.client_id,
            )
        },
    )?;
    assert!(matches!(
        result,
        Err(RedeemNativeAuthorizationCodeError::InvalidRequest(_))
    ));
    Ok(())
}

#[test]
fn should_reject_too_long_pkce_verifier() -> Result<(), RejectResponse> {
    let env = env();
    let request = native_request();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );
    let anchor_number = flows::register_anchor(&env, canister_id);
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare should succeed");
    api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?
    .expect("completion should succeed");

    let result = api::redeem_native_authorization_code(
        &env,
        canister_id,
        &RedeemNativeAuthorizationCodeRequest {
            code_verifier: "a".repeat(129),
            ..redeem_request(
                &prepared.request_id,
                &request.redirect_uri,
                &request.client_id,
            )
        },
    )?;
    assert!(matches!(
        result,
        Err(RedeemNativeAuthorizationCodeError::InvalidRequest(_))
    ));
    Ok(())
}

#[test]
fn should_not_use_caller_supplied_ii_origin_for_signed_issuer() -> Result<(), RejectResponse> {
    let env = env();
    let mut request = native_request();
    request.ii_origin = "https://attacker.example.com".to_string();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );
    let anchor_number = flows::register_anchor(&env, canister_id);
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare should succeed");
    api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?
    .expect("completion should succeed");
    let token_response = api::redeem_native_authorization_code(
        &env,
        canister_id,
        &redeem_request(
            &prepared.request_id,
            &request.redirect_uri,
            &request.client_id,
        ),
    )?
    .expect("redeem should succeed");
    let claims: IdTokenClaims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(
                token_response
                    .id_token
                    .split('.')
                    .nth(1)
                    .expect("JWT payload"),
            )
            .expect("payload should decode"),
    )
    .expect("claims should parse");

    assert_eq!(claims.iss, DEFAULT_TRUSTED_ISSUER_ORIGIN);
    assert_ne!(claims.iss, request.ii_origin);
    assert_eq!(token_response.token_type, "Bearer");
    Ok(())
}

#[test]
fn should_use_configured_issuer_for_signed_tokens() -> Result<(), RejectResponse> {
    let env = env();
    let request = native_request();
    let configured_issuer = "https://identity.ic0.app";
    let canister_id = install_native_oidc_ii_with_issuer(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
        Some(configured_issuer),
    );
    let anchor_number = flows::register_anchor(&env, canister_id);
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare should succeed");
    api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?
    .expect("completion should succeed");
    let token_response = api::redeem_native_authorization_code(
        &env,
        canister_id,
        &redeem_request(
            &prepared.request_id,
            &request.redirect_uri,
            &request.client_id,
        ),
    )?
    .expect("redeem should succeed");
    let claims: IdTokenClaims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(
                token_response
                    .id_token
                    .split('.')
                    .nth(1)
                    .expect("JWT payload"),
            )
            .expect("payload should decode"),
    )
    .expect("claims should parse");

    assert_eq!(claims.iss, configured_issuer);
    assert_eq!(token_response.token_type, "Bearer");
    Ok(())
}

#[test]
fn should_reject_second_redeem() -> Result<(), RejectResponse> {
    let env = env();
    let request = native_request();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );
    let anchor_number = flows::register_anchor(&env, canister_id);
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare should succeed");
    api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?
    .expect("completion should succeed");

    api::redeem_native_authorization_code(
        &env,
        canister_id,
        &redeem_request(
            &prepared.request_id,
            &request.redirect_uri,
            &request.client_id,
        ),
    )?
    .expect("first redeem should succeed");
    let second = api::redeem_native_authorization_code(
        &env,
        canister_id,
        &redeem_request(
            &prepared.request_id,
            &request.redirect_uri,
            &request.client_id,
        ),
    )?;
    assert!(matches!(
        second,
        Err(RedeemNativeAuthorizationCodeError::InvalidGrant(_))
    ));
    Ok(())
}

#[test]
fn should_return_expired_for_expired_access_token() -> Result<(), RejectResponse> {
    let env = env();
    let request = native_request();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );
    let anchor_number = flows::register_anchor(&env, canister_id);
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare should succeed");
    api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?
    .expect("completion should succeed");
    let token_response = api::redeem_native_authorization_code(
        &env,
        canister_id,
        &redeem_request(
            &prepared.request_id,
            &request.redirect_uri,
            &request.client_id,
        ),
    )?
    .expect("redeem should succeed");

    env.advance_time(Duration::from_secs(NATIVE_REQUEST_TTL_SECS + 1));
    env.tick();

    let exchange = api::exchange_native_access_token_for_delegation(
        &env,
        canister_id,
        &ExchangeNativeAccessTokenForDelegationRequest {
            access_token: token_response.access_token,
        },
    )?;
    assert!(matches!(
        exchange,
        Err(ExchangeNativeAccessTokenForDelegationError::Expired)
    ));
    Ok(())
}

#[test]
fn should_return_not_found_for_unknown_access_token() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            "com.example.app",
            vec!["https://app.example.com/callback".to_string()],
        )],
    );

    let exchange = api::exchange_native_access_token_for_delegation(
        &env,
        canister_id,
        &ExchangeNativeAccessTokenForDelegationRequest {
            access_token: "missing-token".to_string(),
        },
    )?;
    assert!(matches!(
        exchange,
        Err(ExchangeNativeAccessTokenForDelegationError::NotFound)
    ));
    Ok(())
}

#[test]
fn should_expire_authorization_code_before_redeem() -> Result<(), RejectResponse> {
    let env = env();
    let request = native_request();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            &request.client_id,
            vec![request.redirect_uri.clone()],
        )],
    );
    let anchor_number = flows::register_anchor(&env, canister_id);
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare should succeed");
    api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?
    .expect("completion should succeed");
    env.advance_time(Duration::from_secs(NATIVE_REQUEST_TTL_SECS + 1));
    env.tick();

    let result = api::redeem_native_authorization_code(
        &env,
        canister_id,
        &redeem_request(
            &prepared.request_id,
            &request.redirect_uri,
            &request.client_id,
        ),
    )?;
    assert!(matches!(
        result,
        Err(RedeemNativeAuthorizationCodeError::InvalidGrant(_))
    ));
    Ok(())
}

#[test]
fn should_reject_unregistered_client_id() -> Result<(), RejectResponse> {
    let env = env();
    let request = native_request();
    let canister_id = install_native_oidc_ii(
        &env,
        vec![native_client_config(
            "com.example.other",
            vec!["https://other.example.com/callback".to_string()],
        )],
    );

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(matches!(
        result,
        Err(PrepareNativeAuthorizationError::InvalidRequest(_))
    ));
    Ok(())
}
