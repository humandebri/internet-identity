//! Tests for native authorization request lifecycle.

use candid::Principal;
use canister_tests::api::internet_identity as api;
use canister_tests::flows;
use canister_tests::framework::*;
use internet_identity_interface::internet_identity::types::{
    CompleteNativeAuthorizationError, FetchNativeDelegationResponse,
    GetNativeAuthorizationRequestError, PrepareNativeAuthorizationError,
    PrepareNativeAuthorizationRequest,
};
use pocket_ic::RejectResponse;
use serde_bytes::ByteBuf;
use std::time::Duration;

fn native_request() -> PrepareNativeAuthorizationRequest {
    PrepareNativeAuthorizationRequest {
        origin: "https://some-dapp.com".to_string(),
        ii_origin: "https://identity.test".to_string(),
        session_public_key: ByteBuf::from("native session key"),
        return_link: "https://app.example.com/callback".to_string(),
        max_time_to_live: None,
    }
}

#[test]
fn should_prepare_and_fetch_native_delegation() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let anchor_number = flows::register_anchor(&env, canister_id);
    let session_key = ByteBuf::from("native session key");
    let request = PrepareNativeAuthorizationRequest {
        origin: "https://some-dapp.com".to_string(),
        ii_origin: "https://identity.test".to_string(),
        session_public_key: session_key.clone(),
        return_link: "https://app.example.com/callback".to_string(),
        max_time_to_live: None,
    };

    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");
    assert_eq!(
        prepared.authorize_url,
        format!(
            "{}/authorize?native_request_id={}",
            request.ii_origin, prepared.request_id
        )
    );

    let loaded = api::get_native_authorization_request(&env, canister_id, &prepared.request_id)?
        .expect("native request should be readable before completion");
    assert_eq!(loaded.origin, request.origin);
    assert_eq!(loaded.session_public_key, session_key);

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
            "{}?native_request_id={}",
            request.return_link, prepared.request_id
        )
    );

    let fetched = api::fetch_native_delegation(&env, canister_id, &prepared.request_id)?;
    let native_delegation = match fetched {
        FetchNativeDelegationResponse::SignedDelegation(native_delegation) => native_delegation,
        other => panic!("unexpected native delegation response: {other:?}"),
    };

    verify_delegation(
        &env,
        native_delegation.user_key,
        &native_delegation.signed_delegation,
        &env.root_key().unwrap(),
    );
    assert_eq!(
        native_delegation.signed_delegation.delegation.pubkey,
        session_key
    );
    Ok(())
}

#[test]
fn should_match_regular_delegation_for_same_origin() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let anchor_number = flows::register_anchor(&env, canister_id);
    let session_key = ByteBuf::from("same session key");
    let origin = "https://same-origin.com";

    let regular = api::prepare_delegation(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        origin,
        &session_key,
        None,
    )?;
    let request = PrepareNativeAuthorizationRequest {
        origin: origin.to_string(),
        ii_origin: "https://identity.test".to_string(),
        session_public_key: session_key,
        return_link: "https://app.example.com/callback".to_string(),
        max_time_to_live: None,
    };
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");
    api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?
    .expect("completion should succeed");

    let fetched = api::fetch_native_delegation(&env, canister_id, &prepared.request_id)?;
    let native_delegation = match fetched {
        FetchNativeDelegationResponse::SignedDelegation(native_delegation) => native_delegation,
        other => panic!("unexpected native delegation response: {other:?}"),
    };
    assert_eq!(native_delegation.user_key, regular.0);
    Ok(())
}

#[test]
fn should_return_pending_before_completion() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let request = PrepareNativeAuthorizationRequest {
        origin: "https://some-dapp.com".to_string(),
        ii_origin: "https://identity.test".to_string(),
        session_public_key: ByteBuf::from("pending session key"),
        return_link: "https://app.example.com/callback".to_string(),
        max_time_to_live: None,
    };
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");

    assert!(matches!(
        api::fetch_native_delegation(&env, canister_id, &prepared.request_id)?,
        FetchNativeDelegationResponse::Pending
    ));
    Ok(())
}

#[test]
fn should_reject_invalid_return_link() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let request = PrepareNativeAuthorizationRequest {
        origin: "https://some-dapp.com".to_string(),
        ii_origin: "https://identity.test".to_string(),
        session_public_key: ByteBuf::from("native session key"),
        return_link: "myapp://callback".to_string(),
        max_time_to_live: None,
    };

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(matches!(
        result,
        Err(PrepareNativeAuthorizationError::InvalidReturnLink(_))
    ));
    Ok(())
}

#[test]
fn should_reject_invalid_ii_origin() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let mut request = native_request();
    request.ii_origin = "https://identity.test:notaport".to_string();

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(matches!(
        result,
        Err(PrepareNativeAuthorizationError::InvalidOrigin(_))
    ));
    Ok(())
}

#[test]
fn should_reject_return_link_with_invalid_port() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let mut request = native_request();
    request.return_link = "https://app.example.com:notaport/callback".to_string();

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(matches!(
        result,
        Err(PrepareNativeAuthorizationError::InvalidReturnLink(_))
    ));
    Ok(())
}

#[test]
fn should_return_expired_after_ttl() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let request = PrepareNativeAuthorizationRequest {
        origin: "https://some-dapp.com".to_string(),
        ii_origin: "https://identity.test".to_string(),
        session_public_key: ByteBuf::from("native session key"),
        return_link: "https://app.example.com/callback".to_string(),
        max_time_to_live: Some(Duration::from_secs(1).as_nanos() as u64),
    };
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");
    env.advance_time(Duration::from_secs(2));
    env.tick();

    let loaded = api::get_native_authorization_request(&env, canister_id, &prepared.request_id)?;
    assert!(matches!(
        loaded,
        Err(GetNativeAuthorizationRequestError::Expired)
    ));
    assert!(matches!(
        api::fetch_native_delegation(&env, canister_id, &prepared.request_id)?,
        FetchNativeDelegationResponse::Expired
    ));
    Ok(())
}

#[test]
fn should_reject_unauthorized_completion() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let anchor_number = flows::register_anchor(&env, canister_id);
    let request = PrepareNativeAuthorizationRequest {
        origin: "https://some-dapp.com".to_string(),
        ii_origin: "https://identity.test".to_string(),
        session_public_key: ByteBuf::from("native session key"),
        return_link: "https://app.example.com/callback".to_string(),
        max_time_to_live: None,
    };
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");

    let result = api::complete_native_authorization(
        &env,
        canister_id,
        Principal::anonymous(),
        anchor_number,
        &prepared.request_id,
        None,
    )?;
    assert!(matches!(
        result,
        Err(CompleteNativeAuthorizationError::Unauthorized(_))
    ));
    Ok(())
}

#[test]
fn should_prune_expired_requests_on_next_prepare() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let request = PrepareNativeAuthorizationRequest {
        origin: "https://some-dapp.com".to_string(),
        ii_origin: "https://identity.test".to_string(),
        session_public_key: ByteBuf::from("native session key"),
        return_link: "https://app.example.com/callback".to_string(),
        max_time_to_live: Some(Duration::from_secs(1).as_nanos() as u64),
    };
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");
    env.advance_time(Duration::from_secs(2));
    env.tick();
    api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("second prepare should succeed");

    assert!(matches!(
        api::fetch_native_delegation(&env, canister_id, &prepared.request_id)?,
        FetchNativeDelegationResponse::NotFound
    ));
    Ok(())
}
