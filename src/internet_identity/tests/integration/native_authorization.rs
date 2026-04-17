//! Tests for native authorization request lifecycle.

use candid::Principal;
use canister_tests::api::internet_identity as api;
use canister_tests::flows;
use canister_tests::framework::*;
use internet_identity_interface::internet_identity::types::*;
use pocket_ic::RejectResponse;
use serde_bytes::ByteBuf;
use std::time::Duration;

const NATIVE_REQUEST_TTL_SECS: u64 = 5 * 60;
const COMPLETED_REQUEST_GRACE_PERIOD_SECS: u64 = 5 * 60;

fn native_request() -> PrepareNativeAuthorizationRequest {
    PrepareNativeAuthorizationRequest {
        origin: "https://app.example.com".to_string(),
        ii_origin: "https://identity.test".to_string(),
        session_public_key: ByteBuf::from("native session key"),
        return_link: "https://app.example.com/callback".to_string(),
        max_time_to_live: None,
    }
}

fn device_last_used(anchor_info: &IdentityAnchorInfo, device_key: &DeviceKey) -> Option<Timestamp> {
    anchor_info
        .devices
        .iter()
        .find(|device| &device.pubkey == device_key)
        .and_then(|device| device.last_usage)
}

#[test]
fn should_prepare_and_fetch_native_delegation() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let anchor_number = flows::register_anchor(&env, canister_id);
    let session_key = ByteBuf::from("native session key");
    let request = PrepareNativeAuthorizationRequest {
        origin: "https://app.example.com".to_string(),
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
fn should_store_canonical_origin_for_native_request() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let request = PrepareNativeAuthorizationRequest {
        origin: "https://App.Example.com:443".to_string(),
        ii_origin: "https://identity.test".to_string(),
        session_public_key: ByteBuf::from("native session key"),
        return_link: "https://app.example.com/callback".to_string(),
        max_time_to_live: None,
    };

    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");
    let loaded = api::get_native_authorization_request(&env, canister_id, &prepared.request_id)?
        .expect("native request should be readable before completion");
    assert_eq!(loaded.origin, "https://app.example.com");
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
        return_link: "https://same-origin.com/callback".to_string(),
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
        origin: "https://app.example.com".to_string(),
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
        origin: "https://app.example.com".to_string(),
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
fn should_reject_return_link_with_userinfo() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let mut request = native_request();
    request.return_link = "https://user@app.example.com/callback".to_string();

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
    assert!(
        matches!(
            result,
            Err(PrepareNativeAuthorizationError::InvalidOrigin(_))
        ),
        "unexpected result: {result:?}"
    );
    Ok(())
}

#[test]
fn should_reject_ii_origin_with_userinfo() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let mut request = native_request();
    request.ii_origin = "https://user@identity.test".to_string();

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(
        matches!(
            result,
            Err(PrepareNativeAuthorizationError::InvalidOrigin(_))
        ),
        "unexpected result: {result:?}"
    );
    Ok(())
}

#[test]
fn should_reject_invalid_origin() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let mut request = native_request();
    request.origin = "https://some-dapp.com/path".to_string();

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(
        matches!(
            result,
            Err(PrepareNativeAuthorizationError::InvalidOrigin(_))
        ),
        "unexpected result: {result:?}"
    );
    Ok(())
}

#[test]
fn should_reject_origin_that_does_not_match_return_link_origin() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let mut request = native_request();
    request.origin = "https://some-dapp.com".to_string();

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(
        matches!(
            result,
            Err(PrepareNativeAuthorizationError::InvalidOrigin(_))
        ),
        "unexpected result: {result:?}"
    );
    Ok(())
}

#[test]
fn should_reject_non_https_origin_even_if_return_link_matches() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let mut request = native_request();
    request.origin = "http://app.example.com".to_string();
    request.return_link = "https://app.example.com/callback".to_string();

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(
        matches!(
            result,
            Err(PrepareNativeAuthorizationError::InvalidOrigin(_))
        ),
        "unexpected result: {result:?}"
    );
    Ok(())
}

#[test]
fn should_accept_origin_matching_return_link_default_https_port() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let mut request = native_request();
    request.origin = "https://app.example.com".to_string();
    request.return_link = "https://app.example.com:443/callback".to_string();

    let result = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(result.is_ok());
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
fn should_expire_pending_request_after_fixed_ttl_even_with_long_delegation_ttl(
) -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let request = PrepareNativeAuthorizationRequest {
        origin: "https://app.example.com".to_string(),
        ii_origin: "https://identity.test".to_string(),
        session_public_key: ByteBuf::from("native session key"),
        return_link: "https://app.example.com/callback".to_string(),
        max_time_to_live: Some(Duration::from_secs(30 * 24 * 60 * 60).as_nanos() as u64),
    };
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");
    env.advance_time(Duration::from_secs(NATIVE_REQUEST_TTL_SECS + 1));
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
        origin: "https://app.example.com".to_string(),
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
fn should_expire_completed_request_after_grace_period() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let anchor_number = flows::register_anchor(&env, canister_id);
    let request = native_request();
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

    assert!(matches!(
        api::fetch_native_delegation(&env, canister_id, &prepared.request_id)?,
        FetchNativeDelegationResponse::SignedDelegation(_)
    ));

    env.advance_time(Duration::from_secs(COMPLETED_REQUEST_GRACE_PERIOD_SECS + 1));
    env.tick();

    assert!(matches!(
        api::fetch_native_delegation(&env, canister_id, &prepared.request_id)?,
        FetchNativeDelegationResponse::Expired
    ));
    Ok(())
}

#[test]
fn should_prune_expired_requests_on_next_prepare() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let request = PrepareNativeAuthorizationRequest {
        origin: "https://app.example.com".to_string(),
        ii_origin: "https://identity.test".to_string(),
        session_public_key: ByteBuf::from("native session key"),
        return_link: "https://app.example.com/callback".to_string(),
        max_time_to_live: Some(Duration::from_secs(30 * 24 * 60 * 60).as_nanos() as u64),
    };
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");
    env.advance_time(Duration::from_secs(NATIVE_REQUEST_TTL_SECS + 1));
    env.tick();
    api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("second prepare should succeed");

    assert!(matches!(
        api::fetch_native_delegation(&env, canister_id, &prepared.request_id)?,
        FetchNativeDelegationResponse::NotFound
    ));
    Ok(())
}

#[test]
fn should_prune_expired_completed_requests_on_next_prepare() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let anchor_number = flows::register_anchor(&env, canister_id);
    let request = native_request();
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

    env.advance_time(Duration::from_secs(COMPLETED_REQUEST_GRACE_PERIOD_SECS + 1));
    env.tick();
    api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("second prepare should succeed");

    assert!(matches!(
        api::fetch_native_delegation(&env, canister_id, &prepared.request_id)?,
        FetchNativeDelegationResponse::NotFound
    ));
    Ok(())
}

#[test]
fn should_keep_completed_request_fetchable_for_full_grace_period_after_short_pending_window(
) -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let anchor_number = flows::register_anchor(&env, canister_id);
    let request = native_request();
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");

    env.advance_time(Duration::from_secs(NATIVE_REQUEST_TTL_SECS - 30));
    env.tick();
    api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?
    .expect("completion should succeed");

    env.advance_time(Duration::from_secs(4 * 60 + 45));
    env.tick();
    assert!(matches!(
        api::fetch_native_delegation(&env, canister_id, &prepared.request_id)?,
        FetchNativeDelegationResponse::SignedDelegation(_)
    ));
    Ok(())
}

#[test]
fn should_not_record_activity_for_missing_or_expired_request() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let anchor_number = flows::register_anchor(&env, canister_id);

    let missing_result = api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        "missing-request",
        None,
    )?;
    assert!(matches!(
        missing_result,
        Err(CompleteNativeAuthorizationError::NotFound)
    ));
    assert!(!get_metrics(&env, canister_id).contains("internet_identity_daily_active_anchors"));

    let mut request = native_request();
    request.max_time_to_live = Some(Duration::from_secs(30 * 24 * 60 * 60).as_nanos() as u64);
    let prepared = api::prepare_native_authorization(&env, canister_id, &request)?
        .expect("prepare native authorization should succeed");
    env.advance_time(Duration::from_secs(NATIVE_REQUEST_TTL_SECS + 1));
    env.tick();

    let expired_result = api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?;
    assert!(matches!(
        expired_result,
        Err(CompleteNativeAuthorizationError::Expired)
    ));
    assert!(!get_metrics(&env, canister_id).contains("internet_identity_daily_active_anchors"));
    Ok(())
}

#[test]
fn should_not_update_last_used_on_already_completed_request() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let anchor_number = flows::register_anchor(&env, canister_id);
    api::add(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &recovery_device_data_1(),
    )?;
    let request = native_request();
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

    env.advance_time(Duration::from_secs(1));
    let anchor_info_before =
        api::get_anchor_info(&env, canister_id, principal_recovery_1(), anchor_number)?;
    let last_used_before = device_last_used(&anchor_info_before, &device_data_1().pubkey);

    env.advance_time(Duration::from_secs(1));
    let second_result = api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?;
    assert!(matches!(
        second_result,
        Err(CompleteNativeAuthorizationError::AlreadyCompleted)
    ));

    env.advance_time(Duration::from_secs(1));
    let anchor_info_after =
        api::get_anchor_info(&env, canister_id, principal_recovery_1(), anchor_number)?;
    assert_eq!(
        device_last_used(&anchor_info_after, &device_data_1().pubkey),
        last_used_before
    );
    Ok(())
}

#[test]
fn should_allow_retry_after_completion_fails_midway_before_pending_ttl_expires(
) -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let anchor_number = flows::register_anchor(&env, canister_id);
    let prepared = api::prepare_native_authorization(&env, canister_id, &native_request())?
        .expect("prepare native authorization should succeed");

    let failed = api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        Some(999_999),
    )?;
    assert!(matches!(
        failed,
        Err(CompleteNativeAuthorizationError::InternalCanisterError(_))
    ));
    assert!(matches!(
        api::get_native_authorization_request(&env, canister_id, &prepared.request_id)?,
        Ok(_)
    ));
    assert!(matches!(
        api::fetch_native_delegation(&env, canister_id, &prepared.request_id)?,
        FetchNativeDelegationResponse::Pending
    ));

    api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        None,
    )?
    .expect("completion retry should succeed");
    assert!(matches!(
        api::fetch_native_delegation(&env, canister_id, &prepared.request_id)?,
        FetchNativeDelegationResponse::SignedDelegation(_)
    ));
    Ok(())
}

#[test]
fn should_not_extend_pending_ttl_when_completion_fails_midway() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let anchor_number = flows::register_anchor(&env, canister_id);
    let prepared = api::prepare_native_authorization(&env, canister_id, &native_request())?
        .expect("prepare native authorization should succeed");

    let failed = api::complete_native_authorization(
        &env,
        canister_id,
        principal_1(),
        anchor_number,
        &prepared.request_id,
        Some(999_999),
    )?;
    assert!(matches!(
        failed,
        Err(CompleteNativeAuthorizationError::InternalCanisterError(_))
    ));

    env.advance_time(Duration::from_secs(NATIVE_REQUEST_TTL_SECS + 1));
    env.tick();

    assert!(matches!(
        api::get_native_authorization_request(&env, canister_id, &prepared.request_id)?,
        Err(GetNativeAuthorizationRequestError::Expired)
    ));
    assert!(matches!(
        api::complete_native_authorization(
            &env,
            canister_id,
            principal_1(),
            anchor_number,
            &prepared.request_id,
            None,
        )?,
        Err(CompleteNativeAuthorizationError::Expired)
    ));
    assert!(matches!(
        api::fetch_native_delegation(&env, canister_id, &prepared.request_id)?,
        FetchNativeDelegationResponse::Expired
    ));
    Ok(())
}

#[test]
fn should_reject_new_requests_when_capacity_is_exhausted_until_pending_requests_expire(
) -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_with_archive(&env, None, None);
    let request = native_request();

    for _ in 0..1_000 {
        let result = api::prepare_native_authorization(&env, canister_id, &request)?;
        assert!(result.is_ok());
    }

    let overflow = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(matches!(
        overflow,
        Err(PrepareNativeAuthorizationError::TooManyRequests)
    ));

    env.advance_time(Duration::from_secs(NATIVE_REQUEST_TTL_SECS + 1));
    env.tick();

    let recovered = api::prepare_native_authorization(&env, canister_id, &request)?;
    assert!(recovered.is_ok());
    Ok(())
}
