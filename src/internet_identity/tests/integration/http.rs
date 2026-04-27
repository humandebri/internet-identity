//! Tests for the HTTP interactions according to the HTTP gateway spec: https://internetcomputer.org/docs/current/references/ic-interface-spec/#http-gateway
//! Includes tests for the HTTP endpoint (including asset certification) and the metrics endpoint.

use crate::v2_api::authn_method_test_helpers::{
    create_identity_with_authn_method, create_identity_with_authn_methods,
    sample_webauthn_authn_method, test_authn_method,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use canister_tests::api::internet_identity::api_v2;
use canister_tests::api::{http_request, http_request_update, internet_identity as api};
use canister_tests::flows;
use canister_tests::framework::*;
use ic_cdk::api::management_canister::main::CanisterId;
use ic_response_verification::types::VerificationInfo;
use ic_response_verification::verify_request_response_pair;
use internet_identity_interface::http_gateway::{HttpRequest, HttpResponse};
use internet_identity_interface::internet_identity::types::vc_mvp::PrepareIdAliasRequest;
use internet_identity_interface::internet_identity::types::{
    AuthnMethod, AuthnMethodData, CaptchaConfig, CaptchaTrigger, ChallengeAttempt, DeviceData,
    FrontendHostname, InternetIdentityInit, InternetIdentitySynchronizedConfig, MetadataEntryV2,
    NativeOidcApplicationType, NativeOidcClientConfig, NativeOidcTokenEndpointAuthMethod,
    OpenIdConfig, PrepareNativeAuthorizationRequest,
};
use pocket_ic::{PocketIc, RejectResponse};
use serde_bytes::ByteBuf;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;

/// Verifies that the backend canister serves its assets with certification.
#[test]
fn ii_canister_serves_http_assets() -> Result<(), RejectResponse> {
    let assets: Vec<(&str, Option<&str>)> = vec![
        ("/.config.did.bin", None),
        ("/.well-known/ic-domains", None),
    ];
    let env = env();
    let canister_id = install_ii_canister(&env, II_WASM.clone());

    for (asset, encoding) in assets {
        for certification_version in 1..=2 {
            let request = HttpRequest {
                method: "GET".to_string(),
                url: asset.to_string(),
                headers: vec![],
                body: ByteBuf::new(),
                certificate_version: Some(certification_version),
            };
            let http_response = http_request(&env, canister_id, &request)?;

            assert_eq!(http_response.status_code, 200);

            if let Some(enc) = encoding {
                let (_, content_encoding) = http_response
                    .headers
                    .iter()
                    .find(|(name, _)| name.to_lowercase() == "content-encoding")
                    .expect("Content-Encoding header not found");
                assert_eq!(
                    content_encoding, enc,
                    "unexpected Content-Encoding header value"
                );
            }
            verify_security_headers(&http_response.headers, &None);

            let result = verify_response_certification(
                &env,
                canister_id,
                request,
                http_response,
                certification_version,
            );
            assert_eq!(result.verification_version, certification_version);
        }
    }
    Ok(())
}

/// Verifies that expected metrics are available via the HTTP endpoint.
#[test]
fn ii_canister_serves_http_metrics() -> Result<(), RejectResponse> {
    let metrics = vec![
        "internet_identity_user_count",
        "internet_identity_min_user_number",
        "internet_identity_max_user_number",
        "internet_identity_signature_count",
        "internet_identity_stable_memory_pages",
        "stable_memory_bytes",
        "internet_identity_heap_pages",
        "heap_memory_bytes",
        "internet_identity_last_upgrade_timestamp",
        "internet_identity_inflight_challenges",
        "internet_identity_users_in_registration_mode",
        "internet_identity_buffered_archive_entries",
        "internet_identity_prepare_id_alias_counter",
    ];
    let env = env();
    env.advance_time(Duration::from_secs(300)); // Advance time to see it reflected on the metrics endpoint

    // Spawn an archive so that we also get the archive related metrics
    let canister_id = install_ii_canister_with_arg(
        &env,
        II_WASM.clone(),
        arg_with_wasm_hash(ARCHIVE_WASM.clone()),
    );
    deploy_archive_via_ii(&env, canister_id);

    let metrics_body = get_metrics(&env, canister_id);
    for metric in metrics {
        let (_, metric_timestamp) = parse_metric(&metrics_body, metric);
        assert_eq!(
            metric_timestamp,
            Duration::from_nanos(time(&env)).as_millis() as u64,
            "metric timestamp did not match state machine time"
        )
    }
    Ok(())
}

/// Verifies that the metrics list the expected user range as configured.
#[test]
fn metrics_should_list_configured_user_range() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_canister_with_arg(
        &env,
        II_WASM.clone(),
        arg_with_anchor_range((10_123, 8_188_860)),
    );

    let metrics = get_metrics(&env, canister_id);

    let (min_user_number, _) = parse_metric(&metrics, "internet_identity_min_user_number");
    let (max_user_number, _) = parse_metric(&metrics, "internet_identity_max_user_number");
    assert_eq!(min_user_number, 10_123f64);
    assert_eq!(max_user_number, 8_188_859f64);
    Ok(())
}

/// Verifies that the metrics list the default user range if none is configured.
#[test]
fn metrics_should_list_default_user_range() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_canister(&env, II_WASM.clone());

    let metrics = get_metrics(&env, canister_id);

    let (min_user_number, _) = parse_metric(&metrics, "internet_identity_min_user_number");
    let (max_user_number, _) = parse_metric(&metrics, "internet_identity_max_user_number");
    assert_eq!(min_user_number, 10_000f64);
    assert_eq!(max_user_number, 67_116_815f64);
    Ok(())
}

/// Verifies that the user count metric is updated correctly.
#[test]
fn metrics_user_count_should_increase_after_register() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_canister(&env, II_WASM.clone());

    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_user_count",
        0f64,
    );
    for count in 0..2 {
        flows::register_anchor(&env, canister_id);
        assert_metric(
            &get_metrics(&env, canister_id),
            "internet_identity_user_count",
            (count + 1) as f64,
        );
    }
    Ok(())
}

/// Verifies that the signature count metric is updated correctly.
#[test]
fn metrics_signature_and_delegation_count() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_canister(&env, II_WASM.clone());
    let frontend_hostname = "https://some-dapp.com";
    let user_number = flows::register_anchor(&env, canister_id);

    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_signature_count",
        0f64,
    );
    for count in 0..3 {
        api::prepare_delegation(
            &env,
            canister_id,
            principal_1(),
            user_number,
            frontend_hostname,
            &ByteBuf::from(format!("session key {count}")),
            None,
        )?;

        assert_metric(
            &get_metrics(&env, canister_id),
            "internet_identity_signature_count",
            (count + 1) as f64,
        );
        assert_metric(
            &get_metrics(&env, canister_id),
            "internet_identity_delegation_counter",
            (count + 1) as f64,
        );
    }

    // long after expiry (we don't want this test to break, if we change the default delegation expiration)
    env.advance_time(Duration::from_secs(365 * 24 * 60 * 60));
    // we need to make an update call to prune expired delegations
    api::prepare_delegation(
        &env,
        canister_id,
        principal_1(),
        user_number,
        frontend_hostname,
        &ByteBuf::from("last session key"),
        None,
    )?;

    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_signature_count",
        1f64, // old ones pruned and a new one created
    );
    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_delegation_counter",
        4f64, // delegation counter is not affected by pruning
    );
    Ok(())
}

/// Verifies that the stable memory pages count metric is updated correctly.
#[test]
fn metrics_stable_memory_pages_should_increase_with_more_users() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_canister(&env, II_WASM.clone());

    let metrics = get_metrics(&env, canister_id);
    let (initial_memory_pages, _) = parse_metric(
        &metrics,
        "internet_identity_virtual_memory_size_pages{memory=\"stable_identities\"}",
    );

    // registering 25 anchors with 20 devices each to reach 500 devices total
    // this is much faster than 500 individual registrations
    for i in 0..25u16 {
        let mut authn_method = test_authn_method();
        // unique pubkey for each anchor registration
        if let AuthnMethod::WebAuthn(ref mut webauthn) = authn_method.authn_method {
            let mut pubkey = vec![0u8; 32];
            pubkey[0..2].copy_from_slice(&i.to_le_bytes());
            webauthn.pubkey = ByteBuf::from(pubkey);
        }

        let identity_number = create_identity_with_authn_method(&env, canister_id, &authn_method);

        // add 19 more devices to the same anchor
        for j in 1..20u16 {
            let mut device = test_authn_method();
            if let AuthnMethod::WebAuthn(ref mut webauthn) = device.authn_method {
                let mut pubkey = vec![0u8; 32];
                pubkey[0..2].copy_from_slice(&i.to_le_bytes());
                pubkey[2..4].copy_from_slice(&j.to_le_bytes());
                webauthn.pubkey = ByteBuf::from(pubkey);

                let mut cred_id = vec![0u8; 64];
                cred_id[0..2].copy_from_slice(&i.to_le_bytes());
                cred_id[2..4].copy_from_slice(&j.to_le_bytes());
                webauthn.credential_id = ByteBuf::from(cred_id);
            }
            device
                .metadata
                .insert("data".to_string(), MetadataEntryV2::String("a".repeat(200)));

            api_v2::authn_method_add(
                &env,
                canister_id,
                authn_method.principal(),
                identity_number,
                &device,
            )
            .unwrap()
            .unwrap();
        }
    }

    let canister_stats = api::stats(&env, canister_id).unwrap();
    assert_eq!(canister_stats.users_registered, 25);

    let metrics = get_metrics(&env, canister_id);
    let (pages_with_users, _) = parse_metric(
        &metrics,
        "internet_identity_virtual_memory_size_pages{memory=\"stable_identities\"}",
    );

    // Metrics are historically f64 values, but conceptually we expect integer values
    let initial_memory_pages = initial_memory_pages as u64;
    let pages_with_users = pages_with_users as u64;

    assert_eq!(
        initial_memory_pages + 1, pages_with_users,
        "initial_memory_pages ({}) + 1 should be equal to pages_with_users ({}) after registering 25 large anchors",
        initial_memory_pages,
        pages_with_users
    );
    Ok(())
}

/// Verifies that the last II wasm upgrade timestamp is updated correctly.
#[test]
fn metrics_last_upgrade_timestamp_should_update_after_upgrade() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_canister(&env, II_WASM.clone());
    // immediately upgrade because installing the canister does not set the metric
    upgrade_ii_canister(&env, canister_id, II_WASM.clone());

    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_last_upgrade_timestamp",
        time(&env) as f64,
    );

    env.advance_time(Duration::from_secs(300)); // the state machine does not advance time on its own
    upgrade_ii_canister(&env, canister_id, II_WASM.clone());

    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_last_upgrade_timestamp",
        time(&env) as f64,
    );
    Ok(())
}

/// Verifies that the inflight challenges metric is updated correctly.
#[test]
fn metrics_inflight_challenges() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id =
        install_ii_canister_with_arg(&env, II_WASM.clone(), arg_with_captcha_enabled());

    let metrics = get_metrics(&env, canister_id);
    let (challenge_count, _) = parse_metric(&metrics, "internet_identity_inflight_challenges");
    assert_eq!(challenge_count, 0f64);

    let challenge_1 = api::create_challenge(&env, canister_id)?;
    api::create_challenge(&env, canister_id)?;

    let metrics = get_metrics(&env, canister_id);
    let (challenge_count, _) = parse_metric(&metrics, "internet_identity_inflight_challenges");
    assert_eq!(challenge_count, 2f64);

    // solving a challenge removes it from the inflight pool
    api::register(
        &env,
        canister_id,
        principal_1(),
        &device_data_1(),
        &ChallengeAttempt {
            chars: "a".to_string(),
            key: challenge_1.challenge_key,
        },
        None,
    )?;

    let metrics = get_metrics(&env, canister_id);
    let (challenge_count, _) = parse_metric(&metrics, "internet_identity_inflight_challenges");
    assert_eq!(challenge_count, 1f64);

    // long after expiry (we don't want this test to break, if we change the captcha expiration)
    env.advance_time(Duration::from_secs(365 * 24 * 60 * 60));
    // the only call that prunes expired captchas
    api::create_challenge(&env, canister_id)?;

    let metrics = get_metrics(&env, canister_id);
    let (challenge_count, _) = parse_metric(&metrics, "internet_identity_inflight_challenges");
    assert_eq!(challenge_count, 1f64); // 1 pruned due to expiry, but also one created

    Ok(())
}

/// Verifies that the users in registration mode metric is updated correctly.
#[test]
fn metrics_device_registration_mode() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_canister(&env, II_WASM.clone());
    let user_number_1 = flows::register_anchor(&env, canister_id);
    let user_number_2 = flows::register_anchor(&env, canister_id);

    let metrics = get_metrics(&env, canister_id);
    let (challenge_count, _) =
        parse_metric(&metrics, "internet_identity_users_in_registration_mode");
    assert_eq!(challenge_count, 0f64);

    api::enter_device_registration_mode(&env, canister_id, principal_1(), user_number_1)?;
    api::enter_device_registration_mode(&env, canister_id, principal_1(), user_number_2)?;

    let metrics = get_metrics(&env, canister_id);
    let (challenge_count, _) =
        parse_metric(&metrics, "internet_identity_users_in_registration_mode");
    assert_eq!(challenge_count, 2f64);

    api::exit_device_registration_mode(&env, canister_id, principal_1(), user_number_1)?;

    let metrics = get_metrics(&env, canister_id);
    let (challenge_count, _) =
        parse_metric(&metrics, "internet_identity_users_in_registration_mode");
    assert_eq!(challenge_count, 1f64);

    // long after expiry (we don't want this test to break, if we change the registration mode expiration)
    env.advance_time(Duration::from_secs(365 * 24 * 60 * 60));
    // make an update call related to tentative devices so that registration mode expiry gets checked
    api::add_tentative_device(&env, canister_id, user_number_2, &device_data_2())?;

    let metrics = get_metrics(&env, canister_id);
    let (challenge_count, _) =
        parse_metric(&metrics, "internet_identity_users_in_registration_mode");
    assert_eq!(challenge_count, 0f64);

    Ok(())
}

/// Verifies that the anchor operation count metric is updated correctly.
#[test]
fn metrics_anchor_operations() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_canister(&env, II_WASM.clone());

    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_anchor_operations_counter",
        0f64,
    );

    let user_number = flows::register_anchor(&env, canister_id);
    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_anchor_operations_counter",
        1f64,
    );

    api::add(
        &env,
        canister_id,
        principal_1(),
        user_number,
        &device_data_2(),
    )?;
    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_anchor_operations_counter",
        2f64,
    );

    let mut device = device_data_2();
    device.alias = "new alias".to_string();
    api::update(
        &env,
        canister_id,
        principal_1(),
        user_number,
        &device.pubkey,
        &device,
    )?;
    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_anchor_operations_counter",
        3f64,
    );

    api::remove(
        &env,
        canister_id,
        principal_1(),
        user_number,
        &device_data_2().pubkey,
    )?;
    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_anchor_operations_counter",
        4f64,
    );

    Ok(())
}

#[test]
fn should_list_virtual_memory_metrics() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_canister(&env, II_WASM.clone());

    let metrics = get_metrics(&env, canister_id);
    assert_metric(
        &metrics,
        "internet_identity_virtual_memory_size_pages{memory=\"header\"}",
        1f64,
    );
    assert_metric(
        &metrics,
        "internet_identity_virtual_memory_size_pages{memory=\"stable_identities\"}",
        1f64,
    );
    assert_metric(
        &metrics,
        "internet_identity_virtual_memory_size_pages{memory=\"stable_accounts\"}",
        1f64,
    );
    assert_metric(
        &metrics,
        "internet_identity_virtual_memory_size_pages{memory=\"stable_applications\"}",
        1f64,
    );
    assert_metric(
        &metrics,
        "internet_identity_virtual_memory_size_pages{memory=\"archive_buffer\"}",
        1f64,
    );
    assert_metric(
        &metrics,
        "internet_identity_virtual_memory_size_pages{memory=\"event_data\"}",
        1f64,
    );
    assert_metric(
        &metrics,
        "internet_identity_virtual_memory_size_pages{memory=\"event_aggregations\"}",
        1f64,
    );
    assert_metric(
        &metrics,
        "internet_identity_virtual_memory_size_pages{memory=\"reference_registration_rate\"}",
        1f64,
    );
    assert_metric(
        &metrics,
        "internet_identity_virtual_memory_size_pages{memory=\"current_registration_rate\"}",
        1f64,
    );

    let authn_method = test_authn_method();
    create_identity_with_authn_method(&env, canister_id, &authn_method);

    let metrics = get_metrics(&env, canister_id);
    assert_metric(
        &metrics,
        "internet_identity_virtual_memory_size_pages{memory=\"header\"}",
        1f64,
    );
    assert_metric(
        &metrics,
        "internet_identity_virtual_memory_size_pages{memory=\"stable_identities\"}",
        1f64,
    );

    // To test the archive buffer and event data related memory metrics growing,
    // we would have a very complex setup and require a large number of request.
    // Or load a prepared state with a large number of entries.
    // This is not done here, as it would either require brittle setup or a long-running test.

    Ok(())
}

#[test]
fn should_list_aggregated_session_seconds_and_event_data_counters() -> Result<(), RejectResponse> {
    let pub_session_key = ByteBuf::from("session public key");
    let authn_method_ic0 = AuthnMethodData {
        metadata: HashMap::from([(
            "origin".to_string(),
            MetadataEntryV2::String("https://identity.ic0.app".to_string()),
        )]),
        ..sample_webauthn_authn_method(1)
    };
    let authn_method_internetcomputer = AuthnMethodData {
        metadata: HashMap::from([(
            "origin".to_string(),
            MetadataEntryV2::String("https://identity.internetcomputer.org".to_string()),
        )]),
        ..sample_webauthn_authn_method(2)
    };

    let env = env();
    let canister_id = install_ii_canister(&env, II_WASM.clone());
    let user_number_1 = create_identity_with_authn_methods(
        &env,
        canister_id,
        &[
            test_authn_method(),
            authn_method_ic0.clone(),
            authn_method_internetcomputer.clone(),
        ],
    );

    let metrics = get_metrics(&env, canister_id);
    // make sure empty data is not listed on the metrics endpoint
    assert!(!metrics.contains("internet_identity_prepare_delegation_session_seconds{"));
    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_event_data_count",
        0f64,
    );
    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_event_aggregations_count",
        0f64,
    );

    api::prepare_delegation(
        &env,
        canister_id,
        test_authn_method().principal(),
        user_number_1,
        "https://some-dapp-1.com",
        &pub_session_key,
        None,
    )?;
    api::prepare_delegation(
        &env,
        canister_id,
        authn_method_ic0.principal(),
        user_number_1,
        "https://some-dapp-2.com",
        &pub_session_key,
        Some(Duration::from_secs(3600).as_nanos() as u64),
    )?;
    api::prepare_delegation(
        &env,
        canister_id,
        authn_method_ic0.principal(),
        user_number_1,
        "https://some-dapp-2.com",
        &pub_session_key,
        None,
    )?;
    api::prepare_delegation(
        &env,
        canister_id,
        authn_method_internetcomputer.principal(),
        user_number_1,
        "https://some-dapp-3.com",
        &pub_session_key,
        None,
    )?;

    let metrics = get_metrics(&env, canister_id);
    assert_metric(
        &metrics,
        "internet_identity_prepare_delegation_session_seconds{dapp=\"https://some-dapp-2.com\",window=\"24h\",ii_origin=\"ic0.app\"}",
        5400f64,
    );
    assert_metric(
        &metrics,
        "internet_identity_prepare_delegation_count{dapp=\"https://some-dapp-2.com\",window=\"24h\",ii_origin=\"ic0.app\"}",
        2f64,
    );
    assert_metric(
        &metrics,
        "internet_identity_prepare_delegation_session_seconds{dapp=\"https://some-dapp-2.com\",window=\"30d\",ii_origin=\"ic0.app\"}",
        5400f64,
    );
    assert_metric(
        &metrics,
        "internet_identity_prepare_delegation_count{dapp=\"https://some-dapp-2.com\",window=\"30d\",ii_origin=\"ic0.app\"}",
        2f64,
    );
    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_event_data_count",
        4f64,
    );
    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_event_aggregations_count",
        12f64,
    );
    assert!(
        !metrics.contains(
            "internet_identity_prepare_delegation_session_seconds{dapp=\"https://some-dapp-3.com\",window=\"24h\""));
    assert!(!metrics.contains("ii_origin=\"other\""));
    assert!(!metrics.contains("ii_origin=\"internetcomputer.org\""));

    // advance time one day to see it reflected on the daily stats
    env.advance_time(Duration::from_secs(60 * 60 * 24));
    // call prepare delegation again to trigger stats update
    api::prepare_delegation(
        &env,
        canister_id,
        authn_method_internetcomputer.principal(),
        user_number_1,
        "https://some-dapp-4.com",
        &pub_session_key,
        None,
    )?;

    let metrics = get_metrics(&env, canister_id);
    // The 24h metrics should be gone now
    assert!(
        !metrics.contains(
            "internet_identity_prepare_delegation_session_seconds{dapp=\"https://some-dapp-2.com\",window=\"24h\""));
    assert!(
        !metrics.contains(
            "internet_identity_prepare_delegation_count{dapp=\"https://some-dapp-2.com\",window=\"24h\""));

    // The 30d metrics should still be there
    assert_metric(
        &metrics,
        "internet_identity_prepare_delegation_session_seconds{dapp=\"https://some-dapp-2.com\",window=\"30d\",ii_origin=\"ic0.app\"}",
        5400f64,
    );
    assert_metric(
        &metrics,
        "internet_identity_prepare_delegation_count{dapp=\"https://some-dapp-2.com\",window=\"30d\",ii_origin=\"ic0.app\"}",
        2f64,
    );
    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_event_data_count",
        5f64,
    );
    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_event_aggregations_count",
        10f64,
    );
    Ok(())
}

#[test]
fn should_list_prepare_id_alias_counter() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_canister(&env, II_WASM.clone());
    let identity_number = flows::register_anchor(&env, canister_id);

    let prepare_id_alias_req = PrepareIdAliasRequest {
        identity_number,
        relying_party: FrontendHostname::from("https://some-dapp.com"),
        issuer: FrontendHostname::from("https://some-issuer-1.com"),
    };

    for _ in 0..3 {
        api::vc_mvp::prepare_id_alias(
            &env,
            canister_id,
            principal_1(),
            prepare_id_alias_req.clone(),
        )?
        .expect("Got 'None' from prepare_id_alias");
    }

    assert_metric(
        &get_metrics(&env, canister_id),
        "internet_identity_prepare_id_alias_counter",
        3f64,
    );
    Ok(())
}

#[test]
fn should_report_registration_rates() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_canister_with_arg(
        &env,
        II_WASM.clone(),
        Some(InternetIdentityInit {
            captcha_config: Some(CaptchaConfig {
                max_unsolved_captchas: 500,
                // High threshold to avoid triggering captcha during the test,
                // since the dummy_captcha feature has been removed and real captchas
                // cannot be solved in tests.
                // With current_rate_sampling_interval_s=10 and reference_rate_sampling_interval_s=100,
                // the current_rate/reference_rate ratio is ~10x, so threshold_pct must be >= 900.
                captcha_trigger: CaptchaTrigger::Dynamic {
                    threshold_pct: 1000,
                    current_rate_sampling_interval_s: 10,
                    reference_rate_sampling_interval_s: 100,
                },
            }),
            ..InternetIdentityInit::default()
        }),
    );

    let metrics = get_metrics(&env, canister_id);
    assert_metric(
        &metrics,
        "internet_identity_registrations_per_second{type=\"reference_rate\"}",
        0.0,
    );
    assert_metric(
        &metrics,
        "internet_identity_registrations_per_second{type=\"current_rate\"}",
        0.0,
    );
    assert_metric(
        &metrics,
        "internet_identity_registrations_per_second{type=\"captcha_threshold_rate\"}",
        0.0,
    );

    for i in 0..20u8 {
        // make sure both registration flows are counted
        // Use unique devices to satisfy passkey pubkey uniqueness
        let legacy_device = DeviceData {
            pubkey: ByteBuf::from(vec![100 + i; 32]),
            alias: "test device".to_string(),
            credential_id: Some(ByteBuf::from(vec![100 + i; 16])),
            ..DeviceData::auth_test_device()
        };
        flows::register_anchor_with_device(&env, canister_id, &legacy_device); // legacy API
        create_identity_with_authn_method(&env, canister_id, &sample_webauthn_authn_method(i)); // v2 API
        env.advance_time(Duration::from_secs(1));
    }

    // advance time a little further to make reference rate be different from the current rate
    env.advance_time(Duration::from_secs(5));
    env.tick(); // tick for the advance time to become effective
    let metrics = get_metrics(&env, canister_id);
    assert_metric_approx(
        &metrics,
        "internet_identity_registrations_per_second{type=\"reference_rate\"}",
        0.4,
        0.1,
    );
    assert_metric_approx(
        &metrics,
        "internet_identity_registrations_per_second{type=\"current_rate\"}",
        2f64,
        0.1,
    );
    assert_metric_approx(
        &metrics,
        "internet_identity_registrations_per_second{type=\"captcha_threshold_rate\"}",
        4.4,
        0.1,
    );
    Ok(())
}

#[test]
fn should_report_total_account_metrics() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = install_ii_canister(&env, II_WASM.clone());
    let identity_number = flows::register_anchor(&env, canister_id);
    let origin = "https://some-dapp.com".to_string();
    let name = "Callisto".to_string();

    let initial_metrics = get_metrics(&env, canister_id);
    assert_metric(
        &initial_metrics,
        "internet_identity_total_accounts_count",
        0f64,
    );
    assert_metric(
        &initial_metrics,
        "internet_identity_total_account_references_count",
        0f64,
    );
    assert_metric(
        &initial_metrics,
        "internet_identity_total_application_count",
        0f64,
    );
    assert_metric(
        &initial_metrics,
        "internet_identity_account_counter_discrepancy_count",
        0f64,
    );

    let _ = api_v2::create_account(
        &env,
        canister_id,
        principal_1(),
        identity_number,
        origin.clone(),
        name.clone(),
    )?;
    let metrics = get_metrics(&env, canister_id);
    assert_metric(&metrics, "internet_identity_total_accounts_count", 1f64);
    assert_metric(
        &metrics,
        "internet_identity_total_account_references_count",
        // One for default account, one for created account
        2f64,
    );
    assert_metric(&metrics, "internet_identity_total_application_count", 1f64);
    Ok(())
}

/// Verifies that the `/.config.did.bin` asset can be decoded as `InternetIdentitySynchronizedConfig`.
#[test]
fn ii_canister_serves_decodable_synchronized_config() -> Result<(), RejectResponse> {
    let env = env();
    let openid_configs = vec![OpenIdConfig {
        name: "Test Provider".to_string(),
        logo: "https://example.com/logo.png".to_string(),
        issuer: "https://accounts.example.com".to_string(),
        client_id: "test-client-id".to_string(),
        jwks_uri: "https://example.com/.well-known/jwks.json".to_string(),
        auth_uri: "https://accounts.example.com/o/oauth2/auth".to_string(),
        auth_scope: vec!["openid".to_string(), "email".to_string()],
        fedcm_uri: None,
        email_verification: None,
    }];
    let config = InternetIdentityInit {
        openid_configs: Some(openid_configs.clone()),
        ..Default::default()
    };
    let canister_id = install_ii_canister_with_arg(&env, II_WASM.clone(), Some(config));

    let request = HttpRequest {
        method: "GET".to_string(),
        url: "/.config.did.bin".to_string(),
        headers: vec![],
        body: ByteBuf::new(),
        certificate_version: Some(2),
    };
    let http_response = http_request(&env, canister_id, &request)?;
    assert_eq!(http_response.status_code, 200);

    let decoded_config: InternetIdentitySynchronizedConfig =
        candid::decode_one(&http_response.body).expect(
            "Failed to decode /.config.did.bin response body as InternetIdentitySynchronizedConfig",
        );

    assert_eq!(
        decoded_config,
        InternetIdentitySynchronizedConfig {
            openid_configs: Some(openid_configs),
            native_oidc_clients: None,
            native_oidc_issuer_origin: None,
        }
    );

    verify_security_headers(&http_response.headers, &None);

    let result = verify_response_certification(&env, canister_id, request, http_response, 2);
    assert_eq!(result.verification_version, 2);

    Ok(())
}

#[test]
fn ii_canister_serves_openid_configuration_and_jwks() -> Result<(), RejectResponse> {
    let env = env();
    let mut init_arg = arg_with_wasm_hash(ARCHIVE_WASM.clone()).unwrap();
    init_arg.native_oidc_issuer_origin = Some("https://identity.ic0.app".to_string());
    let canister_id = install_ii_canister_with_arg(&env, II_WASM.clone(), Some(init_arg));
    api::init_salt(&env, canister_id)?;

    let configuration_request = HttpRequest {
        method: "GET".to_string(),
        url: "/.well-known/openid-configuration".to_string(),
        headers: vec![
            ("host".to_string(), "identity.test".to_string()),
            ("x-forwarded-proto".to_string(), "https".to_string()),
        ],
        body: ByteBuf::new(),
        certificate_version: Some(2),
    };
    let configuration_response = http_request(&env, canister_id, &configuration_request)?;
    assert_eq!(configuration_response.status_code, 200);
    assert_cors_header(&configuration_response.headers);
    let configuration_json: Value =
        serde_json::from_slice(&configuration_response.body).expect("openid config should parse");
    assert_eq!(configuration_json["issuer"], "https://identity.ic0.app");
    assert_eq!(
        configuration_json["authorization_endpoint"],
        "https://identity.ic0.app/authorize"
    );
    assert_eq!(
        configuration_json["token_endpoint"],
        "https://identity.ic0.app/oauth2/token"
    );
    assert_eq!(
        configuration_json["ic_delegation_endpoint"],
        "https://identity.ic0.app/oauth2/delegation"
    );
    assert_eq!(
        configuration_json["jwks_uri"],
        "https://identity.ic0.app/oauth2/jwks"
    );
    assert_eq!(configuration_json["subject_types_supported"][0], "pairwise");
    assert!(configuration_json.get("delegation_endpoint").is_none());

    let jwks_request = HttpRequest {
        method: "GET".to_string(),
        url: "/oauth2/jwks".to_string(),
        headers: vec![],
        body: ByteBuf::new(),
        certificate_version: Some(2),
    };
    let jwks_response = http_request(&env, canister_id, &jwks_request)?;
    assert_eq!(jwks_response.status_code, 200);
    assert_cors_header(&jwks_response.headers);
    let jwks_json: Value = serde_json::from_slice(&jwks_response.body).expect("jwks should parse");
    let keys = jwks_json["keys"]
        .as_array()
        .expect("jwks keys should be an array");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "RSA");
    assert_eq!(keys[0]["alg"], "RS256");

    Ok(())
}

#[test]
fn ii_canister_serves_native_oidc_token_and_delegation_http_endpoints() -> Result<(), RejectResponse>
{
    let env = env();
    let verifier = "native-browser-authorization-pkce-verifier-value";
    let client_id = "com.example.app";
    let redirect_uri = "https://app.example.com/callback";
    let mut init_arg = arg_with_wasm_hash(ARCHIVE_WASM.clone()).unwrap();
    init_arg.native_oidc_issuer_origin = Some("https://identity.ic0.app".to_string());
    init_arg.native_oidc_clients = Some(vec![NativeOidcClientConfig {
        client_id: client_id.to_string(),
        redirect_uris: vec![redirect_uri.to_string()],
        allowed_origins: vec!["https://app.example.com".to_string()],
        application_type: NativeOidcApplicationType::Native,
        token_endpoint_auth_method: NativeOidcTokenEndpointAuthMethod::None,
        require_pkce: true,
    }]);
    let canister_id = install_ii_canister_with_arg(&env, II_WASM.clone(), Some(init_arg));
    api::init_salt(&env, canister_id)?;
    let anchor_number = flows::register_anchor(&env, canister_id);

    let prepared = api::prepare_native_authorization(
        &env,
        canister_id,
        &PrepareNativeAuthorizationRequest {
            origin: "https://app.example.com".to_string(),
            ii_origin: "https://identity.ic0.app".to_string(),
            session_public_key: ByteBuf::from(b"native session key".to_vec()),
            redirect_uri: redirect_uri.to_string(),
            client_id: client_id.to_string(),
            state: "state-123".to_string(),
            scope: vec!["openid".to_string()],
            nonce: "nonce-123".to_string(),
            code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
            code_challenge_method: "S256".to_string(),
            response_type: "code".to_string(),
            response_mode: "query".to_string(),
            max_time_to_live: None,
        },
    )?
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

    let token_request = HttpRequest {
        method: "POST".to_string(),
        url: "/oauth2/token".to_string(),
        headers: vec![(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        body: ByteBuf::from(
            format!(
                "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}&client_id={}",
                prepared.request_id, redirect_uri, verifier, client_id
            )
            .into_bytes(),
        ),
        certificate_version: None,
    };
    let token_response = http_request_update(&env, canister_id, &token_request)?;
    assert_eq!(token_response.status_code, 200);
    assert_cors_header(&token_response.headers);
    assert_no_store_headers(&token_response.headers);
    let token_json: Value =
        serde_json::from_slice(&token_response.body).expect("token response should parse");
    let access_token = token_json["access_token"]
        .as_str()
        .expect("access_token should be present");

    let delegation_preflight_response = http_request(
        &env,
        canister_id,
        &HttpRequest {
            method: "OPTIONS".to_string(),
            url: "/oauth2/delegation".to_string(),
            headers: vec![],
            body: ByteBuf::new(),
            certificate_version: None,
        },
    )?;
    assert_eq!(delegation_preflight_response.status_code, 204);
    assert_cors_header(&delegation_preflight_response.headers);
    assert_header_value(
        &delegation_preflight_response.headers,
        "Access-Control-Allow-Methods",
        "GET, OPTIONS",
    );
    assert_header_value(
        &delegation_preflight_response.headers,
        "Access-Control-Allow-Headers",
        "authorization, content-type",
    );

    let token_preflight_response = http_request(
        &env,
        canister_id,
        &HttpRequest {
            method: "OPTIONS".to_string(),
            url: "/oauth2/token".to_string(),
            headers: vec![],
            body: ByteBuf::new(),
            certificate_version: None,
        },
    )?;
    assert_eq!(token_preflight_response.status_code, 204);
    assert_cors_header(&token_preflight_response.headers);
    assert_header_value(
        &token_preflight_response.headers,
        "Access-Control-Allow-Methods",
        "POST, OPTIONS",
    );
    assert_header_value(
        &token_preflight_response.headers,
        "Access-Control-Allow-Headers",
        "authorization, content-type",
    );

    let delegation_request = HttpRequest {
        method: "GET".to_string(),
        url: "/oauth2/delegation".to_string(),
        headers: vec![(
            "Authorization".to_string(),
            format!("Bearer {access_token}"),
        )],
        body: ByteBuf::new(),
        certificate_version: None,
    };
    let delegation_response = http_request(&env, canister_id, &delegation_request)?;
    assert_eq!(delegation_response.status_code, 200);
    assert_cors_header(&delegation_response.headers);
    assert_no_store_headers(&delegation_response.headers);
    let delegation_json: Value = serde_json::from_slice(&delegation_response.body)
        .expect("delegation response should parse");
    assert!(delegation_json.get("user_key").is_some());
    assert!(delegation_json.get("signed_delegation").is_some());

    let query_fallback_response = http_request(
        &env,
        canister_id,
        &HttpRequest {
            method: "GET".to_string(),
            url: format!("/oauth2/delegation?access_token={access_token}"),
            headers: vec![],
            body: ByteBuf::new(),
            certificate_version: None,
        },
    )?;
    assert_eq!(query_fallback_response.status_code, 200);
    assert_no_store_headers(&query_fallback_response.headers);

    let header_precedence_response = http_request(
        &env,
        canister_id,
        &HttpRequest {
            method: "GET".to_string(),
            url: "/oauth2/delegation?access_token=wrong-token".to_string(),
            headers: vec![(
                "Authorization".to_string(),
                format!("Bearer {access_token}"),
            )],
            body: ByteBuf::new(),
            certificate_version: None,
        },
    )?;
    assert_eq!(header_precedence_response.status_code, 200);
    assert_no_store_headers(&header_precedence_response.headers);

    let token_error_response = http_request_update(
        &env,
        canister_id,
        &HttpRequest {
            method: "POST".to_string(),
            url: "/oauth2/token".to_string(),
            headers: vec![(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            )],
            body: ByteBuf::from(
                format!(
                    "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}",
                    prepared.request_id, redirect_uri, client_id
                )
                .into_bytes(),
            ),
            certificate_version: None,
        },
    )?;
    assert_eq!(token_error_response.status_code, 400);
    assert_no_store_headers(&token_error_response.headers);

    let delegation_error_response = http_request(
        &env,
        canister_id,
        &HttpRequest {
            method: "GET".to_string(),
            url: "/oauth2/delegation?access_token=missing-token".to_string(),
            headers: vec![],
            body: ByteBuf::new(),
            certificate_version: None,
        },
    )?;
    assert_eq!(delegation_error_response.status_code, 404);
    assert_no_store_headers(&delegation_error_response.headers);

    let delegation_missing_token_response = http_request(
        &env,
        canister_id,
        &HttpRequest {
            method: "GET".to_string(),
            url: "/oauth2/delegation".to_string(),
            headers: vec![],
            body: ByteBuf::new(),
            certificate_version: None,
        },
    )?;
    assert_eq!(delegation_missing_token_response.status_code, 400);
    assert_no_store_headers(&delegation_missing_token_response.headers);

    let token_method_response = http_request(
        &env,
        canister_id,
        &HttpRequest {
            method: "GET".to_string(),
            url: "/oauth2/token".to_string(),
            headers: vec![],
            body: ByteBuf::new(),
            certificate_version: None,
        },
    )?;
    assert_eq!(token_method_response.status_code, 405);
    assert_header_value(&token_method_response.headers, "Allow", "POST, OPTIONS");

    let delegation_method_response = http_request_update(
        &env,
        canister_id,
        &HttpRequest {
            method: "POST".to_string(),
            url: "/oauth2/delegation".to_string(),
            headers: vec![],
            body: ByteBuf::new(),
            certificate_version: None,
        },
    )?;
    assert_eq!(delegation_method_response.status_code, 405);
    assert_header_value(&delegation_method_response.headers, "Allow", "GET, OPTIONS");

    Ok(())
}

fn verify_response_certification(
    env: &PocketIc,
    canister_id: CanisterId,
    request: HttpRequest,
    http_response: HttpResponse,
    min_certification_version: u16,
) -> VerificationInfo {
    verify_request_response_pair(
        request.try_into().expect("Cannot represent HttpRequest"),
        http_response
            .try_into()
            .expect("Cannot represent HttpResponse"),
        canister_id.as_slice(),
        time(env) as u128,
        Duration::from_secs(300).as_nanos(),
        &env.root_key().unwrap(),
        min_certification_version as u8,
    )
    .unwrap_or_else(|e| panic!("validation failed: {e}"))
}

fn assert_cors_header(headers: &[(String, String)]) {
    let (_, value) = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("access-control-allow-origin"))
        .expect("Access-Control-Allow-Origin header not found");
    assert_eq!(value, "*");
}

fn assert_no_store_headers(headers: &[(String, String)]) {
    assert_header_value(headers, "Cache-Control", "no-store, no-cache, max-age=0");
    assert_header_value(headers, "Pragma", "no-cache");
}

fn assert_header_value(headers: &[(String, String)], name: &str, expected: &str) {
    let (_, value) = headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .unwrap_or_else(|| panic!("{name} header not found"));
    assert_eq!(value, expected);
}
