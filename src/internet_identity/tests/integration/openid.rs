//! Tests related to openid_credential_add, openid_credential_remove, openid_prepare_delegation and openid_get_delegation

use crate::v2_api::authn_method_test_helpers::{
    create_identity_with_authn_method, create_identity_with_openid_credential,
};
use candid::Principal;
use canister_tests::{api::internet_identity as api, framework::*};
use identity_jose::{jwk::Jwk, jws::Decoder};
use internet_identity_interface::internet_identity::types::{
    ArchiveConfig, AuthnMethod, AuthnMethodData, AuthnMethodProtection, AuthnMethodPurpose,
    AuthnMethodSecuritySettings, DeployArchiveResult, InternetIdentityInit, OpenIdConfig,
    OpenIdCredentialAddError, OpenIdCredentialKey, OpenIdDelegationError, PublicKeyAuthn,
};
use pocket_ic::common::rest::{CanisterHttpReply, CanisterHttpResponse, MockCanisterHttpResponse};
use pocket_ic::{PocketIc, RejectResponse};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::time::Duration;

fn sync_time(env: &PocketIc, test_time: u64) {
    let time_to_advance = Duration::from_millis(test_time) - Duration::from_nanos(time(env));
    env.advance_time(time_to_advance);
}

/// Verifies that Google Accounts can be added
#[test]
fn can_link_google_account() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = setup_canister(&env);
    let (jwt, salt, _claims, test_time, test_principal, test_authn_method) =
        openid_google_test_data();

    let identity_number = create_identity_with_authn_method(&env, canister_id, &test_authn_method);

    sync_time(&env, test_time);

    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal, identity_number)?,
        0
    );

    let _ = api::openid_credential_add(
        &env,
        canister_id,
        test_principal,
        identity_number,
        &jwt,
        &salt,
    )?;

    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal, identity_number)?,
        1
    );

    Ok(())
}

/// Verifies that Microsoft Accounts can be added
#[test]
fn can_link_microsoft_account() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = setup_canister(&env);
    let (jwt, salt, _claims, test_time, test_principal, test_authn_method) =
        one_openid_microsoft_test_data();

    let identity_number = create_identity_with_authn_method(&env, canister_id, &test_authn_method);

    sync_time(&env, test_time);

    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal, identity_number)?,
        0
    );

    let _ = api::openid_credential_add(
        &env,
        canister_id,
        test_principal,
        identity_number,
        &jwt,
        &salt,
    )?;

    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal, identity_number)?,
        1
    );

    Ok(())
}

/// Verifies that the same Microsoft account cannot be linked to two different identities
#[test]
fn cannot_link_same_microsoft_account_to_two_identities() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = setup_canister(&env);
    let (jwt, salt, _claims, test_time, test_principal, test_authn_method) =
        one_openid_microsoft_test_data();
    // This is the same Microsoft account as the one in `one_openid_microsoft_test_data`, but with a different principal.
    // This information is part of the hardcoded JWT.
    let (jwt2, salt2, _claims2, test_time2, test_principal2, test_authn_method2) =
        openid_microsoft_same_as_one_but_different_principal_test_data();

    let identity_number = create_identity_with_authn_method(&env, canister_id, &test_authn_method);
    let identity_number2 =
        create_identity_with_authn_method(&env, canister_id, &test_authn_method2);

    sync_time(&env, test_time);

    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal, identity_number)?,
        0
    );
    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal2, identity_number2)?,
        0
    );

    let _ = api::openid_credential_add(
        &env,
        canister_id,
        test_principal,
        identity_number,
        &jwt,
        &salt,
    )?;

    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal, identity_number)?,
        1
    );
    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal2, identity_number2)?,
        0
    );

    sync_time(&env, test_time2);

    let result = api::openid_credential_add(
        &env,
        canister_id,
        test_principal2,
        identity_number2,
        &jwt2,
        &salt2,
    )?;

    assert_eq!(
        result,
        Err(OpenIdCredentialAddError::OpenIdCredentialAlreadyRegistered)
    );
    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal, identity_number)?,
        1
    );
    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal2, identity_number2)?,
        0
    );

    Ok(())
}

// Linking Microsoft accounts from different tenants to the same identity is not allowed in the frontend, but is allowed in the backend.
// This test verifies that the backend permits this behaviour.
#[test]
fn can_link_microsoft_account_from_different_tenant() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = setup_canister(&env);
    let (jwt, salt, _claims, test_time, test_principal, test_authn_method) =
        one_openid_microsoft_test_data();
    // The tenant is part of `jwt`
    let (jwt2, salt2, _claims2, test_time2, _test_principal2, _test_authn_method2) =
        second_openid_microsoft_test_data();

    let identity_number = create_identity_with_authn_method(&env, canister_id, &test_authn_method);

    sync_time(&env, test_time);

    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal, identity_number)?,
        0
    );

    let _ = api::openid_credential_add(
        &env,
        canister_id,
        test_principal,
        identity_number,
        &jwt,
        &salt,
    )?;

    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal, identity_number)?,
        1
    );

    sync_time(&env, test_time2);

    let _ = api::openid_credential_add(
        &env,
        canister_id,
        test_principal,
        identity_number,
        &jwt2,
        &salt2,
    )?;

    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal, identity_number)?,
        2
    );

    Ok(())
}

/// Verifies that Google Accounts can be removed
#[test]
fn can_remove_google_account() -> Result<(), RejectResponse> {
    let env = env();
    let canister_id = setup_canister(&env);
    #[allow(unused_variables)]
    let (jwt, salt, claims, test_time, test_principal, test_authn_method) =
        openid_google_test_data();

    let identity_number = create_identity_with_authn_method(&env, canister_id, &test_authn_method);

    sync_time(&env, test_time);

    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal, identity_number)?,
        0
    );

    let _ = api::openid_credential_add(
        &env,
        canister_id,
        test_principal,
        identity_number,
        &jwt,
        &salt,
    )?;

    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal, identity_number)?,
        1
    );

    let _ = api::openid_credential_remove(
        &env,
        canister_id,
        test_principal,
        identity_number,
        &claims.key(),
    )?;

    // Try to get delegation based on credential, should fail now
    // Create session key
    let pub_session_key = ByteBuf::from("session public key");

    assert_eq!(
        number_of_openid_credentials(&env, canister_id, test_principal, identity_number)?,
        0
    );

    // Prepare the delegation
    match api::openid_prepare_delegation(
        &env,
        canister_id,
        test_principal,
        &jwt,
        &salt,
        &pub_session_key,
    )? {
        Ok(_) => panic!("We shouldn't be able to get a delegation here!"),
        Err(err) => match err {
            OpenIdDelegationError::NoSuchAnchor => Ok(()),
            _ => panic!("We should get a NoSuchAnchor error here!"),
        },
    }
}

/// Verifies that valid JWT delegations are issued based on added credential.
#[test]
fn can_get_valid_jwt_delegation() -> Result<(), RejectResponse> {
    let env = env();

    let canister_id = setup_canister(&env);

    let (jwt, salt, _claims, test_time, test_principal, test_authn_method) =
        openid_google_test_data();

    // Create identity
    let identity_number = create_identity_with_authn_method(&env, canister_id, &test_authn_method);

    sync_time(&env, test_time);

    let _ = api::openid_credential_add(
        &env,
        canister_id,
        test_principal,
        identity_number,
        &jwt,
        &salt,
    )?;

    // Create session key
    let pub_session_key = ByteBuf::from("session public key");

    // Prepare the delegation
    let prepare_response = match api::openid_prepare_delegation(
        &env,
        canister_id,
        test_principal,
        &jwt,
        &salt,
        &pub_session_key,
    )? {
        Ok(response) => response,
        Err(err) => panic!("Failing at openid_prepare_delegation: {err:?}"),
    };

    assert_eq!(
        prepare_response.expiration,
        time(&env) + Duration::from_secs(30 * 60).as_nanos() as u64 // default expiration: 30 minutes
    );

    // Get the delegation
    let signed_delegation = match api::openid_get_delegation(
        &env,
        canister_id,
        test_principal,
        &jwt,
        &salt,
        &pub_session_key,
        &prepare_response.expiration,
    )? {
        Ok(signed_delegation) => signed_delegation,
        Err(err) => {
            panic!("Failing at openid_get_delegation: {err:?}")
        }
    };

    // Verify the delegation
    verify_delegation(
        &env,
        prepare_response.user_key,
        &signed_delegation,
        &env.root_key().unwrap(),
    );
    assert_eq!(signed_delegation.delegation.pubkey, pub_session_key);
    assert_eq!(
        signed_delegation.delegation.expiration,
        prepare_response.expiration
    );
    Ok(())
}

/// Verifies that you can register with google
#[test]
fn can_register_with_google() -> Result<(), RejectResponse> {
    let env = env();

    let canister_id = setup_canister(&env);

    let (jwt, salt, _claims, test_time, test_principal, _test_authn_method) =
        openid_google_test_data();

    sync_time(&env, test_time);

    // Create identity (this will panic if it doesn't work)
    // the test principal here is technically from webauthn, while in practice it would be a temporary random frontend keypair
    // however, this makes no functional difference. we just need a principal and salt together with a jwt
    // which contains a signed nonce derived from said principal and salt.

    let _identity_number =
        create_identity_with_openid_credential(&env, canister_id, &jwt, &salt, test_principal);

    Ok(())
}

#[test]
fn can_register_with_microsoft() -> Result<(), RejectResponse> {
    let env = env();

    let canister_id = setup_canister(&env);

    let (jwt, salt, _claims, test_time, test_principal, _test_authn_method) =
        one_openid_microsoft_test_data();

    sync_time(&env, test_time);

    // Create identity (this will panic if it doesn't work)
    // the test principal here is technically from webauthn, while in practice it would be a temporary random frontend keypair
    // however, this makes no functional difference. we just need a principal and salt together with a jwt
    // which contains a signed nonce derived from said principal and salt.

    let _identity_number =
        create_identity_with_openid_credential(&env, canister_id, &jwt, &salt, test_principal);

    Ok(())
}

/// Verifies that you cannot register with a faulty jwt
#[test]
#[should_panic]
fn cannot_register_with_faulty_jwt() {
    let env = env();

    let canister_id = setup_canister(&env);

    let (_jwt, salt, _claims, test_time, test_principal, _test_authn_method) =
        openid_google_test_data();

    let faulty_jwt = concat!("eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtcnNhLWtleSIsInR5cCI6IkpXVCJ9", ".", "eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiIzNjA1ODc5OTE2NjgtNjNicGMxZ25ncDFzNWdibzFhbGRhbDRhNTBjMWowYmIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiJ0ZXN0LWdvb2dsZS1zdWJqZWN0LTEiLCJub25jZSI6ImZCRzFLcjNRa3lnR0d6U0lYb093andEX3lCOFdLQV9xUk9SVmMwWnRYeUkiLCJpYXQiOjE3NDA1ODM3MTIsIm5iZiI6MTc0MDU4MzcxMiwiZXhwIjoxNzQwNTg3MzEyLCJlbWFpbCI6Im9wZW5pZC1nb29nbGUtMUBleGFtcGxlLnRlc3QiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6Ik9wZW5JRCBHb29nbGUgT25lIn0", ".", "xiRc3a0oowsvWo5sfSHL-IStohmB0GabTPjb9xgBw6GEdJToGYc2wF7Wr5Vw9tnMqNCPNs4wpwPvImRy5eFBoJY4WqIhVFDjRSXKm0VZmd__OjgpZgpGihtjbX49X30u2U5fVYWVIkAhOxvWSTYD5cH2T8JKtJ_p_K9Ze-DCxtC4rhnQRykR5pcQIuYdUhgqBVbNcBXIwm4_LVxL9V-w2D_xGDYWAjbaqEXx-IcfVr7X2thu5KmEAqfKmW5cYDYafDLjIRImOfof7VpF8V3B0ShJTgFci03YEqJUkBwqGp0rtIamcVnGW4c8o77U5BEkov9-dBYQO1nn_grIudfV2g");

    sync_time(&env, test_time);

    // Create identity - this will panic if it doesn't work. It should panic as we are using a faulty jwt.

    let _identity_number = create_identity_with_openid_credential(
        &env,
        canister_id,
        faulty_jwt,
        &salt,
        test_principal,
    );
}

/// Verifies that JWT cannot be maliciously gotten by reassociating the credential and anchors between the prepare and get calls.
#[test]
fn cannot_get_valid_jwt_delegation_after_reassociation() -> Result<(), RejectResponse> {
    let env = env();

    let canister_id = setup_canister(&env);

    let (jwt, salt, claims, test_time, test_principal, test_authn_method_data) =
        openid_google_test_data();
    let (
        second_jwt,
        second_salt,
        _second_claims,
        second_test_time,
        second_test_principal,
        second_test_authn_method_data,
    ) = second_openid_google_test_data();

    // Create identity
    let identity_number =
        create_identity_with_authn_method(&env, canister_id, &test_authn_method_data);

    // Link Google Account to Identity
    let time_to_advance = Duration::from_millis(test_time) - Duration::from_nanos(time(&env));
    let second_time_to_advance =
        Duration::from_millis(second_test_time) - Duration::from_millis(test_time);

    env.advance_time(time_to_advance);

    let _ = api::openid_credential_add(
        &env,
        canister_id,
        test_principal,
        identity_number,
        &jwt,
        &salt,
    )?;

    // Create session key
    let pub_session_key = ByteBuf::from("session public key");

    // Prepare the delegation
    let prepare_response = match api::openid_prepare_delegation(
        &env,
        canister_id,
        test_principal,
        &jwt,
        &salt,
        &pub_session_key,
    )? {
        Ok(response) => response,
        Err(err) => panic!("Failing at openid_prepare_delegation: {err:?}"),
    };

    assert_eq!(
        prepare_response.expiration,
        time(&env) + Duration::from_secs(30 * 60).as_nanos() as u64 // default expiration: 30 minutes
    );

    let _ = api::openid_credential_remove(
        &env,
        canister_id,
        test_principal,
        identity_number,
        &claims.key(),
    )?;

    env.advance_time(second_time_to_advance);

    let second_identity_number =
        create_identity_with_authn_method(&env, canister_id, &second_test_authn_method_data);

    let _ = api::openid_credential_add(
        &env,
        canister_id,
        second_test_principal,
        second_identity_number,
        &second_jwt,
        &second_salt,
    )?;

    // Get the delegation
    match api::openid_get_delegation(
        &env,
        canister_id,
        second_test_principal,
        &second_jwt,
        &second_salt,
        &pub_session_key, // Note that this only works if we have access to the original session key
        &prepare_response.expiration,
    )? {
        Ok(_) => panic!("Should not have been able to get delegation"),
        Err(_) => Ok(()),
    }
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub nonce: String,
    pub iat: u64,
    // Optional Google specific claims
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
}

impl Claims {
    fn key(&self) -> OpenIdCredentialKey {
        (self.iss.clone(), self.sub.clone(), self.aud.clone())
    }
}

#[derive(Serialize, Deserialize)]
struct Certs {
    keys: Vec<Jwk>,
}

pub fn setup_canister(env: &PocketIc) -> Principal {
    let args = InternetIdentityInit {
        openid_configs: Some(vec![OpenIdConfig {
            name: "Google".into(),
            logo: "<svg viewBox=\"0 0 24 24\"><path d=\"M12.19 2.83A9.15 9.15 0 0 0 4 16.11c1.5 3 4.6 5.06 8.18 5.06 2.47 0 4.55-.82 6.07-2.22a8.95 8.95 0 0 0 2.73-6.74c0-.65-.06-1.28-.17-1.88h-8.63v3.55h4.93a4.23 4.23 0 0 1-1.84 2.76c-3.03 2-7.12.55-8.22-2.9h-.01a5.5 5.5 0 0 1 5.14-7.26 5 5 0 0 1 3.5 1.37l2.63-2.63a8.8 8.8 0 0 0-6.13-2.39z\" style=\"fill: currentColor;\"></path></svg>".into(),
            issuer: "https://accounts.google.com".into(),
            client_id: "360587991668-63bpc1gngp1s5gbo1aldal4a50c1j0bb.apps.googleusercontent.com"
                .into(),
            jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".into(),
            auth_uri: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            auth_scope: vec!["openid".into(), "profile".into(), "email".into()],
            fedcm_uri: Some("https://accounts.google.com/gsi/fedcm.json".into()),
            email_verification: None,
        }, OpenIdConfig {
            name: "Microsoft".into(),
            logo: "<svg viewBox=\"0 0 24 24\"><path d=\"M2.5 2.5h9v9h-9zm10 0h9v9h-9zm-10 10h9v9h-9zm10 0h9v9h-9z\" style=\"fill: currentColor;\"></path></svg>".into(),
            issuer: "https://login.microsoftonline.com/{tid}/v2.0".into(),
            client_id: "d948c073-eebd-4ab8-861d-055f7ab49e17"
                .into(),
            jwks_uri: "https://login.microsoftonline.com/common/discovery/v2.0/keys".into(),
            auth_uri: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".into(),
            auth_scope: vec!["openid".into(), "profile".into(), "email".into()],
            fedcm_uri: Some("".into()),
            email_verification: None,
        }]),
        archive_config: Some(ArchiveConfig {
            module_hash: wasm_module_hash(&ARCHIVE_WASM),
            entries_buffer_limit: 10_000,
            polling_interval_ns: Duration::from_secs(1).as_nanos() as u64,
            entries_fetch_limit: 10,
        }),
        canister_creation_cycles_cost: Some(0),
        ..Default::default()
    };
    // Cycles are needed before installation because of the async HTTP outcalls
    let canister_id = install_ii_canister_with_arg_and_cycles(
        env,
        II_WASM.clone(),
        Some(args),
        10_000_000_000_000,
    );

    match api::deploy_archive(env, canister_id, &ARCHIVE_WASM) {
        Ok(DeployArchiveResult::Success(_archive_principal)) => {
            // Successfully deployed.
        }
        Ok(unexpected_result) => {
            panic!("archive deployment returned unexpected Ok result: {unexpected_result:?}");
        }
        Err(err) => {
            panic!("archive deployment failed: {err:?}");
        }
    }

    // Mock google certs response
    mock_google_certs_response(env);
    mock_microsoft_certs_response(env);

    canister_id
}

pub fn mock_google_certs_response(env: &PocketIc) {
    let url = "https://www.googleapis.com/oauth2/v3/certs";
    mock_certs_response(env, url, test_jwks());
}

pub fn mock_microsoft_certs_response(env: &PocketIc) {
    let url = "https://login.microsoftonline.com/common/discovery/v2.0/keys";
    mock_certs_response(env, url, test_jwks());
}

fn test_jwks() -> &'static str {
    r#"{"keys":[{"kty":"RSA","n":"0dbaWQrLCbYfGU1ezvZ6eV00s3knn0vxX6gYjwVDVfWcNYlyUh9-jOQdHYfO5DyNW2IjdrRby_zsgusACCrMrz1TvX7N17DEEHiPOJ1n8er8-WZr2kXOGx7V219xEfCU0BT-Xy2n5iAlA-JVlrvpbP3mJEVOgGV4DH7R959ZU3efqCNmGbDXkC2iAoSoltd-6UCWw9B5u1rkm9mH4rL9Jcdbx-_CQpj9s-UUY3PAbtd1E2VIB6MGavYTkX2vKh-F6TwFdAXVE7FrTRzrA8bNRVHW-9gm2D6aUCvxQrrnx-nGTfUFFK-lA6mfUBqZU9TLAJxY6j2Lo88zz0vBF9ZaFw","e":"AQAB","kid":"test-rsa-key","alg":"RS256","use":"sig"}]}"#
}

pub fn mock_certs_response(env: &PocketIc, url: &str, mock_certs: &str) {
    const MAX_ATTEMPTS: u32 = 10;
    let mut attempts = 0;

    loop {
        env.tick();
        attempts += 1;

        let requests = env.get_canister_http();

        if let Some(cert_request) = requests.iter().find(|req| req.url == url) {
            // Use the same test certificate data that's used in google.rs
            let mock_certs = serde_json::from_str::<Certs>(mock_certs).unwrap().keys;

            let http_response = CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&Certs { keys: mock_certs }).unwrap(),
            });

            let response = MockCanisterHttpResponse {
                subnet_id: cert_request.subnet_id,
                request_id: cert_request.request_id,
                response: http_response,
                additional_responses: vec![],
            };

            env.mock_canister_http_response(response);
            env.tick();
            return;
        }

        if attempts >= MAX_ATTEMPTS {
            panic!("No cert requests found for URL '{url}' after {MAX_ATTEMPTS} attempts");
        }
    }
}

/**
 * Explanation of the fields used for the test data:
 * - JWT: the JWT received by the openID provider.
 * - salt: the salt used to create the JWT from before.
 * - test_time: the `iat` (issued at) field from the JWT
 * - test_principal: the principal of the identity used the link the OpenID account.
 * - test_pubkey: the public key of the credential used to sign in with the identity from `test_principal`.
 *   Not the public key of the principal of the identity. You don't get it with connection.identity.getPublicKey().
 *
 * How to get the test data:
 * 1. Setup a local environment with open id providers.
 * 2. Create an identity with Passkey in the local environment.
 * 3. Log in with that identity and console.log the public key from `DiscoverablePasskeyIdentity.useExisting` `getPublicKey` argument.
 *    console.log("in da lookup", lookupResult.pubkey);
 *    This is the `test_pubkey`.
 * 4. Link an OpenID account to that identity.
 *    Add a few logs:
 *    - the identity's principal with `identity.getPrincipal().toUint8Array()`. This goes to `test_principal`.
 *    - the jwt after requesting it. This goes to `jwt`.
 *    - the salt from the authenticatedStore. This goes to `salt`.
 *    - the rest of the fields in the JWT claims, find the `iat`. This goes to `test_time`.
 *    - For example, you can find the JWT, salt and principal in `linkOpenIdAccount` from `addAccessMethodFlow`.
 *    - The claims you can log them in `decodeJWT`.
 *
 * Additional notes:
 * - The openID configuration when installing the canister in the test environment must match your local environment.
 * - If you add a new openID providers, you need to mock the credentials with `mock_certs_response`.
 * - We need to set the time in the pocket-ic environment becuase the JWT are already expired at the time of the test.
 * - These JWT can still be used to register an identity.
 */
pub fn openid_google_test_data() -> (String, [u8; 32], Claims, u64, Principal, AuthnMethodData) {
    let jwt = concat!("eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtcnNhLWtleSIsInR5cCI6IkpXVCJ9", ".", "eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiIzNjA1ODc5OTE2NjgtNjNicGMxZ25ncDFzNWdibzFhbGRhbDRhNTBjMWowYmIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiJ0ZXN0LWdvb2dsZS1zdWJqZWN0LTEiLCJub25jZSI6ImZCRzFLcjNRa3lnR0d6U0lYb093andEX3lCOFdLQV9xUk9SVmMwWnRYeUkiLCJpYXQiOjE3NDA1ODM3MTIsIm5iZiI6MTc0MDU4MzcxMiwiZXhwIjoxNzQwNTg3MzEyLCJlbWFpbCI6Im9wZW5pZC1nb29nbGUtMUBleGFtcGxlLnRlc3QiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6Ik9wZW5JRCBHb29nbGUgT25lIn0", ".", "wiRc3a0oowsvWo5sfSHL-IStohmB0GabTPjb9xgBw6GEdJToGYc2wF7Wr5Vw9tnMqNCPNs4wpwPvImRy5eFBoJY4WqIhVFDjRSXKm0VZmd__OjgpZgpGihtjbX49X30u2U5fVYWVIkAhOxvWSTYD5cH2T8JKtJ_p_K9Ze-DCxtC4rhnQRykR5pcQIuYdUhgqBVbNcBXIwm4_LVxL9V-w2D_xGDYWAjbaqEXx-IcfVr7X2thu5KmEAqfKmW5cYDYafDLjIRImOfof7VpF8V3B0ShJTgFci03YEqJUkBwqGp0rtIamcVnGW4c8o77U5BEkov9-dBYQO1nn_grIudfV2g");
    let salt: [u8; 32] = [
        107, 14, 204, 55, 92, 39, 93, 230, 53, 20, 153, 234, 70, 25, 120, 74, 136, 94, 251, 187,
        238, 96, 97, 180, 255, 135, 20, 149, 143, 27, 159, 83,
    ];
    let validation_item = Decoder::new()
        .decode_compact_serialization(jwt.as_bytes(), None)
        .unwrap();
    let claims: Claims = serde_json::from_slice(validation_item.claims()).unwrap();
    let test_time = 1740583715239;
    let test_principal = Principal::from_slice(&[
        211, 40, 186, 145, 43, 2, 6, 17, 232, 23, 22, 44, 51, 178, 233, 163, 131, 231, 82, 174, 66,
        201, 203, 1, 102, 109, 20, 75, 2,
    ]);
    let test_pubkey = [
        48, 94, 48, 12, 6, 10, 43, 6, 1, 4, 1, 131, 184, 67, 1, 1, 3, 78, 0, 165, 1, 2, 3, 38, 32,
        1, 33, 88, 32, 252, 182, 240, 218, 160, 61, 178, 176, 17, 228, 185, 84, 148, 45, 86, 216,
        171, 120, 72, 246, 212, 55, 212, 167, 142, 59, 227, 0, 242, 182, 129, 211, 34, 88, 32, 158,
        197, 96, 131, 51, 156, 176, 65, 128, 29, 75, 98, 163, 187, 104, 38, 255, 65, 92, 234, 229,
        245, 221, 74, 40, 202, 29, 83, 162, 84, 177, 204,
    ];

    let test_authn_method = AuthnMethodData {
        authn_method: AuthnMethod::PubKey(PublicKeyAuthn {
            pubkey: ByteBuf::from(test_pubkey),
        }),
        metadata: Default::default(),
        security_settings: AuthnMethodSecuritySettings {
            protection: AuthnMethodProtection::Unprotected,
            purpose: AuthnMethodPurpose::Authentication,
        },
        last_authentication: None,
    };

    (
        jwt.into(),
        salt,
        claims,
        test_time,
        test_principal,
        test_authn_method,
    )
}

fn second_openid_google_test_data() -> (String, [u8; 32], Claims, u64, Principal, AuthnMethodData) {
    let jwt = concat!("eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtcnNhLWtleSIsInR5cCI6IkpXVCJ9", ".", "eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiIzNjA1ODc5OTE2NjgtNjNicGMxZ25ncDFzNWdibzFhbGRhbDRhNTBjMWowYmIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiJ0ZXN0LWdvb2dsZS1zdWJqZWN0LTIiLCJub25jZSI6IkdzU19vME9rTkJMX08xOTFlU05HSUR4eGZjN1dOM2tkZ2FZSkxxYWFIdGsiLCJpYXQiOjE3NDEwMTY5MDIsIm5iZiI6MTc0MTAxNjkwMiwiZXhwIjoxNzQxMDIwNTAyLCJlbWFpbCI6Im9wZW5pZC1nb29nbGUtMkBleGFtcGxlLnRlc3QiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6Ik9wZW5JRCBHb29nbGUgVHdvIn0", ".", "sEK9skfqOGix8grTJty5VFPm1G98Et443fuo8bJYDQV0hrhe4o2xCguGxeKuKJW0IOx1u-aER-L_rr7aqMVmtbHeoUdjwIePOqqqa_N0FiK9adLUecYzcQXJ4gIRbanYmZxWHa9vRY1fJwo76i0BJugH_5i07lvklLCb43wP8Xy6ZUiEhx2ErIbuTWNk2CWzVCig53QC06JsGHps0n-QYK86CLSocOeaUE2uu8KWGg5bqUIt_4u9552q8cFFcUiSwFcutgqv9gve7QEiQUUJ1H-85dQgeP-qbTB8h2FAQy2H-s5i97ixKK4SHzFB41JnBmdqA6lQTUy6Ni3LwIDp8Q");
    let salt: [u8; 32] = [
        73, 220, 36, 27, 90, 88, 236, 203, 175, 35, 73, 47, 62, 19, 239, 54, 105, 37, 123, 90, 175,
        248, 124, 179, 244, 231, 182, 142, 180, 139, 171, 253,
    ];
    let validation_item = Decoder::new()
        .decode_compact_serialization(jwt.as_bytes(), None)
        .unwrap();
    let claims: Claims = serde_json::from_slice(validation_item.claims()).unwrap();
    let test_time = 1741016902000;
    let test_principal = Principal::from_slice(&[
        189, 168, 196, 34, 223, 103, 250, 254, 55, 167, 15, 174, 41, 207, 68, 219, 125, 21, 215,
        167, 119, 47, 20, 195, 139, 233, 255, 210, 2,
    ]);
    let test_pubkey = [
        48, 94, 48, 12, 6, 10, 43, 6, 1, 4, 1, 131, 184, 67, 1, 1, 3, 78, 0, 165, 1, 2, 3, 38, 32,
        1, 33, 88, 32, 186, 6, 79, 74, 150, 108, 73, 69, 11, 154, 213, 120, 228, 162, 244, 219, 50,
        15, 108, 166, 154, 59, 197, 43, 180, 128, 122, 81, 145, 5, 55, 89, 34, 88, 32, 110, 143,
        94, 76, 94, 197, 172, 41, 10, 127, 224, 31, 66, 150, 206, 21, 4, 148, 86, 141, 117, 36, 16,
        119, 242, 232, 155, 6, 154, 223, 6, 123,
    ];

    let test_authn_method = AuthnMethodData {
        authn_method: AuthnMethod::PubKey(PublicKeyAuthn {
            pubkey: ByteBuf::from(test_pubkey),
        }),
        metadata: Default::default(),
        security_settings: AuthnMethodSecuritySettings {
            protection: AuthnMethodProtection::Unprotected,
            purpose: AuthnMethodPurpose::Authentication,
        },
        last_authentication: None,
    };

    (
        jwt.into(),
        salt,
        claims,
        test_time,
        test_principal,
        test_authn_method,
    )
}

pub fn one_openid_microsoft_test_data(
) -> (String, [u8; 32], Claims, u64, Principal, AuthnMethodData) {
    let jwt = concat!("eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtcnNhLWtleSIsInR5cCI6IkpXVCJ9", ".", "eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNGE0MzVjNWUtNjQ1MS00YzFhLWE4MWYtYWI5NjY2YjZkZThmL3YyLjAiLCJhdWQiOiJkOTQ4YzA3My1lZWJkLTRhYjgtODYxZC0wNTVmN2FiNDllMTciLCJzdWIiOiJ0ZXN0LW1pY3Jvc29mdC1zdWJqZWN0LTEiLCJub25jZSI6ImN1UmM4VlNEN1ZkQU9ISmpsX1UxbkNWdlpvamQtMGJoUE81X0lGbTc0N2MiLCJpYXQiOjE3NTY4MDgzMjQsIm5iZiI6MTc1NjgwODMyNCwiZXhwIjoxNzU2ODEyMjI0LCJlbWFpbCI6Im9wZW5pZC1taWNyb3NvZnQtMUBleGFtcGxlLnRlc3QiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6Ik9wZW5JRCBNaWNyb3NvZnQgT25lIiwidGlkIjoiNGE0MzVjNWUtNjQ1MS00YzFhLWE4MWYtYWI5NjY2YjZkZThmIn0", ".", "TvtlVUChWj9g2_2cFl1qEBtkFlwoX9F4Myosew0Xpk2zoxnrdsqllHK6K0-nivDTHuCerfEdiGNQgVariiQuQ32BtL8MyB-OTYKd8qT0c5sMh-hDe-OmS6a6cLPIRot1cbVwLGLWKyRzFGjgXm0vrQXzwi66aJD4QdSZEB3DImifPx3cLKBBT3Na31O-VOLEd5N5-2CYRrtY6TlW_M-U57DbbZiu42_0RqzKQ9Ilaq-wF-Outh8qF0uY6cHFSeXf3W71l7DwyjK5b625delRbzAEPx445bj0roc5Q3xxQ_NIqtMApxedD0FlCy1BiJwSbIXmbALXULz3BbYFcYTqGA");
    let salt: [u8; 32] = [
        196, 116, 153, 227, 8, 104, 231, 67, 202, 28, 156, 132, 101, 84, 170, 111, 86, 233, 29, 54,
        230, 234, 243, 167, 159, 27, 102, 53, 166, 149, 172, 207,
    ];
    let validation_item = Decoder::new()
        .decode_compact_serialization(jwt.as_bytes(), None)
        .unwrap();
    let claims: Claims = serde_json::from_slice(validation_item.claims()).unwrap();
    let test_time = 1756808324000;
    let test_principal = Principal::from_slice(&[
        33, 56, 228, 195, 129, 228, 78, 174, 18, 66, 159, 91, 0, 114, 146, 13, 69, 50, 30, 206, 73,
        70, 162, 63, 23, 149, 200, 139, 2,
    ]);
    let test_pubkey = [
        48, 94, 48, 12, 6, 10, 43, 6, 1, 4, 1, 131, 184, 67, 1, 1, 3, 78, 0, 165, 1, 2, 3, 38, 32,
        1, 33, 88, 32, 114, 42, 126, 192, 250, 94, 195, 79, 142, 211, 6, 212, 9, 135, 147, 58, 253,
        65, 125, 244, 95, 13, 249, 210, 209, 90, 66, 232, 237, 16, 43, 67, 34, 88, 32, 202, 212,
        22, 86, 222, 64, 75, 9, 157, 166, 125, 253, 46, 167, 174, 115, 181, 178, 11, 188, 189, 144,
        205, 63, 23, 227, 218, 35, 14, 101, 7, 235,
    ];

    let test_authn_method = AuthnMethodData {
        authn_method: AuthnMethod::PubKey(PublicKeyAuthn {
            pubkey: ByteBuf::from(test_pubkey),
        }),
        metadata: Default::default(),
        security_settings: AuthnMethodSecuritySettings {
            protection: AuthnMethodProtection::Unprotected,
            purpose: AuthnMethodPurpose::Authentication,
        },
        last_authentication: None,
    };

    (
        jwt.into(),
        salt,
        claims,
        test_time,
        test_principal,
        test_authn_method,
    )
}

/**
 * This is the same Microsoft account as the one in `one_openid_microsoft_test_data`, but with a different principal.
 * This information is part of the hardcoded JWT.
 */
fn openid_microsoft_same_as_one_but_different_principal_test_data(
) -> (String, [u8; 32], Claims, u64, Principal, AuthnMethodData) {
    let jwt = concat!("eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtcnNhLWtleSIsInR5cCI6IkpXVCJ9", ".", "eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNGE0MzVjNWUtNjQ1MS00YzFhLWE4MWYtYWI5NjY2YjZkZThmL3YyLjAiLCJhdWQiOiJkOTQ4YzA3My1lZWJkLTRhYjgtODYxZC0wNTVmN2FiNDllMTciLCJzdWIiOiJ0ZXN0LW1pY3Jvc29mdC1zdWJqZWN0LTEiLCJub25jZSI6IjRRc3QzVTNBeEl5OUx1ajQtck9UczhqbnlxbWVIYUxuVjc5UHdiZkQ2c0UiLCJpYXQiOjE3NTY4MDk4OTcsIm5iZiI6MTc1NjgwOTg5NywiZXhwIjoxNzU2ODEzNzk3LCJlbWFpbCI6Im9wZW5pZC1taWNyb3NvZnQtMUBleGFtcGxlLnRlc3QiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6Ik9wZW5JRCBNaWNyb3NvZnQgT25lIiwidGlkIjoiNGE0MzVjNWUtNjQ1MS00YzFhLWE4MWYtYWI5NjY2YjZkZThmIn0", ".", "V5HkfPzdBO0Qaij5_F7DPAT5N58FHCxX-wFEhDUmFzvxoOYhww1_tOdSy4cAgR7Kb7FC7MtMzWJS1429Sc_ahwvxLwPIYzDIsAahwZT7PcM8Xpx_22dfjPrtwjcZPhAWilck_WBv2ytMVT-LfGAWT1ppU9SQFMAD6eFLwt4g8_nM7wRlhHpLD15aYyw7xINFq2O_6vaZoqYmwzRWx3Gvx49NSPsOF-J9CuUTivMD0BUH29JpEM76Rx6HHKCPuOcKP1hovVp00jhDlHB7jUbnoGSezMT84v62oABF6r0IRrOr_jxoXlY55F500Txt4JMeAgv1g3imRMDS4X6sp6rw6w");
    let salt: [u8; 32] = [
        248, 17, 147, 158, 173, 176, 67, 222, 21, 206, 90, 244, 23, 215, 200, 214, 219, 39, 213,
        124, 225, 127, 112, 189, 122, 46, 84, 28, 4, 177, 98, 233,
    ];
    let validation_item = Decoder::new()
        .decode_compact_serialization(jwt.as_bytes(), None)
        .unwrap();
    let claims: Claims = serde_json::from_slice(validation_item.claims()).unwrap();
    let test_time = 1756809897000;
    let test_principal = Principal::from_slice(&[
        207, 89, 197, 37, 100, 13, 121, 8, 153, 196, 203, 90, 42, 72, 233, 220, 119, 173, 118, 203,
        235, 245, 229, 42, 249, 96, 210, 28, 2,
    ]);
    let test_pubkey = [
        48, 94, 48, 12, 6, 10, 43, 6, 1, 4, 1, 131, 184, 67, 1, 1, 3, 78, 0, 165, 1, 2, 3, 38, 32,
        1, 33, 88, 32, 8, 146, 104, 45, 59, 242, 233, 149, 153, 10, 83, 252, 72, 236, 114, 32, 116,
        99, 16, 86, 47, 224, 150, 170, 9, 191, 42, 181, 81, 125, 157, 194, 34, 88, 32, 64, 124, 12,
        58, 148, 180, 243, 137, 40, 0, 10, 151, 172, 157, 34, 32, 129, 114, 68, 156, 126, 187, 174,
        224, 55, 171, 240, 28, 242, 24, 183, 78,
    ];

    let test_authn_method = AuthnMethodData {
        authn_method: AuthnMethod::PubKey(PublicKeyAuthn {
            pubkey: ByteBuf::from(test_pubkey),
        }),
        metadata: Default::default(),
        security_settings: AuthnMethodSecuritySettings {
            protection: AuthnMethodProtection::Unprotected,
            purpose: AuthnMethodPurpose::Authentication,
        },
        last_authentication: None,
    };

    (
        jwt.into(),
        salt,
        claims,
        test_time,
        test_principal,
        test_authn_method,
    )
}

fn second_openid_microsoft_test_data() -> (String, [u8; 32], Claims, u64, Principal, AuthnMethodData)
{
    let jwt = concat!("eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtcnNhLWtleSIsInR5cCI6IkpXVCJ9", ".", "eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vOTE4ODA0MGQtNmM2Ny00YzViLWIxMTItMzZhMzA0YjY2ZGFkL3YyLjAiLCJhdWQiOiJkOTQ4YzA3My1lZWJkLTRhYjgtODYxZC0wNTVmN2FiNDllMTciLCJzdWIiOiJ0ZXN0LW1pY3Jvc29mdC1zdWJqZWN0LTIiLCJub25jZSI6Iko1LU10N1pTYU1hcEJTc0ZHSVcyVmNuaUUwMWt2bWI5dXFJSU83VDVpVm8iLCJpYXQiOjE3NTY4MDg2MTYsIm5iZiI6MTc1NjgwODYxNiwiZXhwIjoxNzU2ODk1MzE2LCJlbWFpbCI6Im9wZW5pZC1taWNyb3NvZnQtMkBleGFtcGxlLnRlc3QiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6Ik9wZW5JRCBNaWNyb3NvZnQgVHdvIiwidGlkIjoiOTE4ODA0MGQtNmM2Ny00YzViLWIxMTItMzZhMzA0YjY2ZGFkIn0", ".", "gUhYMqcKXLNgyBOAvnzk98X8VrP043-pYAJQVVw5dKCYg-FkITVkJjaV2tilKeywXOy3f8ys1juxCFFsDJ663iIXNXk9QFpBtYIoCMB_01dEmsQfm2Yz-Jak_HPTZ3s4hmiTaqzOnngXjszeJudfnQrqBsUhvZcLfDighH1oNYGjh5hNnVhRDfMH--_BE9-EgXFqBb4aelYqH9esrZtzOD7s2baQfgVigNoTb0Am5mo2C5A-eABguE-dHv2eRZt2n5iDirmNS5pk2DZOiYr2ZMv4T3FwizQBCuoeqE2limX5y0PR-CPnqBOMzutGGAROsXdnbW5qhaHbhlw5KR4M4Q");
    let salt: [u8; 32] = [
        130, 72, 159, 133, 3, 151, 246, 106, 96, 151, 157, 243, 233, 14, 234, 0, 220, 62, 210, 94,
        76, 220, 218, 255, 97, 101, 136, 232, 156, 181, 30, 210,
    ];
    let validation_item = Decoder::new()
        .decode_compact_serialization(jwt.as_bytes(), None)
        .unwrap();
    let claims: Claims = serde_json::from_slice(validation_item.claims()).unwrap();
    let test_time = 1756808616000;
    // Same as `openid_microsoft_test_data`.
    let test_principal = Principal::from_slice(&[
        33, 56, 228, 195, 129, 228, 78, 174, 18, 66, 159, 91, 0, 114, 146, 13, 69, 50, 30, 206, 73,
        70, 162, 63, 23, 149, 200, 139, 2,
    ]);
    // Same as `openid_microsoft_test_data`.
    let test_pubkey = [
        48, 94, 48, 12, 6, 10, 43, 6, 1, 4, 1, 131, 184, 67, 1, 1, 3, 78, 0, 165, 1, 2, 3, 38, 32,
        1, 33, 88, 32, 114, 42, 126, 192, 250, 94, 195, 79, 142, 211, 6, 212, 9, 135, 147, 58, 253,
        65, 125, 244, 95, 13, 249, 210, 209, 90, 66, 232, 237, 16, 43, 67, 34, 88, 32, 202, 212,
        22, 86, 222, 64, 75, 9, 157, 166, 125, 253, 46, 167, 174, 115, 181, 178, 11, 188, 189, 144,
        205, 63, 23, 227, 218, 35, 14, 101, 7, 235,
    ];

    let test_authn_method = AuthnMethodData {
        authn_method: AuthnMethod::PubKey(PublicKeyAuthn {
            pubkey: ByteBuf::from(test_pubkey),
        }),
        metadata: Default::default(),
        security_settings: AuthnMethodSecuritySettings {
            protection: AuthnMethodProtection::Unprotected,
            purpose: AuthnMethodPurpose::Authentication,
        },
        last_authentication: None,
    };

    (
        jwt.into(),
        salt,
        claims,
        test_time,
        test_principal,
        test_authn_method,
    )
}

fn number_of_openid_credentials(
    env: &PocketIc,
    canister_id: Principal,
    sender: Principal,
    identity_number: u64,
) -> Result<usize, RejectResponse> {
    let openid_credentials = api::get_anchor_info(env, canister_id, sender, identity_number)?
        .openid_credentials
        .expect("Could not fetch credentials!");

    Ok(openid_credentials.len())
}
