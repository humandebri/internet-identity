//! Native authorization request and token state.
//! Stores short-lived authorization requests, redeemed codes, and exchange tokens.

use internet_identity_interface::internet_identity::types::{
    AccountNumber, CompleteNativeAuthorizationError, ExchangeNativeAccessTokenForDelegationError,
    RedeemNativeAuthorizationCodeError, SessionKey, Timestamp, UserKey,
};
use std::collections::HashMap;

const MAX_NATIVE_AUTHORIZATION_REQUESTS: usize = 1_000;
const MAX_AUTHORIZATION_CODES: usize = 1_000;
const MAX_NATIVE_ACCESS_TOKENS: usize = 2_000;
const COMPLETION_CLAIM_TTL_NS: u64 = 5 * 60 * 1_000_000_000;

#[derive(Clone, Debug)]
pub struct NativeAuthorizationRecord {
    pub origin: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub state: String,
    pub scope: Vec<String>,
    pub nonce: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub session_public_key: SessionKey,
    pub max_time_to_live: Option<u64>,
    pub issuer: String,
    pub expires_at: Timestamp,
    pub status: NativeAuthorizationStatus,
}

#[derive(Clone, Debug)]
pub enum NativeAuthorizationStatus {
    Pending,
    InProgress(InProgressNativeAuthorization),
    Authorized(AuthorizedNativeAuthorization),
}

#[derive(Clone, Debug)]
pub struct InProgressNativeAuthorization {
    pub previous_expiration: Timestamp,
}

#[derive(Clone, Debug)]
pub struct AuthorizedNativeAuthorization {
    pub anchor_number: u64,
    pub account_number: Option<AccountNumber>,
    pub user_key: UserKey,
    pub expiration: Timestamp,
}

#[derive(Clone, Debug)]
pub struct AuthorizationCodeRecord {
    pub request_id: String,
    pub expires_at: Timestamp,
    pub redeemed_at: Option<Timestamp>,
}

#[derive(Clone, Debug)]
pub struct NativeAccessTokenRecord {
    pub anchor_number: u64,
    pub account_number: Option<AccountNumber>,
    pub origin: String,
    pub session_public_key: SessionKey,
    pub user_key: UserKey,
    pub expiration: Timestamp,
    pub expires_at: Timestamp,
}

#[derive(Default)]
pub struct NativeAuthorizationState {
    records: HashMap<String, NativeAuthorizationRecord>,
    authorization_codes: HashMap<String, AuthorizationCodeRecord>,
    access_tokens: HashMap<String, NativeAccessTokenRecord>,
}

impl NativeAuthorizationState {
    pub fn insert(
        &mut self,
        request_id: String,
        record: NativeAuthorizationRecord,
    ) -> Result<(), ()> {
        if self.records.len() >= MAX_NATIVE_AUTHORIZATION_REQUESTS {
            return Err(());
        }
        self.records.insert(request_id, record);
        Ok(())
    }

    pub fn get(&self, request_id: &str) -> Option<&NativeAuthorizationRecord> {
        self.records.get(request_id)
    }

    pub fn claim_for_completion(
        &mut self,
        request_id: &str,
        now: Timestamp,
    ) -> Result<NativeAuthorizationRecord, CompleteNativeAuthorizationError> {
        let Some(record) = self.records.get_mut(request_id) else {
            self.prune_expired(now);
            return Err(CompleteNativeAuthorizationError::NotFound);
        };
        if record.expires_at <= now {
            return Err(CompleteNativeAuthorizationError::Expired);
        }
        match record.status {
            NativeAuthorizationStatus::Pending => {
                let previous_expiration = record.expires_at;
                record.expires_at = now.saturating_add(COMPLETION_CLAIM_TTL_NS);
                record.status =
                    NativeAuthorizationStatus::InProgress(InProgressNativeAuthorization {
                        previous_expiration,
                    });
                Ok(record.clone())
            }
            NativeAuthorizationStatus::InProgress(_) | NativeAuthorizationStatus::Authorized(_) => {
                Err(CompleteNativeAuthorizationError::AlreadyCompleted)
            }
        }
    }

    pub fn complete_claimed_with_authorization_code(
        &mut self,
        request_id: &str,
        authorized: AuthorizedNativeAuthorization,
        request_expires_at: Timestamp,
        code: String,
        code_record: AuthorizationCodeRecord,
        now: Timestamp,
    ) -> Result<(), CompleteNativeAuthorizationError> {
        self.prune_expired(now);
        if self.authorization_codes.len() >= MAX_AUTHORIZATION_CODES {
            return Err(CompleteNativeAuthorizationError::InternalCanisterError(
                "too many authorization codes".to_string(),
            ));
        }
        let Some(record) = self.records.get_mut(request_id) else {
            return Err(CompleteNativeAuthorizationError::NotFound);
        };
        match record.status {
            NativeAuthorizationStatus::InProgress(_) => {
                record.expires_at = request_expires_at;
                record.status = NativeAuthorizationStatus::Authorized(authorized);
                self.authorization_codes.insert(code, code_record);
                Ok(())
            }
            NativeAuthorizationStatus::Pending => Err(CompleteNativeAuthorizationError::NotFound),
            NativeAuthorizationStatus::Authorized(_) => {
                Err(CompleteNativeAuthorizationError::AlreadyCompleted)
            }
        }
    }

    pub fn release_claim(&mut self, request_id: &str) {
        let Some(record) = self.records.get_mut(request_id) else {
            return;
        };
        let NativeAuthorizationStatus::InProgress(in_progress) = &record.status else {
            return;
        };
        record.expires_at = in_progress.previous_expiration;
        record.status = NativeAuthorizationStatus::Pending;
    }

    pub fn authorized_code(
        &mut self,
        code: &str,
        now: Timestamp,
    ) -> Result<
        (AuthorizationCodeRecord, NativeAuthorizationRecord),
        RedeemNativeAuthorizationCodeError,
    > {
        self.prune_expired(now);
        let Some(code_record) = self.authorization_codes.get(code).cloned() else {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code not found".to_string(),
            ));
        };
        if code_record.expires_at <= now {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code expired".to_string(),
            ));
        }
        if code_record.redeemed_at.is_some() {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code already redeemed".to_string(),
            ));
        }
        let Some(record) = self.records.get(&code_record.request_id) else {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code not found".to_string(),
            ));
        };
        let NativeAuthorizationStatus::Authorized(_) = &record.status else {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code is not ready".to_string(),
            ));
        };
        Ok((code_record, record.clone()))
    }

    pub fn issue_access_token_and_consume_authorization(
        &mut self,
        code: &str,
        request_id: &str,
        access_token: String,
        token_record: NativeAccessTokenRecord,
        now: Timestamp,
    ) -> Result<(), RedeemNativeAuthorizationCodeError> {
        self.prune_expired(now);
        if self.access_tokens.len() >= MAX_NATIVE_ACCESS_TOKENS {
            return Err(RedeemNativeAuthorizationCodeError::InternalCanisterError(
                "too many native access tokens".to_string(),
            ));
        }
        let Some(code_record) = self.authorization_codes.get(code) else {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code not found".to_string(),
            ));
        };
        if code_record.request_id != request_id {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code does not match the prepared request".to_string(),
            ));
        }
        if code_record.redeemed_at.is_some() {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code already redeemed".to_string(),
            ));
        }
        let Some(record) = self.records.get_mut(request_id) else {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code not found".to_string(),
            ));
        };
        let NativeAuthorizationStatus::Authorized(_) = &mut record.status else {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code is not ready".to_string(),
            ));
        };
        let Some(code_record) = self.authorization_codes.get_mut(code) else {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code not found".to_string(),
            ));
        };
        code_record.redeemed_at = Some(now);
        self.access_tokens.insert(access_token, token_record);
        self.authorization_codes.remove(code);
        self.records.remove(request_id);
        Ok(())
    }

    pub fn invalidate_authorization_code(&mut self, code: &str, now: Timestamp) {
        let Some(code_record) = self.authorization_codes.get_mut(code) else {
            return;
        };
        if code_record.redeemed_at.is_none() {
            code_record.redeemed_at = Some(now);
        }
    }

    pub fn prune_expired(&mut self, now: Timestamp) {
        self.records.retain(|_, record| record.expires_at > now);
        self.authorization_codes
            .retain(|_, record| record.expires_at > now);
        self.access_tokens
            .retain(|_, record| record.expires_at > now);
    }

    pub fn access_token(
        &mut self,
        access_token: &str,
        now: Timestamp,
    ) -> Result<NativeAccessTokenRecord, ExchangeNativeAccessTokenForDelegationError> {
        let Some(record) = self.access_tokens.get(access_token).cloned() else {
            return Err(ExchangeNativeAccessTokenForDelegationError::NotFound);
        };
        if record.expires_at <= now {
            self.access_tokens.remove(access_token);
            return Err(ExchangeNativeAccessTokenForDelegationError::Expired);
        }
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_bytes::ByteBuf;

    fn record() -> NativeAuthorizationRecord {
        NativeAuthorizationRecord {
            origin: "https://app.example.com".to_string(),
            redirect_uri: "https://app.example.com/callback".to_string(),
            client_id: "https://app.example.com".to_string(),
            state: "state".to_string(),
            scope: vec!["openid".to_string()],
            nonce: "nonce".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: "S256".to_string(),
            session_public_key: ByteBuf::from(b"session".to_vec()),
            max_time_to_live: None,
            issuer: "https://identity.test".to_string(),
            expires_at: 100,
            status: NativeAuthorizationStatus::Pending,
        }
    }

    fn authorized() -> AuthorizedNativeAuthorization {
        AuthorizedNativeAuthorization {
            anchor_number: 42,
            account_number: None,
            user_key: ByteBuf::from(b"user".to_vec()),
            expiration: 777,
        }
    }

    #[test]
    fn should_issue_access_token_and_release_authorization_capacity() {
        let mut state = NativeAuthorizationState::default();
        state.insert("request".to_string(), record()).unwrap();
        state.claim_for_completion("request", 10).unwrap();
        state
            .complete_claimed_with_authorization_code(
                "request",
                authorized(),
                200,
                "code".to_string(),
                AuthorizationCodeRecord {
                    request_id: "request".to_string(),
                    expires_at: 120,
                    redeemed_at: None,
                },
                20,
            )
            .expect("complete should succeed");

        let token_record = NativeAccessTokenRecord {
            anchor_number: 42,
            account_number: None,
            origin: "https://app.example.com".to_string(),
            session_public_key: ByteBuf::from(b"session".to_vec()),
            user_key: ByteBuf::from(b"user".to_vec()),
            expiration: 777,
            expires_at: 150,
        };

        state.authorized_code("code", 20).unwrap();
        state
            .issue_access_token_and_consume_authorization(
                "code",
                "request",
                "token".to_string(),
                token_record,
                20,
            )
            .unwrap();
        assert!(matches!(
            state.authorized_code("code", 21),
            Err(RedeemNativeAuthorizationCodeError::InvalidGrant(_))
        ));
        assert!(state.get("request").is_none());

        state.insert("request".to_string(), record()).unwrap();
        state.claim_for_completion("request", 10).unwrap();
        state
            .complete_claimed_with_authorization_code(
                "request",
                authorized(),
                200,
                "code-0".to_string(),
                AuthorizationCodeRecord {
                    request_id: "request".to_string(),
                    expires_at: 120,
                    redeemed_at: None,
                },
                20,
            )
            .expect("complete should succeed");
        for index in 1..MAX_AUTHORIZATION_CODES {
            state.authorization_codes.insert(
                format!("code-{index}"),
                AuthorizationCodeRecord {
                    request_id: "request".to_string(),
                    expires_at: 120,
                    redeemed_at: None,
                },
            );
        }
        state
            .issue_access_token_and_consume_authorization(
                "code-0",
                "request",
                "token-0".to_string(),
                NativeAccessTokenRecord {
                    anchor_number: 42,
                    account_number: None,
                    origin: "https://app.example.com".to_string(),
                    session_public_key: ByteBuf::from(b"session".to_vec()),
                    user_key: ByteBuf::from(b"user".to_vec()),
                    expiration: 777,
                    expires_at: 150,
                },
                20,
            )
            .expect("token issuance should free one code slot");
        state.insert("request-next".to_string(), record()).unwrap();
        state.claim_for_completion("request-next", 10).unwrap();
        state
            .complete_claimed_with_authorization_code(
                "request-next",
                authorized(),
                200,
                "code-next".to_string(),
                AuthorizationCodeRecord {
                    request_id: "request-next".to_string(),
                    expires_at: 120,
                    redeemed_at: None,
                },
                20,
            )
            .expect("redeemed code should not occupy code capacity");

        let mut state = NativeAuthorizationState::default();
        state.insert("request".to_string(), record()).unwrap();
        state.claim_for_completion("request", 10).unwrap();
        state
            .complete_claimed_with_authorization_code(
                "request",
                authorized(),
                200,
                "code".to_string(),
                AuthorizationCodeRecord {
                    request_id: "request".to_string(),
                    expires_at: 120,
                    redeemed_at: None,
                },
                20,
            )
            .expect("complete should succeed");
        let token_record = NativeAccessTokenRecord {
            anchor_number: 42,
            account_number: None,
            origin: "https://app.example.com".to_string(),
            session_public_key: ByteBuf::from(b"session".to_vec()),
            user_key: ByteBuf::from(b"user".to_vec()),
            expiration: 777,
            expires_at: 150,
        };
        state
            .issue_access_token_and_consume_authorization(
                "code",
                "request",
                "token".to_string(),
                token_record,
                20,
            )
            .unwrap();
        for index in 0..MAX_NATIVE_AUTHORIZATION_REQUESTS {
            state
                .insert(format!("request-{index}"), record())
                .expect("redeemed request should not occupy request capacity");
        }
    }

    #[test]
    fn should_invalidate_authorization_code() {
        let mut state = NativeAuthorizationState::default();
        state.insert("request".to_string(), record()).unwrap();
        state.claim_for_completion("request", 10).unwrap();
        state
            .complete_claimed_with_authorization_code(
                "request",
                authorized(),
                200,
                "code".to_string(),
                AuthorizationCodeRecord {
                    request_id: "request".to_string(),
                    expires_at: 120,
                    redeemed_at: None,
                },
                20,
            )
            .expect("complete should succeed");

        state.invalidate_authorization_code("code", 20);

        assert!(matches!(
            state.authorized_code("code", 21),
            Err(RedeemNativeAuthorizationCodeError::InvalidGrant(_))
        ));
    }

    #[test]
    fn should_not_complete_claim_when_code_capacity_is_exhausted() {
        let mut state = NativeAuthorizationState::default();
        state.insert("request".to_string(), record()).unwrap();
        state.claim_for_completion("request", 10).unwrap();
        for index in 0..MAX_AUTHORIZATION_CODES {
            state.authorization_codes.insert(
                format!("code-{index}"),
                AuthorizationCodeRecord {
                    request_id: format!("other-{index}"),
                    expires_at: 120,
                    redeemed_at: None,
                },
            );
        }

        assert!(matches!(
            state.complete_claimed_with_authorization_code(
                "request",
                authorized(),
                200,
                "code".to_string(),
                AuthorizationCodeRecord {
                    request_id: "request".to_string(),
                    expires_at: 120,
                    redeemed_at: None,
                },
                20,
            ),
            Err(CompleteNativeAuthorizationError::InternalCanisterError(_))
        ));
        assert!(matches!(
            state.get("request").map(|record| &record.status),
            Some(NativeAuthorizationStatus::InProgress(_))
        ));
    }
}
