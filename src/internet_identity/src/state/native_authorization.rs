//! Native authorization request and token state.
//! Stores short-lived authorization requests, redeemed codes, and exchange tokens.

use internet_identity_interface::internet_identity::types::{
    AccountNumber, CompleteNativeAuthorizationError, ExchangeNativeAccessTokenForDelegationError,
    RedeemNativeAuthorizationCodeError, SessionKey, Timestamp, UserKey,
};
use std::collections::HashMap;

const MAX_NATIVE_AUTHORIZATION_REQUESTS: usize = 1_000;
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
    pub code_expires_at: Timestamp,
    pub redeemed_at: Option<Timestamp>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct NativeAccessTokenRecord {
    pub request_id: String,
    pub anchor_number: u64,
    pub account_number: Option<AccountNumber>,
    pub origin: String,
    pub session_public_key: SessionKey,
    pub user_key: UserKey,
    pub expiration: Timestamp,
    pub issuer: String,
    pub client_id: String,
    pub nonce: String,
    pub scope: Vec<String>,
    pub expires_at: Timestamp,
}

#[derive(Default)]
pub struct NativeAuthorizationState {
    records: HashMap<String, NativeAuthorizationRecord>,
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

    pub fn complete_claimed(
        &mut self,
        request_id: &str,
        authorized: AuthorizedNativeAuthorization,
        expires_at: Timestamp,
    ) -> Result<(), CompleteNativeAuthorizationError> {
        let Some(record) = self.records.get_mut(request_id) else {
            return Err(CompleteNativeAuthorizationError::NotFound);
        };
        match record.status {
            NativeAuthorizationStatus::InProgress(_) => {
                record.expires_at = expires_at;
                record.status = NativeAuthorizationStatus::Authorized(authorized);
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
        request_id: &str,
        now: Timestamp,
    ) -> Result<NativeAuthorizationRecord, RedeemNativeAuthorizationCodeError> {
        self.prune_expired(now);
        let Some(record) = self.records.get(request_id) else {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code not found".to_string(),
            ));
        };
        if record.expires_at <= now {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code expired".to_string(),
            ));
        }
        let NativeAuthorizationStatus::Authorized(authorized) = &record.status else {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code is not ready".to_string(),
            ));
        };
        if authorized.code_expires_at <= now {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code expired".to_string(),
            ));
        }
        if authorized.redeemed_at.is_some() {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code already redeemed".to_string(),
            ));
        }
        Ok(record.clone())
    }

    pub fn issue_access_token(
        &mut self,
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
        let Some(record) = self.records.get_mut(request_id) else {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code not found".to_string(),
            ));
        };
        let NativeAuthorizationStatus::Authorized(authorized) = &mut record.status else {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code is not ready".to_string(),
            ));
        };
        if authorized.redeemed_at.is_some() {
            return Err(RedeemNativeAuthorizationCodeError::InvalidGrant(
                "authorization code already redeemed".to_string(),
            ));
        }
        authorized.redeemed_at = Some(now);
        self.access_tokens.insert(access_token, token_record);
        Ok(())
    }

    pub fn prune_expired(&mut self, now: Timestamp) {
        self.records.retain(|_, record| record.expires_at > now);
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
            code_expires_at: 120,
            redeemed_at: None,
        }
    }

    #[test]
    fn should_issue_access_token_once() {
        let mut state = NativeAuthorizationState::default();
        state.insert("request".to_string(), record()).unwrap();
        state.claim_for_completion("request", 10).unwrap();
        state
            .complete_claimed("request", authorized(), 200)
            .expect("complete should succeed");

        let token_record = NativeAccessTokenRecord {
            request_id: "request".to_string(),
            anchor_number: 42,
            account_number: None,
            origin: "https://app.example.com".to_string(),
            session_public_key: ByteBuf::from(b"session".to_vec()),
            user_key: ByteBuf::from(b"user".to_vec()),
            expiration: 777,
            issuer: "https://identity.test".to_string(),
            client_id: "https://app.example.com".to_string(),
            nonce: "nonce".to_string(),
            scope: vec!["openid".to_string()],
            expires_at: 150,
        };

        state.authorized_code("request", 20).unwrap();
        state
            .issue_access_token("request", "token".to_string(), token_record, 20)
            .unwrap();
        assert!(matches!(
            state.authorized_code("request", 21),
            Err(RedeemNativeAuthorizationCodeError::InvalidGrant(_))
        ));
    }
}
