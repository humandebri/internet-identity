//! In-memory native authorization request state.
//! This state is intentionally short-lived and is not persisted across upgrades.
//! Completed requests keep only the data needed to reconstruct the signed delegation on fetch.

use internet_identity_interface::internet_identity::types::{
    AccountNumber, CompleteNativeAuthorizationError, SessionKey, Timestamp, UserKey,
};
use std::collections::HashMap;

const MAX_NATIVE_AUTHORIZATION_REQUESTS: usize = 1_000;
const COMPLETION_CLAIM_TTL_NS: u64 = 5 * 60 * 1_000_000_000;

#[derive(Clone, Debug)]
pub struct NativeAuthorizationRecord {
    pub origin: String,
    pub session_public_key: SessionKey,
    pub return_link: String,
    pub max_time_to_live: Option<u64>,
    pub expires_at: Timestamp,
    pub status: NativeAuthorizationStatus,
}

#[derive(Clone, Debug)]
pub enum NativeAuthorizationStatus {
    Pending,
    InProgress(InProgressNativeAuthorization),
    Completed(CompletedNativeAuthorization),
}

#[derive(Clone, Debug)]
pub struct InProgressNativeAuthorization {
    // Failed completion restores the original pending request TTL.
    pub previous_expiration: Timestamp,
}

#[derive(Clone, Debug)]
pub struct CompletedNativeAuthorization {
    pub anchor_number: u64,
    pub account_number: Option<AccountNumber>,
    pub user_key: UserKey,
    pub expiration: Timestamp,
}

#[derive(Default)]
pub struct NativeAuthorizationState {
    records: HashMap<String, NativeAuthorizationRecord>,
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
        // Single linearization point for completion.
        // The claim TTL is internal only and must not change the external request TTL contract.
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
            NativeAuthorizationStatus::InProgress(_) | NativeAuthorizationStatus::Completed(_) => {
                Err(CompleteNativeAuthorizationError::AlreadyCompleted)
            }
        }
    }

    pub fn complete_claimed(
        &mut self,
        request_id: &str,
        completed: CompletedNativeAuthorization,
        now: Timestamp,
    ) -> Result<(), CompleteNativeAuthorizationError> {
        // Finalizes only an already-claimed request.
        let Some(record) = self.records.get_mut(request_id) else {
            return Err(CompleteNativeAuthorizationError::NotFound);
        };
        match record.status {
            NativeAuthorizationStatus::InProgress(_) => {
                record.expires_at = now;
                record.status = NativeAuthorizationStatus::Completed(completed);
                Ok(())
            }
            NativeAuthorizationStatus::Pending => Err(CompleteNativeAuthorizationError::NotFound),
            NativeAuthorizationStatus::Completed(_) => {
                Err(CompleteNativeAuthorizationError::AlreadyCompleted)
            }
        }
    }

    pub fn release_claim(&mut self, request_id: &str) {
        // Failed completion only undoes the internal claim and restores the original TTL.
        let Some(record) = self.records.get_mut(request_id) else {
            return;
        };
        let NativeAuthorizationStatus::InProgress(in_progress) = &record.status else {
            return;
        };
        record.expires_at = in_progress.previous_expiration;
        record.status = NativeAuthorizationStatus::Pending;
    }

    pub fn prune_expired(&mut self, now: Timestamp) {
        self.records.retain(|_, record| record.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_bytes::ByteBuf;

    fn record() -> NativeAuthorizationRecord {
        NativeAuthorizationRecord {
            origin: "https://app.example.com".to_string(),
            session_public_key: ByteBuf::from(b"session".to_vec()),
            return_link: "https://app.example.com/callback".to_string(),
            max_time_to_live: None,
            expires_at: 100,
            status: NativeAuthorizationStatus::Pending,
        }
    }

    fn completed() -> CompletedNativeAuthorization {
        CompletedNativeAuthorization {
            anchor_number: 42,
            account_number: None,
            user_key: ByteBuf::from(b"user".to_vec()),
            expiration: 777,
        }
    }

    #[test]
    fn should_claim_pending_request_for_completion() {
        let mut state = NativeAuthorizationState::default();
        state
            .insert("request".to_string(), record())
            .expect("insert should succeed");

        let claimed = state
            .claim_for_completion("request", 10)
            .expect("claim should succeed");

        assert!(matches!(
            claimed.status,
            NativeAuthorizationStatus::InProgress(_)
        ));
        assert!(matches!(
            state.get("request").expect("request should exist").status,
            NativeAuthorizationStatus::InProgress(_)
        ));
    }

    #[test]
    fn should_reject_claim_for_in_progress_or_completed_request() {
        let mut state = NativeAuthorizationState::default();
        state
            .insert("request".to_string(), record())
            .expect("insert should succeed");
        state
            .claim_for_completion("request", 10)
            .expect("first claim should succeed");

        assert!(matches!(
            state.claim_for_completion("request", 11),
            Err(CompleteNativeAuthorizationError::AlreadyCompleted)
        ));

        state
            .complete_claimed("request", completed(), 120)
            .expect("complete should succeed");
        assert!(matches!(
            state.claim_for_completion("request", 21),
            Err(CompleteNativeAuthorizationError::AlreadyCompleted)
        ));
    }

    #[test]
    fn should_release_only_in_progress_claims() {
        let mut state = NativeAuthorizationState::default();
        state
            .insert("request".to_string(), record())
            .expect("insert should succeed");
        state
            .claim_for_completion("request", 10)
            .expect("claim should succeed");

        state.release_claim("request");

        let record = state.get("request").expect("request should exist");
        assert!(matches!(record.status, NativeAuthorizationStatus::Pending));
        assert_eq!(record.expires_at, 100);

        state
            .claim_for_completion("request", 11)
            .expect("second claim should succeed");
        state
            .complete_claimed("request", completed(), 20)
            .expect("complete should succeed");
        state.release_claim("request");
        assert!(matches!(
            state.get("request").expect("request should exist").status,
            NativeAuthorizationStatus::Completed(_)
        ));
    }

    #[test]
    fn should_complete_only_claimed_request() {
        let mut state = NativeAuthorizationState::default();
        state
            .insert("request".to_string(), record())
            .expect("insert should succeed");

        assert!(matches!(
            state.complete_claimed("request", completed(), 20),
            Err(CompleteNativeAuthorizationError::NotFound)
        ));

        state
            .claim_for_completion("request", 10)
            .expect("claim should succeed");
        state
            .complete_claimed("request", completed(), 20)
            .expect("complete should succeed");
        assert!(matches!(
            state.get("request").expect("request should exist").status,
            NativeAuthorizationStatus::Completed(_)
        ));
    }
}
