//! In-memory native authorization request state.
//! This state is intentionally short-lived and is not persisted across upgrades.
//! Completed requests keep only the data needed to reconstruct the signed delegation on fetch.

use internet_identity_interface::internet_identity::types::{
    AccountNumber, SessionKey, Timestamp, UserKey,
};
use std::collections::{HashMap, VecDeque};

const MAX_NATIVE_AUTHORIZATION_REQUESTS: usize = 1_000;

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
    Completed(CompletedNativeAuthorization),
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
    order: VecDeque<String>,
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
        self.order.push_back(request_id.clone());
        self.records.insert(request_id, record);
        Ok(())
    }

    pub fn get(&self, request_id: &str) -> Option<&NativeAuthorizationRecord> {
        self.records.get(request_id)
    }

    pub fn get_mut(&mut self, request_id: &str) -> Option<&mut NativeAuthorizationRecord> {
        self.records.get_mut(request_id)
    }

    pub fn prune_expired(&mut self, now: Timestamp) {
        self.records.retain(|_, record| record.expires_at > now);
        self.order
            .retain(|request_id| self.records.contains_key(request_id));
    }
}
