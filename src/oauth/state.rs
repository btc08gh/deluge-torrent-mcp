// Copyright (c) 2026 Sandy McArthur, Jr.
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::sync::Mutex;
use tracing::trace;

pub const CODE_TTL: Duration = Duration::from_secs(10 * 60);
pub const ACCESS_TOKEN_TTL: Duration = Duration::from_secs(60 * 60);
pub const REFRESH_TOKEN_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub const REFRESH_GRACE_PERIOD: Duration = Duration::from_secs(30);
pub const PENDING_AUTH_TTL: Duration = Duration::from_secs(5 * 60);
pub const MAX_CLIENTS: usize = 100;
pub const MAX_PENDING_AUTHORIZATIONS: usize = 1000;
/// Clients that never complete authorization are removed after this period.
pub const UNAUTHED_CLIENT_TTL: Duration = Duration::from_secs(15 * 60);

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

pub struct ClientInfo {
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    #[allow(dead_code)]
    pub grant_types: Vec<String>,
    pub created_at: Instant,
    /// Set to `true` once a token has been issued for this client.
    /// Unauthorized clients are garbage-collected after `UNAUTHED_CLIENT_TTL`.
    pub authorized: bool,
}

pub struct CodeInfo {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scope: String,
    pub expires_at: Instant,
}

#[allow(dead_code)]
pub struct TokenInfo {
    pub client_id: String,
    pub scope: String,
    pub expires_at: Instant,
}

pub struct RefreshInfo {
    pub client_id: String,
    pub scope: String,
    pub access_token: String,
    pub expires_at: Instant,
    /// Set when this token has been rotated out. The token remains valid for
    /// `REFRESH_GRACE_PERIOD` after this timestamp to handle network failures.
    pub superseded_at: Option<Instant>,
}

/// Stores the validated parameters from a GET /authorize request while the
/// consent page is displayed to the user. The nonce ties the POST back to
/// this pending authorization.
#[derive(Clone)]
pub struct PendingAuth {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scope: String,
    pub state_param: String,
    pub expires_at: Instant,
}

// ---------------------------------------------------------------------------
// OAuthState
// ---------------------------------------------------------------------------

pub struct OAuthState {
    pub issuer: String,
    pub resource: String,
    pub api_token: Option<String>,
    clients: Mutex<HashMap<String, ClientInfo>>,
    codes: Mutex<HashMap<String, CodeInfo>>,
    access_tokens: Mutex<HashMap<String, TokenInfo>>,
    refresh_tokens: Mutex<HashMap<String, RefreshInfo>>,
    pending_authorizations: Mutex<HashMap<String, PendingAuth>>,
}

impl OAuthState {
    pub fn new(issuer: String, api_token: Option<String>) -> Self {
        let resource = format!("{issuer}/mcp");
        Self {
            issuer,
            resource,
            api_token,
            clients: Mutex::new(HashMap::new()),
            codes: Mutex::new(HashMap::new()),
            access_tokens: Mutex::new(HashMap::new()),
            refresh_tokens: Mutex::new(HashMap::new()),
            pending_authorizations: Mutex::new(HashMap::new()),
        }
    }

    // -- Client operations --

    pub async fn client_count(&self) -> usize {
        self.clients.lock().await.len()
    }

    pub async fn register_client(&self, client_id: String, info: ClientInfo) {
        self.clients.lock().await.insert(client_id, info);
    }

    pub async fn get_client_name(&self, client_id: &str) -> Option<Option<String>> {
        self.clients.lock().await.get(client_id).map(|c| c.client_name.clone())
    }

    pub async fn client_has_redirect_uri(&self, client_id: &str, redirect_uri: &str) -> Option<bool> {
        self.clients.lock().await.get(client_id).map(|c| c.redirect_uris.iter().any(|u| u == redirect_uri))
    }

    pub async fn client_exists(&self, client_id: &str) -> bool {
        self.clients.lock().await.contains_key(client_id)
    }

    pub async fn mark_client_authorized(&self, client_id: &str) -> bool {
        let mut clients = self.clients.lock().await;
        match clients.get_mut(client_id) {
            Some(client) => {
                client.authorized = true;
                true
            }
            None => false,
        }
    }

    // -- Pending authorization operations --

    pub async fn pending_auth_count(&self) -> usize {
        self.pending_authorizations.lock().await.len()
    }

    pub async fn insert_pending_auth(&self, nonce: String, pending: PendingAuth) {
        self.pending_authorizations.lock().await.insert(nonce, pending);
    }

    pub async fn get_pending_auth(&self, nonce: &str) -> Option<PendingAuth> {
        self.pending_authorizations.lock().await.get(nonce).cloned()
    }

    pub async fn take_pending_auth(&self, nonce: &str) -> Option<PendingAuth> {
        self.pending_authorizations.lock().await.remove(nonce)
    }

    // -- Authorization code operations --

    pub async fn insert_auth_code(&self, code: String, info: CodeInfo) {
        self.codes.lock().await.insert(code, info);
    }

    pub async fn take_auth_code(&self, code: &str) -> Option<CodeInfo> {
        self.codes.lock().await.remove(code)
    }

    // -- Access token operations --

    pub async fn validate_token(&self, token: &str) -> bool {
        let tokens = self.access_tokens.lock().await;
        let valid = matches!(tokens.get(token), Some(info) if info.expires_at > Instant::now());
        trace!(valid, "Bearer token validation");
        valid
    }

    pub async fn insert_access_token(&self, token: String, info: TokenInfo) {
        self.access_tokens.lock().await.insert(token, info);
    }

    pub async fn revoke_access_token(&self, token: &str) {
        self.access_tokens.lock().await.remove(token);
    }

    // -- Refresh token operations --

    pub async fn insert_refresh_token(&self, token: String, info: RefreshInfo) {
        self.refresh_tokens.lock().await.insert(token, info);
    }

    /// Look up a refresh token and return a snapshot of its data.
    /// Does NOT remove it — caller decides based on grace period logic.
    pub async fn get_refresh_info(&self, token: &str) -> Option<RefreshSnapshot> {
        self.refresh_tokens.lock().await.get(token).map(|info| RefreshSnapshot {
            client_id: info.client_id.clone(),
            scope: info.scope.clone(),
            access_token: info.access_token.clone(),
            expires_at: info.expires_at,
            superseded_at: info.superseded_at,
        })
    }

    pub async fn remove_refresh_token(&self, token: &str) {
        self.refresh_tokens.lock().await.remove(token);
    }

    /// Mark a refresh token as superseded. Uses `get_or_insert` so that a
    /// grace-period retry does not bump the timestamp.
    pub async fn mark_refresh_superseded(&self, token: &str, now: Instant) {
        if let Some(info) = self.refresh_tokens.lock().await.get_mut(token) {
            info.superseded_at.get_or_insert(now);
        }
    }

    // -- Cleanup --

    pub async fn sweep_expired(&self) -> SweepResult {
        let now = Instant::now();
        let mut result = SweepResult::default();

        self.codes.lock().await.retain(|_, v| {
            if v.expires_at > now { true } else { result.codes += 1; false }
        });

        self.access_tokens.lock().await.retain(|_, v| {
            if v.expires_at > now { true } else { result.access_tokens += 1; false }
        });

        self.refresh_tokens.lock().await.retain(|_, v| {
            if v.expires_at <= now {
                result.refresh_tokens += 1;
                return false;
            }
            if let Some(superseded) = v.superseded_at {
                if now.duration_since(superseded) >= REFRESH_GRACE_PERIOD {
                    result.refresh_tokens += 1;
                    return false;
                }
            }
            true
        });

        self.pending_authorizations.lock().await.retain(|_, v| {
            if v.expires_at > now { true } else { result.pending_auths += 1; false }
        });

        self.clients.lock().await.retain(|_, v| {
            if v.authorized || now.duration_since(v.created_at) < UNAUTHED_CLIENT_TTL {
                true
            } else {
                result.clients += 1;
                false
            }
        });

        result
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn generate_random_hex(len: usize) -> String {
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Snapshot of refresh token data returned by `get_refresh_info`.
pub struct RefreshSnapshot {
    pub client_id: String,
    pub scope: String,
    pub access_token: String,
    pub expires_at: Instant,
    pub superseded_at: Option<Instant>,
}

#[derive(Default)]
pub struct SweepResult {
    pub codes: usize,
    pub access_tokens: usize,
    pub refresh_tokens: usize,
    pub pending_auths: usize,
    pub clients: usize,
}
