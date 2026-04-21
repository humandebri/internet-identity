# Native OIDC PR Draft

## Summary

This PR updates Internet Identity native browser authorization from the original
`prepare -> browser -> callback(native_request_id) -> fetch_native_delegation`
shape to an OAuth-style split flow:

`prepare -> browser authorize -> redirect_uri?code=...&state=... -> POST /oauth2/token -> GET /oauth2/delegation`

The PR scope is:

- native OIDC backend flow
- native OIDC frontend helper
- HTTP gateway update path
- docs, tests, and generated bindings

## What Changed

### Backend flow

- `prepare_native_authorization` now prepares an OAuth-style authorization code flow instead of
  returning a `native_request_id` callback contract.
- `complete_native_authorization` now completes browser auth by redirecting to
  `redirect_uri?code=<request_id>&state=<state>`.
- `redeem_native_authorization_code` exchanges that code for an II-native `access_token`,
  `token_type`, `expires_in`, and `id_token`.
- `exchange_native_access_token_for_delegation` turns the short-lived II exchange token into the
  certified IC delegation.

### HTTP gateway

- Added `http_request_update` because `/oauth2/token` must run as an update call.
- Added OIDC-facing HTTP endpoints:
  - `POST /oauth2/token`
  - `GET /oauth2/delegation`
  - `GET /.well-known/openid-configuration`
  - `GET /oauth2/jwks`
- Discovery now exposes the II-specific extension field `ic_delegation_endpoint`.

### Frontend helper

- Added thin helper APIs for app code:
  - `exchangeNativeOidcCode`
  - `fetchIcDelegation`
  - `completeNativeOidcLogin`
- The helper keeps the wire protocol 2-step, but exposes a single higher-level login flow for app
  integrations.

### Generated bindings

- Generated JS/TS bindings were resynced for the new public API surface.
- The generated sync is kept in dedicated commit `a3e86f36 chore(generated): resync internet_identity idl`.
- The GitHub PR diff still includes unrelated ICRC-3 generated churn. Restacking onto `origin/main`
  does not remove it.
- That extra churn comes from pre-existing drift between the DID and the generated frontend
  bindings on `origin/main`, not from the native OIDC flow itself. Reviewers should treat only the
  native OIDC binding additions as in-scope for this PR.

## Security And Transport Notes

- `/oauth2/token` and `/oauth2/delegation` return `Access-Control-Allow-Origin: *`.
- Both secret-carrying endpoints also return:
  - `Cache-Control: no-store, no-cache, max-age=0`
  - `Pragma: no-cache`
- The recommended delegation transport is:
  - `GET /oauth2/delegation`
  - `Authorization: Bearer <access_token>`
- `GET /oauth2/delegation?access_token=...` remains available as temporary legacy compatibility.
  New clients should not use it.
- `access_token` is an II-specific exchange token. It is not a general bearer token for arbitrary
  resources.
- `id_token.sub` is now a pairwise subject per `client_id`, not the anchor number.

## Known Limitations / Follow-Ups

- `prepare_native_authorization` is anonymously callable and currently relies only on global caps
  for pending requests and exchange tokens. Per-client, per-origin, and caller-scoped quotas are
  not part of this PR.
- Full removal of `GET /oauth2/delegation?access_token=...` is intentionally deferred because it
  is a compatibility decision, not a transport hardening bug.
- Pairwise `sub` stability depends on the configured issuer origin. Changing the issuer can rotate
  subjects and should be treated as an operational migration.

## Test Coverage

- HTTP integration covers:
  - CORS and no-store/no-cache headers on `/oauth2/token` and `/oauth2/delegation`
  - `Authorization` header transport
  - header precedence over query fallback
  - method contracts and `Allow` headers
- Native authorization integration covers:
  - short verifier rejection
  - 129-byte verifier rejection
  - immediate code invalidation after PKCE mismatch
- Frontend helper tests cover:
  - discovery-based endpoint resolution
  - explicit endpoint overrides
  - bearer header transport
  - terminal `expired` / `not_found` / `invalid_token` behavior without retries
