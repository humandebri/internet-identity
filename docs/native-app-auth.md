# Native Browser Authorization

II native browser authorization now follows an OAuth-style split flow:

1. Native app calls `prepare_native_authorization`.
2. II returns `authorize_url` and short-lived `request_id`.
3. Native app opens `authorize_url` in a browser.
4. II completes user authentication on `/authorize`.
5. II redirects to `redirect_uri?code=<request_id>&state=<state>`.
6. Native app redeems the code with `redeem_native_authorization_code`.
7. II returns a short-lived II-native `access_token`, `token_type`, `expires_in`, and `id_token`.
8. Native app calls `exchange_native_access_token_for_delegation`.
9. II returns the regular IC delegation (`user_key` and `signed_delegation`).

## DX Model

- Wire protocol stays 2-step:
  1. `/oauth2/token`
  2. `/oauth2/delegation`
- Developer experience can stay 1-flow:
  - Use any standard OIDC client for the authorization code exchange.
  - Add one thin II-specific helper call for certified delegation retrieval.

`ic_delegation_endpoint` is exposed as a discovery extension field. Standard OIDC clients can
ignore it safely.

## Frontend Helper

Frontend code now has a thin utility at
`src/frontend/src/lib/utils/authentication/nativeOidc.ts`.

- `exchangeNativeOidcCode(...)`
  - Resolves discovery when needed.
  - Can use an explicit `tokenEndpoint` without discovery.
- Calls `POST /oauth2/token`.
- `fetchIcDelegation(...)`
  - Uses `Authorization: Bearer <access_token>` with `GET /oauth2/delegation`.
  - Converts the response into a frontend `DelegationChain`.
  - Can use an explicit `delegationEndpoint` without discovery.
- `completeNativeOidcLogin(...)`
  - Runs both steps and returns `DelegationIdentity`.
  - Requires `issuer`, or both `tokenEndpoint` and `delegationEndpoint`.

Minimal example:

```ts
import { Ed25519KeyIdentity } from "@icp-sdk/core/identity";
import { completeNativeOidcLogin } from "$lib/utils/authentication";

const sessionIdentity = Ed25519KeyIdentity.generate();

const { tokenResponse, delegationIdentity } = await completeNativeOidcLogin({
  issuer: "https://identity.ic0.app",
  clientId: "com.example.app",
  code,
  codeVerifier,
  redirectUri: "com.example.app:/oauth2redirect/ii",
  sessionIdentity,
});
```

If an app already owns the OIDC code exchange, use only the second step:

```ts
import { fetchIcDelegation } from "$lib/utils/authentication";

const { delegationChain } = await fetchIcDelegation({
  issuer: "https://identity.ic0.app",
  accessToken: tokenResponse.access_token,
});
```

Explicit endpoint override example:

```ts
import {
  exchangeNativeOidcCode,
  fetchIcDelegation,
} from "$lib/utils/authentication";

const tokenResponse = await exchangeNativeOidcCode({
  tokenEndpoint: "https://gateway.example/oauth2/token",
  clientId: "com.example.app",
  code,
  codeVerifier,
  redirectUri: "com.example.app:/oauth2redirect/ii",
});

const { delegationChain } = await fetchIcDelegation({
  delegationEndpoint: "https://gateway.example/oauth2/delegation",
  accessToken: tokenResponse.access_token,
});
```

## Endpoint Resolution

- `issuer` only
  - Helper reads discovery.
  - `token_endpoint` and `ic_delegation_endpoint` come from the discovery document.
- `tokenEndpoint` only
  - `exchangeNativeOidcCode(...)` can use it directly.
- `delegationEndpoint` only
  - `fetchIcDelegation(...)` can use it directly.
- `completeNativeOidcLogin(...)`
  - Must receive `issuer`, or both explicit endpoints.
  - Partial endpoint override is rejected as invalid configuration.

## Error Contract

- Helper failures throw `NativeOidcError`.
- Stable fields:
  - `phase`
    - `discovery`
    - `token`
    - `delegation`
  - `status`
    - HTTP status when the backend responded
  - `code`
    - backend error code such as `expired`, `not_found`, `invalid_token`
    - `invalid_configuration` for bad helper input
  - `message`
    - backend `error_description` when present, otherwise a synthesized message

Helper does not poll or retry. Usual usage should not add app-level retries for
`expired`, `not_found`, or `invalid_token`; those are terminal contract errors.
Network retries are only relevant for transport failures where no valid backend error
response was received.

Native OIDC HTTP responses are cross-origin readable and return
`Access-Control-Allow-Origin: *` on discovery, token, delegation, and JWKS.
`/oauth2/token` and `/oauth2/delegation` also return `Cache-Control: no-store, no-cache, max-age=0`
and `Pragma: no-cache` because they carry short-lived secrets.

Recommended delegation transport is `GET /oauth2/delegation` with
`Authorization: Bearer <access_token>`. Certified delegation retrieval still stays on the query
path, but the token no longer needs to appear in the URL for new clients.
Browser preflight for the `Authorization` header is supported by II CORS responses.

`GET /oauth2/delegation?access_token=...` remains available as legacy compatibility. The access
token is a short-lived exchange token, not a general Bearer token, but query transport can still
surface it in server logs, proxies, or APM systems. Prefer the header transport and avoid copying
or persisting legacy request URLs.

## Redirect URI Policy

Supported redirect URI classes:

- Claimed HTTPS
- Private-use URI scheme in reverse-domain form, for example `com.example.app:/oauth2redirect/ii`
- Loopback HTTP redirects on `127.0.0.1`, `localhost`, or `[::1]`

Rejected redirect URIs include:

- Query strings or fragments
- Userinfo
- Arbitrary short custom schemes such as `myapp:/callback`

For claimed HTTPS redirects, `redirect_uri` must match the prepared `origin`. Private-use and
loopback redirects are validated by URI class, registered `redirect_uri` membership, and registered
`allowed_origins` membership.

## Request Binding

`prepare_native_authorization` requires:

- `client_id`
- `redirect_uri`
- `state`
- `scope` including `openid`
- `nonce`
- `code_challenge`
  - Must satisfy RFC 7636 length bounds: 43-128 characters.
- `code_challenge_method` set to `S256`
- `response_type` set to `code`
- `response_mode` set to `query`

Native clients must also be statically registered in II config. Each registration contains:

- `client_id`
- allowed `redirect_uris`
- allowed `allowed_origins`
- `application_type = native`
- `token_endpoint_auth_method = none`
- `require_pkce = true`

`client_id` is a registered native client identifier. It does not need to be a developer domain or
HTTPS origin. `origin` must be a registered HTTPS origin in `allowed_origins`; it is the delegation
origin that will be bound to the issued IC delegation.

Registration is always bound to the `client_id` / `redirect_uri` / `origin` triple. Claimed HTTPS
redirects add one extra check: `origin` must match the redirect origin.

## Token Semantics

- `access_token` is an II-specific exchange token. It is not a Bearer token for arbitrary HTTP resources.
- `id_token` is signed with II-managed RSA keys and can be verified via `/.well-known/openid-configuration` and `/oauth2/jwks`.
- `id_token.sub` is pairwise per `client_id`; it is no longer the anchor number.
- IC delegation is only returned by `exchange_native_access_token_for_delegation`.
- `code_verifier` must also satisfy RFC 7636 length bounds: 43-128 characters.
- PKCE mismatch invalidates the authorization code immediately; retry with a corrected verifier does not work.
