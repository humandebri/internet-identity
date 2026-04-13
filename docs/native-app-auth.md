# Native App Authorization With Browser

This flow lets a native app request an Internet Identity delegation without
hosting its own bridge frontend.

## Flow

1. The app generates a session key pair.
2. The app calls `prepare_native_authorization`, including the II frontend
   origin it wants the browser to open.
3. II returns a `request_id`, `authorize_url`, and expiration.
4. The app opens `authorize_url` in a browser-based auth surface.
5. The II frontend loads the native request and runs the existing `/authorize`
   flow.
6. After the user authenticates, the frontend calls
   `complete_native_authorization`.
7. II stores the signed delegation in short-lived canister memory.
8. The frontend redirects to the saved `return_link`, including
   `native_request_id` in the query string.
9. After the app resumes, it calls `fetch_native_delegation` to retrieve the
   `user_key` and `signed_delegation`.

## Callback Policy

- `return_link` must start with `https://`.
- Only universal links / app links are supported in v1.
- Custom URL schemes are not supported in v1.
- `return_link` must not contain a query string or fragment.
- The signed delegation is never embedded in the callback URL.

## Current Default Authorize URL

In v1, `authorize_url` is returned by the backend using the `ii_origin`
provided in `prepare_native_authorization`.

This lets the native app open the same II deployment that stored the request,
including local and staging environments.

## iOS Recommendation

On iOS, use `ASWebAuthenticationSession` as the primary auth surface.

The v1 flow does not guarantee app return through JavaScript-triggered
navigation in `WKWebView` or other generic webviews. The native app should rely
on the callback handling provided by `ASWebAuthenticationSession`.
