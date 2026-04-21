use crate::http::metrics::metrics;
use crate::native_authorization;
use crate::state;
use ic_canister_sig_creation::signature_map::LABEL_SIG;
use ic_certification::{labeled_hash, pruned};
use internet_identity_interface::http_gateway::{HeaderField, HttpRequest, HttpResponse};
use internet_identity_interface::internet_identity::types::RedeemNativeAuthorizationCodeRequest;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use serde_json::json;
use std::collections::BTreeMap;

mod metrics;

fn http_options_request() -> HttpResponse {
    // TODO: Restrict origin to just the II-specific origins.
    let headers = vec![("Access-Control-Allow-Origin".to_string(), "*".to_string())];

    HttpResponse {
        // Indicates success without any additional content to be sent in the response content.
        status_code: 204,
        headers,
        body: ByteBuf::from(vec![]),
        upgrade: None,
    }
}

fn http_get_request(
    url: String,
    _headers: Vec<HeaderField>,
    certificate_version: Option<u16>,
) -> HttpResponse {
    let parts: Vec<&str> = url.split('?').collect();

    match parts[0] {
        "/.well-known/openid-configuration" => {
            match native_authorization::openid_configuration_json() {
                Ok(body) => json_response(body),
                Err(err) => server_error(err),
            }
        }
        "/oauth2/jwks" => match native_authorization::jwks_json() {
            Ok(body) => json_response(body),
            Err(err) => server_error(err),
        },
        "/oauth2/delegation" => {
            let Some(query) = parts.get(1) else {
                return bad_request("missing access_token");
            };
            let Ok(fields) = parse_form_urlencoded(query.as_bytes()) else {
                return bad_request("invalid delegation exchange request");
            };
            let Ok(access_token) = required_form_field(&fields, "access_token") else {
                return bad_request("missing access_token");
            };
            match native_authorization::exchange_delegation(
                internet_identity_interface::internet_identity::types::ExchangeNativeAccessTokenForDelegationRequest {
                    access_token,
                },
            ) {
                Ok(response) => json_response(
                    serde_json::to_vec(&json!({
                        "user_key": response.user_key,
                        "signed_delegation": {
                            "delegation": {
                                "pubkey": response.signed_delegation.delegation.pubkey,
                                "expiration": response.signed_delegation.delegation.expiration,
                                "targets": response.signed_delegation.delegation.targets,
                            },
                            "signature": response.signed_delegation.signature,
                        },
                        "expiration": response.expiration,
                    }))
                    .expect("delegation exchange response should serialize"),
                ),
                Err(err) => delegation_exchange_error_response(err),
            }
        }
        "/metrics" => match metrics() {
            Ok(body) => {
                let mut headers = vec![
                    (
                        "Content-Type".to_string(),
                        "text/plain; version=0.0.4".to_string(),
                    ),
                    ("Content-Length".to_string(), body.len().to_string()),
                ];
                headers.append(&mut security_headers(None));
                HttpResponse {
                    status_code: 200,
                    headers,
                    body: ByteBuf::from(body),
                    upgrade: None,
                }
            }
            Err(err) => HttpResponse {
                status_code: 500,
                headers: security_headers(None),
                body: ByteBuf::from(format!("Failed to encode metrics: {err}")),
                upgrade: None,
            },
        },
        probably_an_asset => match get_asset(probably_an_asset, certificate_version) {
            Some((status_code, content, headers)) => HttpResponse {
                status_code,
                headers,
                body: ByteBuf::from(content),
                upgrade: None,
            },
            None => HttpResponse {
                status_code: 404,
                headers: security_headers(None),
                body: ByteBuf::from(format!("Asset {probably_an_asset} not found.")),
                upgrade: None,
            },
        },
    }
}

fn method_not_allowed(unsupported_method: &str) -> HttpResponse {
    HttpResponse {
        status_code: 405,
        headers: vec![("Allow".into(), "GET, OPTIONS".into())],
        body: ByteBuf::from(format!("Method {unsupported_method} not allowed.")),
        upgrade: None,
    }
}

pub fn http_request(req: HttpRequest) -> HttpResponse {
    let HttpRequest {
        method,
        url,
        certificate_version,
        headers,
        body: _,
    } = req;

    match method.as_str() {
        "OPTIONS" => http_options_request(),
        "GET" => http_get_request(url, headers, certificate_version),
        "POST" if is_upgradable_post(&url) => HttpResponse {
            status_code: 204,
            headers: vec![("Access-Control-Allow-Origin".to_string(), "*".to_string())],
            body: ByteBuf::from(vec![]),
            upgrade: Some(true),
        },
        unsupported_method => method_not_allowed(unsupported_method),
    }
}

pub async fn http_request_update(req: HttpRequest) -> HttpResponse {
    let HttpRequest {
        method,
        url,
        headers,
        body,
        certificate_version: _,
    } = req;
    if method != "POST" {
        return method_not_allowed(&method);
    }
    match url.split('?').next().unwrap_or_default() {
        "/oauth2/token" => {
            let Ok(request) = parse_redeem_request(&headers, &body) else {
                return bad_request("invalid token request");
            };
            match native_authorization::redeem_code(RedeemNativeAuthorizationCodeRequest {
                grant_type: request.grant_type,
                code: request.code,
                redirect_uri: request.redirect_uri,
                code_verifier: request.code_verifier,
                client_id: request.client_id,
            })
            .await
            {
                Ok(response) => json_response(
                    serde_json::to_vec(&json!({
                        "access_token": response.access_token,
                        "token_type": response.token_type,
                        "expires_in": response.expires_in,
                        "id_token": response.id_token,
                    }))
                    .expect("token response should serialize"),
                ),
                Err(err) => oauth_error_response(err),
            }
        }
        _ => method_not_allowed("POST"),
    }
}

fn json_response(body: Vec<u8>) -> HttpResponse {
    let mut headers = vec![
        ("Access-Control-Allow-Origin".to_string(), "*".to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Content-Length".to_string(), body.len().to_string()),
    ];
    headers.append(&mut security_headers(None));
    HttpResponse {
        status_code: 200,
        headers,
        body: ByteBuf::from(body),
        upgrade: None,
    }
}

fn server_error(message: String) -> HttpResponse {
    HttpResponse {
        status_code: 500,
        headers: plain_text_headers(message.len()),
        body: ByteBuf::from(message),
        upgrade: None,
    }
}

fn bad_request(message: &str) -> HttpResponse {
    HttpResponse {
        status_code: 400,
        headers: plain_text_headers(message.len()),
        body: ByteBuf::from(message.as_bytes().to_vec()),
        upgrade: None,
    }
}

fn json_headers(content_length: usize) -> Vec<HeaderField> {
    let mut headers = vec![
        ("Access-Control-Allow-Origin".to_string(), "*".to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Content-Length".to_string(), content_length.to_string()),
    ];
    headers.append(&mut security_headers(None));
    headers
}

fn plain_text_headers(content_length: usize) -> Vec<HeaderField> {
    let mut headers = vec![
        ("Access-Control-Allow-Origin".to_string(), "*".to_string()),
        (
            "Content-Type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        ),
        ("Content-Length".to_string(), content_length.to_string()),
    ];
    headers.append(&mut security_headers(None));
    headers
}

fn is_upgradable_post(url: &str) -> bool {
    matches!(url.split('?').next().unwrap_or_default(), "/oauth2/token")
}

fn oauth_error_response(
    error: internet_identity_interface::internet_identity::types::RedeemNativeAuthorizationCodeError,
) -> HttpResponse {
    let (status_code, error_name, description) = match error {
        internet_identity_interface::internet_identity::types::RedeemNativeAuthorizationCodeError::InvalidGrant(message) => {
            (400, "invalid_grant", message)
        }
        internet_identity_interface::internet_identity::types::RedeemNativeAuthorizationCodeError::InvalidRequest(message) => {
            (400, "invalid_request", message)
        }
        internet_identity_interface::internet_identity::types::RedeemNativeAuthorizationCodeError::UnsupportedGrantType(message) => {
            (400, "unsupported_grant_type", message)
        }
        internet_identity_interface::internet_identity::types::RedeemNativeAuthorizationCodeError::InternalCanisterError(message) => {
            (500, "server_error", message)
        }
    };
    let body = serde_json::to_vec(&json!({
        "error": error_name,
        "error_description": description,
    }))
    .expect("oauth error should serialize");
    HttpResponse {
        status_code,
        headers: json_headers(body.len()),
        body: ByteBuf::from(body),
        upgrade: None,
    }
}

fn delegation_exchange_error_response(
    error: internet_identity_interface::internet_identity::types::ExchangeNativeAccessTokenForDelegationError,
) -> HttpResponse {
    let (status_code, body) = match error {
        internet_identity_interface::internet_identity::types::ExchangeNativeAccessTokenForDelegationError::InvalidToken(message) => {
            (401, json!({"error": "invalid_token", "error_description": message}))
        }
        internet_identity_interface::internet_identity::types::ExchangeNativeAccessTokenForDelegationError::Expired => {
            (401, json!({"error": "expired"}))
        }
        internet_identity_interface::internet_identity::types::ExchangeNativeAccessTokenForDelegationError::NotFound => {
            (404, json!({"error": "not_found"}))
        }
        internet_identity_interface::internet_identity::types::ExchangeNativeAccessTokenForDelegationError::InternalCanisterError(message) => {
            (500, json!({"error": "server_error", "error_description": message}))
        }
    };
    let body = serde_json::to_vec(&body).expect("exchange error should serialize");
    HttpResponse {
        status_code,
        headers: json_headers(body.len()),
        body: ByteBuf::from(body),
        upgrade: None,
    }
}

#[derive(Deserialize)]
struct JsonRedeemRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
    client_id: String,
}

fn parse_redeem_request(headers: &[HeaderField], body: &[u8]) -> Result<JsonRedeemRequest, String> {
    if request_content_type(headers)
        .is_some_and(|content_type| content_type == "application/x-www-form-urlencoded")
    {
        let fields = parse_form_urlencoded(body)?;
        return Ok(JsonRedeemRequest {
            grant_type: required_form_field(&fields, "grant_type")?,
            code: required_form_field(&fields, "code")?,
            redirect_uri: required_form_field(&fields, "redirect_uri")?,
            code_verifier: required_form_field(&fields, "code_verifier")?,
            client_id: required_form_field(&fields, "client_id")?,
        });
    }
    serde_json::from_slice(body).map_err(|_| "invalid JSON token request".to_string())
}

fn request_content_type(headers: &[HeaderField]) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        })
}

fn parse_form_urlencoded(body: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let body = std::str::from_utf8(body).map_err(|_| "request body is not valid UTF-8")?;
    let mut fields = BTreeMap::new();
    for pair in body.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut parts = pair.splitn(2, '=');
        let key = percent_decode(parts.next().unwrap_or_default())?;
        let value = percent_decode(parts.next().unwrap_or_default())?;
        fields.insert(key, value);
    }
    Ok(fields)
}

fn required_form_field(fields: &BTreeMap<String, String>, name: &str) -> Result<String, String> {
    fields
        .get(name)
        .cloned()
        .ok_or_else(|| format!("missing form field: {name}"))
}

fn percent_decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err("truncated percent encoding".to_string());
                }
                let high = decode_hex(bytes[index + 1])?;
                let low = decode_hex(bytes[index + 2])?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| "decoded value is not valid UTF-8".to_string())
}

fn decode_hex(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid percent encoding".to_string()),
    }
}

/// List of recommended security headers as per https://owasp.org/www-project-secure-headers/
/// These headers enable browser security features (like limit access to platform apis and set
/// iFrame policies, etc.).
///
/// Integrity hashes for scripts must be specified.
pub fn security_headers(maybe_related_origins: Option<Vec<String>>) -> Vec<HeaderField> {
    // Allow related origins to create/get WebAuthn credentials from one another
    let public_key_credentials_create_get = maybe_related_origins
        .clone()
        .unwrap_or_default()
        .iter()
        .fold("self".to_string(), |acc, origin| {
            acc + " \"" + origin + "\""
        });

    vec![
        // X-Frame-Options: DENY
        // Prevents the page from being displayed in a frame, iframe, embed or object
        // This is a legacy header, also enforced by CSP frame-ancestors directive
        ("X-Frame-Options".to_string(), "DENY".to_string()),
        // X-Content-Type-Options: nosniff
        // Prevents browsers from MIME-sniffing a response away from the declared content-type
        // Reduces risk of drive-by downloads and serves as defense against MIME confusion attacks
        ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
        // Content-Security-Policy (CSP)
        // Blocks all resource loading (scripts, styles, images, fonts, frames, etc.)
        // If any HTML is ever rendered, nothing executes
        // Effectively neutralizes most XSS risks
        (
            "Content-Security-Policy".to_string(),
            "default-src 'none';".to_string(),
        ),
        // Strict-Transport-Security (HSTS)
        // Forces browsers to use HTTPS for all future requests to this domain
        // max-age=31536000: Valid for 1 year (31,536,000 seconds)
        // includeSubDomains: Also applies to all subdomains of this domain
        (
            "Strict-Transport-Security".to_string(),
            "max-age=31536000 ; includeSubDomains".to_string(),
        ),
        // Referrer-Policy: same-origin
        // Controls how much referrer information is sent with outgoing requests
        // same-origin: Only send referrer to same-origin requests (no cross-origin leakage)
        // Note: "no-referrer" would be more strict but breaks local dev deployment
        ("Referrer-Policy".to_string(), "same-origin".to_string()),
        // Permissions-Policy (formerly Feature-Policy)
        // Controls which browser features and APIs can be used
        // Most permissions are denied by default, with specific exceptions:
        // - clipboard-write=(self): Allow copying to clipboard from same origin
        // - publickey-credentials-get: Allow WebAuthn from self and related origins
        // - sync-xhr=(self): Allow synchronous XMLHttpRequest from same origin
        (
            "Permissions-Policy".to_string(),
            format!(
                "accelerometer=(),\
                 ambient-light-sensor=(),\
                 autoplay=(),\
                 battery=(),\
                 camera=(),\
                 clipboard-read=(),\
                 clipboard-write=(self),\
                 conversion-measurement=(),\
                 cross-origin-isolated=(),\
                 display-capture=(),\
                 document-domain=(),\
                 encrypted-media=(),\
                 execution-while-not-rendered=(),\
                 execution-while-out-of-viewport=(),\
                 focus-without-user-activation=(),\
                 fullscreen=(),\
                 gamepad=(),\
                 geolocation=(),\
                 gyroscope=(),\
                 hid=(),\
                 idle-detection=(),\
                 interest-cohort=(),\
                 keyboard-map=(),\
                 magnetometer=(),\
                 microphone=(),\
                 midi=(),\
                 navigation-override=(),\
                 payment=(),\
                 picture-in-picture=(),\
                 publickey-credentials-create=({public_key_credentials_create_get}),\
                 publickey-credentials-get=({public_key_credentials_create_get}),\
                 screen-wake-lock=(),\
                 serial=(),\
                 speaker-selection=(),\
                 sync-script=(),\
                 sync-xhr=(self),\
                 trust-token-redemption=(),\
                 usb=(),\
                 vertical-scroll=(),\
                 web-share=(),\
                 window-placement=(),\
                 xr-spatial-tracking=()"
            )
            .to_string(),
        ),
    ]
}

/// Read an asset from memory, returning the associated HTTP code, content and full list of
/// headers that were certified with the asset.
fn get_asset(
    asset_name: &str,
    certificate_version: Option<u16>,
) -> Option<(u16, Vec<u8>, Vec<HeaderField>)> {
    state::assets_and_signatures(|assets, sigs| {
        let asset = assets.get_certified_asset(
            asset_name,
            certificate_version,
            Some(pruned(labeled_hash(LABEL_SIG, &sigs.root_hash()))),
        )?;
        let shared_headers = assets.shared_headers.clone();

        let mut headers = asset.headers.clone();
        headers.append(&mut shared_headers.to_vec());

        Some((asset.status_code, asset.content, headers))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_parse_form_urlencoded_token_request() {
        let headers = vec![(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded; charset=utf-8".to_string(),
        )];
        let request = parse_redeem_request(
            &headers,
            b"grant_type=authorization_code&code=abc123&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&code_verifier=verifier-123&client_id=https%3A%2F%2Fapp.example.com",
        )
        .expect("form request should parse");

        assert_eq!(request.grant_type, "authorization_code");
        assert_eq!(request.code, "abc123");
        assert_eq!(request.redirect_uri, "https://app.example.com/callback");
        assert_eq!(request.code_verifier, "verifier-123");
        assert_eq!(request.client_id, "https://app.example.com");
    }

    #[test]
    fn should_decode_plus_in_form_urlencoded_values() {
        let fields = parse_form_urlencoded(b"nonce=hello+world").expect("form body should parse");
        assert_eq!(fields.get("nonce"), Some(&"hello world".to_string()));
    }
}
