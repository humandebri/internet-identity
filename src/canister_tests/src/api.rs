use ic_cdk::api::management_canister::main::CanisterId;
use internet_identity_interface::http_gateway::{HttpRequest, HttpResponse};
use pocket_ic::{call_candid, query_candid, PocketIc, RejectResponse};

pub mod archive;
pub mod internet_identity;

// api methods common to all canisters

pub fn http_request(
    env: &PocketIc,
    canister_id: CanisterId,
    http_request: &HttpRequest,
) -> Result<HttpResponse, RejectResponse> {
    query_candid(env, canister_id, "http_request", (http_request,)).map(|(x,)| x)
}

pub fn http_request_update(
    env: &PocketIc,
    canister_id: CanisterId,
    http_request: &HttpRequest,
) -> Result<HttpResponse, RejectResponse> {
    call_candid(
        env,
        canister_id,
        pocket_ic::common::rest::RawEffectivePrincipal::None,
        "http_request_update",
        (http_request,),
    )
    .map(|(x,)| x)
}
