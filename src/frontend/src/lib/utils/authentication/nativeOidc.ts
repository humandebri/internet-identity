/**
 * Frontend helper for native OIDC login.
 * Keeps the certified delegation flow as a safe 2-step wire protocol
 * while exposing a thin 1-flow DX for app code.
 */
import type {
  ExchangeNativeAccessTokenForDelegationResponse,
  RedeemNativeAuthorizationCodeResponse,
} from "$lib/generated/internet_identity_types";
import { transformSignedDelegation } from "$lib/utils/utils";
import type { SignIdentity } from "@icp-sdk/core/agent";
import { DelegationChain, DelegationIdentity } from "@icp-sdk/core/identity";
import {
  nativeOidcError,
  NativeOidcError,
  parseDelegationResponse,
  parseDiscoveryDocument,
  parseTokenResponse,
  readJsonBody,
  readJsonText,
  type NativeOidcDiscoveryDocument,
} from "./nativeOidcParsing";

export { NativeOidcError } from "./nativeOidcParsing";

type FetchFn = typeof fetch;

type NativeOidcEndpointConfig = {
  issuer?: string;
  tokenEndpoint?: string;
  delegationEndpoint?: string;
  fetchFn?: FetchFn;
};

type NativeOidcCodeExchangeInput = NativeOidcEndpointConfig & {
  clientId: string;
  code: string;
  codeVerifier: string;
  redirectUri: string;
};

type NativeOidcDelegationInput = NativeOidcEndpointConfig & {
  accessToken: string;
};

type CompleteNativeOidcLoginInput = NativeOidcCodeExchangeInput & {
  sessionIdentity: SignIdentity;
};

type CompleteNativeOidcLoginResult = {
  tokenResponse: RedeemNativeAuthorizationCodeResponse;
  delegationResponse: ExchangeNativeAccessTokenForDelegationResponse;
  delegationChain: DelegationChain;
  delegationIdentity: DelegationIdentity;
};

export const fetchNativeOidcDiscovery = async ({
  issuer,
  fetchFn = fetch,
}: {
  issuer: string;
  fetchFn?: FetchFn;
}): Promise<NativeOidcDiscoveryDocument> => {
  const response = await fetchFn(`${issuer}/.well-known/openid-configuration`, {
    method: "GET",
    headers: { Accept: "application/json" },
  });
  const body = await readJsonBody(response, "discovery");
  if (!response.ok) {
    throw nativeOidcError({
      phase: "discovery",
      status: response.status,
      body,
    });
  }
  return parseDiscoveryDocument(body);
};

export const exchangeNativeOidcCode = async (
  input: NativeOidcCodeExchangeInput,
): Promise<RedeemNativeAuthorizationCodeResponse> => {
  const tokenEndpoint = await resolveTokenEndpoint(input);
  const formBody = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    redirect_uri: input.redirectUri,
    code_verifier: input.codeVerifier,
    client_id: input.clientId,
  });
  const response = await (input.fetchFn ?? fetch)(tokenEndpoint, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: formBody,
  });
  const parsed = await readJsonBody(response, "token");
  if (!response.ok) {
    throw nativeOidcError({
      phase: "token",
      status: response.status,
      body: parsed,
    });
  }
  return parseTokenResponse(parsed);
};

export const fetchIcDelegation = async (
  input: NativeOidcDelegationInput,
): Promise<{
  delegationResponse: ExchangeNativeAccessTokenForDelegationResponse;
  delegationChain: DelegationChain;
}> => {
  const delegationEndpoint = await resolveDelegationEndpoint(input);
  const response = await (input.fetchFn ?? fetch)(delegationEndpoint, {
    method: "GET",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${input.accessToken}`,
    },
  });
  const { body } = await readJsonText(response, "delegation");
  if (!response.ok) {
    throw nativeOidcError({
      phase: "delegation",
      status: response.status,
      body,
    });
  }
  const delegationResponse = parseDelegationResponse(body);
  const delegationChain = DelegationChain.fromDelegations(
    [transformSignedDelegation(delegationResponse.signed_delegation)],
    new Uint8Array(delegationResponse.user_key),
  );
  return { delegationResponse, delegationChain };
};

export const completeNativeOidcLogin = async (
  input: CompleteNativeOidcLoginInput,
): Promise<CompleteNativeOidcLoginResult> => {
  const endpoints = await resolveCompleteNativeOidcEndpoints(input);
  const tokenResponse = await exchangeNativeOidcCode({
    ...input,
    tokenEndpoint: endpoints.tokenEndpoint,
    delegationEndpoint: endpoints.delegationEndpoint,
  });
  const { delegationResponse, delegationChain } = await fetchIcDelegation({
    tokenEndpoint: endpoints.tokenEndpoint,
    delegationEndpoint: endpoints.delegationEndpoint,
    fetchFn: input.fetchFn,
    accessToken: tokenResponse.access_token,
  });
  return {
    tokenResponse,
    delegationResponse,
    delegationChain,
    delegationIdentity: DelegationIdentity.fromDelegation(
      input.sessionIdentity,
      delegationChain,
    ),
  };
};

const resolveNativeOidcEndpoints = async (
  input: NativeOidcEndpointConfig,
): Promise<{ tokenEndpoint: string; delegationEndpoint: string }> => {
  if (
    input.tokenEndpoint !== undefined &&
    input.delegationEndpoint !== undefined
  ) {
    return {
      tokenEndpoint: input.tokenEndpoint,
      delegationEndpoint: input.delegationEndpoint,
    };
  }
  if (input.issuer === undefined) {
    throw new Error(
      "issuer is required when tokenEndpoint or delegationEndpoint is missing",
    );
  }
  const discovery = await fetchNativeOidcDiscovery({
    issuer: input.issuer,
    fetchFn: input.fetchFn,
  });
  return {
    tokenEndpoint: input.tokenEndpoint ?? discovery.tokenEndpoint,
    delegationEndpoint:
      input.delegationEndpoint ?? discovery.icDelegationEndpoint,
  };
};

const resolveCompleteNativeOidcEndpoints = (
  input: NativeOidcEndpointConfig,
): Promise<{ tokenEndpoint: string; delegationEndpoint: string }> => {
  if (input.issuer !== undefined) {
    return resolveNativeOidcEndpoints(input);
  }
  if (
    input.tokenEndpoint !== undefined &&
    input.delegationEndpoint !== undefined
  ) {
    return Promise.resolve({
      tokenEndpoint: input.tokenEndpoint,
      delegationEndpoint: input.delegationEndpoint,
    });
  }
  throw new NativeOidcError({
    phase: "discovery",
    code: "invalid_configuration",
    message:
      "completeNativeOidcLogin requires issuer or both tokenEndpoint and delegationEndpoint",
  });
};

const resolveTokenEndpoint = async (
  input: NativeOidcEndpointConfig,
): Promise<string> => {
  if (input.tokenEndpoint !== undefined) {
    return input.tokenEndpoint;
  }
  return (await resolveNativeOidcEndpoints(input)).tokenEndpoint;
};

const resolveDelegationEndpoint = async (
  input: NativeOidcEndpointConfig,
): Promise<string> => {
  if (input.delegationEndpoint !== undefined) {
    return input.delegationEndpoint;
  }
  return (await resolveNativeOidcEndpoints(input)).delegationEndpoint;
};
