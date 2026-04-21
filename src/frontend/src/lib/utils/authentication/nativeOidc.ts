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
  fetchFn?: FetchFn;
};

type NativeOidcCodeExchangeEndpointConfig = NativeOidcEndpointConfig & {
  tokenEndpoint?: string;
};

type NativeOidcDelegationEndpointConfig = NativeOidcEndpointConfig & {
  delegationEndpoint?: string;
};

type NativeOidcCodeExchangeInput = NativeOidcCodeExchangeEndpointConfig & {
  clientId: string;
  code: string;
  codeVerifier: string;
  redirectUri: string;
};

type NativeOidcDelegationInput = NativeOidcDelegationEndpointConfig & {
  accessToken: string;
};

type CompleteNativeOidcLoginInput = NativeOidcCodeExchangeInput &
  NativeOidcDelegationEndpointConfig & {
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
    clientId: input.clientId,
    code: input.code,
    codeVerifier: input.codeVerifier,
    redirectUri: input.redirectUri,
    fetchFn: input.fetchFn,
    issuer: input.issuer,
    tokenEndpoint: endpoints.tokenEndpoint,
  });
  const { delegationResponse, delegationChain } = await fetchIcDelegation({
    issuer: input.issuer,
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
  input: NativeOidcCodeExchangeEndpointConfig & NativeOidcDelegationEndpointConfig,
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
  input: NativeOidcCodeExchangeEndpointConfig & NativeOidcDelegationEndpointConfig,
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
  input: NativeOidcCodeExchangeEndpointConfig,
): Promise<string> => {
  if (input.tokenEndpoint !== undefined) {
    return input.tokenEndpoint;
  }
  if (input.issuer === undefined) {
    throw new Error("issuer is required when tokenEndpoint is missing");
  }
  return (
    await resolveNativeOidcEndpoints({
      issuer: input.issuer,
      fetchFn: input.fetchFn,
    })
  ).tokenEndpoint;
};

const resolveDelegationEndpoint = async (
  input: NativeOidcDelegationEndpointConfig,
): Promise<string> => {
  if (input.delegationEndpoint !== undefined) {
    return input.delegationEndpoint;
  }
  if (input.issuer === undefined) {
    throw new Error("issuer is required when delegationEndpoint is missing");
  }
  return (
    await resolveNativeOidcEndpoints({
      issuer: input.issuer,
      fetchFn: input.fetchFn,
    })
  ).delegationEndpoint;
};
