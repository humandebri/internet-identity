import { type Readable, derived, writable, get } from "svelte/store";
import { authenticatedStore } from "$lib/stores/authentication.store";
import { remapToLegacyDomain } from "$lib/utils/iiConnection";
import {
  waitFor,
  throwCanisterError,
  transformSignedDelegation,
  retryFor,
} from "$lib/utils/utils";
import { features } from "$lib/legacy/features";
import { anonymousActor, frontendCanisterConfig } from "$lib/globals";
import { validateDerivationOrigin } from "$lib/utils/validateDerivationOrigin";
import { DelegationChain } from "@icp-sdk/core/identity";
import { AuthRequest, DelegationParams } from "$lib/utils/transport/utils";
import { fromBase64URL } from "$lib/utils/utils";

export type AuthorizationContext = {
  kind: "channel" | "native";
  authRequest: AuthRequest; // Additional details e.g. derivation origin
  requestId: string | number; // The ID of the JSON RPC request
  requestOrigin: string; // Displayed to the user to identify the app
  effectiveOrigin: string; // Used for last used storage and delegations
  isAuthenticating: boolean; // True if user is being redirect back to app
};

type AuthorizationResult =
  | {
      kind: "channel";
      requestId: string | number;
      delegationChain: DelegationChain;
    }
  | {
      kind: "native";
      redirectUrl: string;
    };

type AuthorizationStore = Readable<AuthorizationContext | undefined> & {
  handleRequest: (
    requestOrigin: string,
    requestId: string | number,
    params: DelegationParams,
  ) => Promise<void>;
  handleNativeOidcAuthorizeRequest: (params: URLSearchParams) => Promise<void>;
  authorize: (
    accountNumber: Promise<bigint | undefined> | bigint | undefined,
    artificialDelay?: number,
  ) => Promise<AuthorizationResult>;
};

const internalStore = writable<AuthorizationContext | undefined>();

export const authorizationStore: AuthorizationStore = {
  handleRequest: async (requestOrigin, requestId, params) => {
    const effectiveOrigin = remapToLegacyDomain(
      params.icrc95DerivationOrigin ?? requestOrigin,
    );
    const validationResult = await validateDerivationOrigin({
      requestOrigin,
      derivationOrigin: params.icrc95DerivationOrigin,
    });
    if (validationResult.result === "invalid") {
      throw new Error("Unverified origin");
    }
    internalStore.set({
      kind: "channel",
      authRequest: {
        kind: "authorize-client",
        sessionPublicKey: new Uint8Array(params.publicKey.toDer()),
        maxTimeToLive: params.maxTimeToLive,
        derivationOrigin: params.icrc95DerivationOrigin,
      },
      requestId,
      requestOrigin,
      effectiveOrigin,
      isAuthenticating: false,
    });
  },
  handleNativeOidcAuthorizeRequest: async (params) => {
    const request = nativeOidcAuthorizeRequest(params);
    const { request_id } = await anonymousActor
      .register_native_authorization_request(request)
      .then(throwCanisterError);
    internalStore.set({
      kind: "native",
      authRequest: {
        kind: "authorize-client",
        sessionPublicKey: new Uint8Array(request.session_public_key),
        maxTimeToLive: request.max_time_to_live[0],
      },
      requestId: request_id,
      requestOrigin: request.origin,
      effectiveOrigin: request.origin,
      isAuthenticating: false,
    });
  },
  subscribe: (...args) => internalStore.subscribe(...args),
  authorize: async (accountNumberMaybePromise, artificialDelay) => {
    const context = get(authorizationContextStore);
    internalStore.set({
      ...context,
      isAuthenticating: true,
    });
    const { identityNumber, actor } = get(authenticatedStore);
    const artificialDelayPromise = waitFor(
      features.DUMMY_AUTH ||
        frontendCanisterConfig.dummy_auth[0]?.[0] !== undefined
        ? 0
        : (artificialDelay ?? 0),
    );
    const accountNumber = await accountNumberMaybePromise;
    if (context.kind === "native") {
      const { redirect_url } = await actor
        .complete_native_authorization(
          identityNumber,
          `${context.requestId}`,
          accountNumber !== undefined ? [accountNumber] : [],
        )
        .then(throwCanisterError);
      await artificialDelayPromise;
      return {
        kind: "native",
        redirectUrl: redirect_url,
      };
    }
    const { user_key, expiration } = await actor
      .prepare_account_delegation(
        identityNumber,
        context.effectiveOrigin,
        accountNumber !== undefined ? [accountNumber] : [],
        context.authRequest.sessionPublicKey,
        context.authRequest.maxTimeToLive !== undefined
          ? [context.authRequest.maxTimeToLive]
          : [],
      )
      .then(throwCanisterError);
    const delegationChain = await retryFor(5, () =>
      actor
        .get_account_delegation(
          identityNumber,
          context.effectiveOrigin,
          accountNumber !== undefined ? [accountNumber] : [],
          context.authRequest.sessionPublicKey,
          expiration,
        )
        .then(throwCanisterError)
        .then(transformSignedDelegation)
        .then((delegation) =>
          DelegationChain.fromDelegations(
            [delegation],
            new Uint8Array(user_key),
          ),
        ),
    );
    await artificialDelayPromise;
    return {
      kind: "channel",
      requestId: context.requestId,
      delegationChain,
    };
  },
};

const requiredNativeAuthorizeParam = (
  params: URLSearchParams,
  name: string,
): string => {
  const values = params.getAll(name);
  if (values.length !== 1 || values[0] === "") {
    throw new Error(`Invalid native OIDC authorization request: ${name}`);
  }
  return values[0];
};

const optionalNativeAuthorizeNat64 = (
  params: URLSearchParams,
  name: string,
): [] | [bigint] => {
  const values = params.getAll(name);
  if (values.length === 0) {
    return [];
  }
  if (values.length !== 1 || !/^[0-9]+$/.test(values[0])) {
    throw new Error(`Invalid native OIDC authorization request: ${name}`);
  }
  return [BigInt(values[0])];
};

const nativeAuthorizeSessionPublicKey = (
  params: URLSearchParams,
): Uint8Array => {
  try {
    return fromBase64URL(
      requiredNativeAuthorizeParam(params, "ic_session_public_key"),
    );
  } catch {
    throw new Error(
      "Invalid native OIDC authorization request: ic_session_public_key",
    );
  }
};

const nativeOidcAuthorizeRequest = (params: URLSearchParams) => ({
  response_type: requiredNativeAuthorizeParam(params, "response_type"),
  client_id: requiredNativeAuthorizeParam(params, "client_id"),
  redirect_uri: requiredNativeAuthorizeParam(params, "redirect_uri"),
  scope: requiredNativeAuthorizeParam(params, "scope"),
  state: requiredNativeAuthorizeParam(params, "state"),
  nonce: requiredNativeAuthorizeParam(params, "nonce"),
  code_challenge: requiredNativeAuthorizeParam(params, "code_challenge"),
  code_challenge_method: requiredNativeAuthorizeParam(
    params,
    "code_challenge_method",
  ),
  origin: requiredNativeAuthorizeParam(params, "ic_origin"),
  session_public_key: nativeAuthorizeSessionPublicKey(params),
  max_time_to_live: optionalNativeAuthorizeNat64(
    params,
    "ic_max_time_to_live",
  ),
});

export const authorizationContextStore: Readable<AuthorizationContext> =
  derived(authorizationStore, (context) => {
    if (context === undefined) {
      throw new Error("Authorization context is not available yet");
    }
    return context;
  });
