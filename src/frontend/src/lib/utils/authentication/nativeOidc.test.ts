import { describe, expect, it, vi } from "vitest";
import { Ed25519KeyIdentity } from "@icp-sdk/core/identity";
import {
  completeNativeOidcLogin,
  exchangeNativeOidcCode,
  fetchIcDelegation,
} from "./nativeOidc";

const discoveryBody = JSON.stringify({
  issuer: "https://identity.ic0.app",
  authorization_endpoint: "https://identity.ic0.app/authorize",
  token_endpoint: "https://identity.ic0.app/oauth2/token",
  ic_delegation_endpoint: "https://identity.ic0.app/oauth2/delegation",
  jwks_uri: "https://identity.ic0.app/oauth2/jwks",
});

const tokenBody = JSON.stringify({
  access_token: "native-access-token",
  token_type: "https://identity.ic0.app/oauth/token-type/native-access-token",
  expires_in: 300,
  id_token: "header.payload.signature",
});

const delegationBody = `{
  "user_key":[1,2,3,4],
  "signed_delegation":{
    "delegation":{
      "pubkey":[5,6,7,8],
      "expiration":1844674407370955160,
      "targets":null
    },
    "signature":[9,10,11]
  },
  "expiration":1844674407370955161
}`;

const targetedDelegationBody = `{
  "expiration":1844674407370955161,
  "signed_delegation":{
    "signature":[9,10,11],
    "delegation":{
      "targets":["aaaaa-aa"],
      "expiration":1844674407370955160,
      "pubkey":[5,6,7,8]
    }
  },
  "user_key":[1,2,3,4]
}`;

describe("nativeOidc", () => {
  it("resolves discovery and exchanges a native OIDC code", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(discoveryBody))
      .mockResolvedValueOnce(jsonResponse(tokenBody));

    const response = await exchangeNativeOidcCode({
      issuer: "https://identity.ic0.app",
      fetchFn: fetchMock,
      clientId: "com.example.app",
      code: "native-code",
      codeVerifier: "native-verifier",
      redirectUri: "com.example.app:/oauth2redirect/ii",
    });

    expect(response.access_token).toBe("native-access-token");
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://identity.ic0.app/.well-known/openid-configuration",
      expect.objectContaining({ method: "GET" }),
    );
    const [, tokenInit] = fetchMock.mock.calls[1];
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://identity.ic0.app/oauth2/token",
      expect.objectContaining({ method: "POST" }),
    );
    expect(tokenInit?.headers).toEqual(
      expect.objectContaining({
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      }),
    );
    expect(String(tokenInit?.body)).toContain("grant_type=authorization_code");
    expect(String(tokenInit?.body)).toContain("code=native-code");
    expect(String(tokenInit?.body)).toContain("client_id=com.example.app");
  });

  it("rejects discovery when returned issuer does not match requested issuer", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      jsonResponse(
        JSON.stringify({
          ...JSON.parse(discoveryBody),
          issuer: "https://evil.example.com",
        }),
      ),
    );

    await expect(
      exchangeNativeOidcCode({
        issuer: "https://identity.ic0.app",
        fetchFn: fetchMock,
        clientId: "com.example.app",
        code: "native-code",
        codeVerifier: "native-verifier",
        redirectUri: "com.example.app:/oauth2redirect/ii",
      }),
    ).rejects.toMatchObject({
      name: "NativeOidcError",
      phase: "discovery",
      code: "invalid_configuration",
    });
  });

  it("uses an explicit token endpoint without discovery", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse(tokenBody));

    const response = await exchangeNativeOidcCode({
      tokenEndpoint: "https://gateway.example/oauth2/token",
      fetchFn: fetchMock,
      clientId: "com.example.app",
      code: "native-code",
      codeVerifier: "native-verifier",
      redirectUri: "com.example.app:/oauth2redirect/ii",
    });

    expect(response.access_token).toBe("native-access-token");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://gateway.example/oauth2/token",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("rejects code exchange without issuer or token endpoint as invalid configuration", async () => {
    await expect(
      exchangeNativeOidcCode({
        fetchFn: vi.fn(),
        clientId: "com.example.app",
        code: "native-code",
        codeVerifier: "native-verifier",
        redirectUri: "com.example.app:/oauth2redirect/ii",
      }),
    ).rejects.toMatchObject({
      name: "NativeOidcError",
      phase: "discovery",
      code: "invalid_configuration",
      message: "issuer is required when tokenEndpoint is missing",
    });
  });

  it("fetches certified delegation and converts it to a DelegationChain", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(discoveryBody))
      .mockResolvedValueOnce(jsonResponse(delegationBody));

    const { delegationResponse, delegationChain } = await fetchIcDelegation({
      issuer: "https://identity.ic0.app",
      fetchFn: fetchMock,
      accessToken: "native-access-token",
    });

    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://identity.ic0.app/oauth2/delegation",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Accept: "application/json",
          Authorization: "Bearer native-access-token",
        }),
      }),
    );
    expect(delegationResponse.expiration).toBe(BigInt("1844674407370955161"));
    expect(delegationResponse.signed_delegation.delegation.expiration).toBe(
      BigInt("1844674407370955160"),
    );
    expect(delegationChain.delegations).toHaveLength(1);
    expect(delegationChain.delegations[0].delegation.expiration).toBe(
      BigInt("1844674407370955160"),
    );
    expect(Array.from(delegationChain.publicKey)).toEqual([1, 2, 3, 4]);
  });

  it("parses bigint expirations and populated targets without field-order dependence", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(targetedDelegationBody));

    const { delegationResponse, delegationChain } = await fetchIcDelegation({
      delegationEndpoint: "https://gateway.example/oauth2/delegation",
      fetchFn: fetchMock,
      accessToken: "native-access-token",
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://gateway.example/oauth2/delegation",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Accept: "application/json",
          Authorization: "Bearer native-access-token",
        }),
      }),
    );
    const parsedTargets =
      delegationResponse.signed_delegation.delegation.targets[0];
    expect(parsedTargets).toBeDefined();
    expect(parsedTargets?.[0].toText()).toBe("aaaaa-aa");
    expect(
      delegationChain.delegations[0].delegation.targets?.[0].toText(),
    ).toBe("aaaaa-aa");
  });

  it("rejects delegation fetch without issuer or delegation endpoint as invalid configuration", async () => {
    await expect(
      fetchIcDelegation({
        fetchFn: vi.fn(),
        accessToken: "native-access-token",
      }),
    ).rejects.toMatchObject({
      name: "NativeOidcError",
      phase: "discovery",
      code: "invalid_configuration",
      message: "issuer is required when delegationEndpoint is missing",
    });
  });

  it("completes the token and delegation flow in one helper call", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(discoveryBody))
      .mockResolvedValueOnce(jsonResponse(tokenBody))
      .mockResolvedValueOnce(jsonResponse(delegationBody));
    const sessionIdentity = Ed25519KeyIdentity.generate();

    const result = await completeNativeOidcLogin({
      issuer: "https://identity.ic0.app",
      fetchFn: fetchMock,
      clientId: "com.example.app",
      code: "native-code",
      codeVerifier: "native-verifier",
      redirectUri: "com.example.app:/oauth2redirect/ii",
      sessionIdentity,
    });

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(result.tokenResponse.id_token).toBe("header.payload.signature");
    expect(result.delegationChain.delegations).toHaveLength(1);
    expect(result.delegationIdentity.getDelegation().delegations).toHaveLength(
      1,
    );
  });

  it("passes only token inputs to code exchange and only delegation inputs to delegation fetch", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(tokenBody))
      .mockResolvedValueOnce(jsonResponse(delegationBody));

    await completeNativeOidcLogin({
      tokenEndpoint: "https://gateway.example/oauth2/token",
      delegationEndpoint: "https://gateway.example/oauth2/delegation",
      fetchFn: fetchMock,
      clientId: "com.example.app",
      code: "native-code",
      codeVerifier: "native-verifier",
      redirectUri: "com.example.app:/oauth2redirect/ii",
      sessionIdentity: Ed25519KeyIdentity.generate(),
    });

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://gateway.example/oauth2/token",
      expect.objectContaining({ method: "POST" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://gateway.example/oauth2/delegation",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("surfaces delegation exchange errors without polling", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(JSON.stringify({ error: "expired" }), 401),
      );

    await expect(
      fetchIcDelegation({
        delegationEndpoint: "https://identity.ic0.app/oauth2/delegation",
        fetchFn: fetchMock,
        accessToken: "expired-token",
      }),
    ).rejects.toMatchObject({
      name: "NativeOidcError",
      phase: "delegation",
      code: "expired",
      status: 401,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("surfaces not_found and invalid_token responses without retries", async () => {
    const notFoundFetch = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(JSON.stringify({ error: "not_found" }), 404),
      );
    const invalidTokenFetch = vi.fn().mockResolvedValueOnce(
      jsonResponse(
        JSON.stringify({
          error: "invalid_token",
          error_description: "delegation is not available for the access token",
        }),
        401,
      ),
    );

    await expect(
      fetchIcDelegation({
        delegationEndpoint: "https://identity.ic0.app/oauth2/delegation",
        fetchFn: notFoundFetch,
        accessToken: "missing-token",
      }),
    ).rejects.toMatchObject({
      phase: "delegation",
      code: "not_found",
      status: 404,
    });
    await expect(
      fetchIcDelegation({
        delegationEndpoint: "https://identity.ic0.app/oauth2/delegation",
        fetchFn: invalidTokenFetch,
        accessToken: "invalid-token",
      }),
    ).rejects.toMatchObject({
      phase: "delegation",
      code: "invalid_token",
      status: 401,
      message: "delegation is not available for the access token",
    });
    expect(notFoundFetch).toHaveBeenCalledTimes(1);
    expect(invalidTokenFetch).toHaveBeenCalledTimes(1);
    expect(notFoundFetch).toHaveBeenCalledWith(
      "https://identity.ic0.app/oauth2/delegation",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer missing-token",
        }),
      }),
    );
    expect(invalidTokenFetch).toHaveBeenCalledWith(
      "https://identity.ic0.app/oauth2/delegation",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({
          Authorization: "Bearer invalid-token",
        }),
      }),
    );
  });

  it("requires issuer or both explicit endpoints for completeNativeOidcLogin", async () => {
    await expect(
      completeNativeOidcLogin({
        tokenEndpoint: "https://gateway.example/oauth2/token",
        clientId: "com.example.app",
        code: "native-code",
        codeVerifier: "native-verifier",
        redirectUri: "com.example.app:/oauth2redirect/ii",
        sessionIdentity: Ed25519KeyIdentity.generate(),
      }),
    ).rejects.toMatchObject({
      name: "NativeOidcError",
      phase: "discovery",
      code: "invalid_configuration",
    });
  });
});

const jsonResponse = (body: string, status = 200): Response =>
  new Response(body, {
    status,
    headers: { "Content-Type": "application/json" },
  });
