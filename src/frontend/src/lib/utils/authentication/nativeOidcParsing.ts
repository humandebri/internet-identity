/**
 * Parsing helpers for native OIDC HTTP responses.
 * Keeps bigint-sensitive delegation parsing isolated from orchestration code.
 */
import type {
  ExchangeNativeAccessTokenForDelegationResponse,
  RedeemNativeAuthorizationCodeResponse,
} from "$lib/generated/internet_identity_types";
import { Principal } from "@icp-sdk/core/principal";

export type NativeOidcDiscoveryDocument = {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  icDelegationEndpoint: string;
};

export class NativeOidcError extends Error {
  readonly phase: "discovery" | "token" | "delegation";
  readonly status?: number;
  readonly code?: string;

  constructor({
    phase,
    message,
    status,
    code,
  }: {
    phase: "discovery" | "token" | "delegation";
    message: string;
    status?: number;
    code?: string;
  }) {
    super(message);
    this.name = "NativeOidcError";
    this.phase = phase;
    this.status = status;
    this.code = code;
  }
}

export const readJsonBody = async (
  response: Response,
  phase: "discovery" | "token" | "delegation",
): Promise<unknown> => {
  const { body } = await readJsonText(response, phase);
  return body;
};

export const readJsonText = async (
  response: Response,
  phase: "discovery" | "token" | "delegation",
): Promise<{ text: string; body: unknown }> => {
  const text = await response.text();
  try {
    return {
      text,
      body:
        phase === "delegation" ? parseDelegationJson(text) : JSON.parse(text),
    };
  } catch {
    throw new NativeOidcError({
      phase,
      status: response.status,
      message: `${phase} response is not valid JSON`,
    });
  }
};

export const nativeOidcError = ({
  phase,
  status,
  body,
}: {
  phase: "discovery" | "token" | "delegation";
  status: number;
  body: unknown;
}): NativeOidcError => {
  const error =
    isRecord(body) && typeof body.error === "string" ? body.error : undefined;
  const description =
    isRecord(body) && typeof body.error_description === "string"
      ? body.error_description
      : undefined;
  return new NativeOidcError({
    phase,
    status,
    code: error,
    message:
      description ?? error ?? `${phase} request failed with status ${status}`,
  });
};

export const parseDiscoveryDocument = (
  value: unknown,
): NativeOidcDiscoveryDocument => {
  const record = expectRecord(value, "native OIDC discovery");
  return {
    issuer: expectString(record, "issuer"),
    authorizationEndpoint: expectString(record, "authorization_endpoint"),
    tokenEndpoint: expectString(record, "token_endpoint"),
    icDelegationEndpoint: expectString(record, "ic_delegation_endpoint"),
  };
};

export const parseTokenResponse = (
  value: unknown,
): RedeemNativeAuthorizationCodeResponse => {
  const record = expectRecord(value, "native OIDC token response");
  return {
    access_token: expectString(record, "access_token"),
    token_type: expectString(record, "token_type"),
    expires_in: BigInt(expectSafeInteger(record, "expires_in")),
    id_token: expectString(record, "id_token"),
  };
};

export const parseDelegationResponse = (
  value: unknown,
): ExchangeNativeAccessTokenForDelegationResponse => {
  const record = expectRecord(value, "native OIDC delegation response");
  const signedDelegationRecord = expectRecord(
    record.signed_delegation,
    "signed_delegation",
  );
  const delegationRecord = expectRecord(
    signedDelegationRecord.delegation,
    "delegation",
  );
  return {
    user_key: expectByteArray(record, "user_key"),
    signed_delegation: {
      delegation: {
        pubkey: expectByteArray(delegationRecord, "pubkey"),
        expiration: expectBigInt(delegationRecord, "expiration"),
        targets: expectTargets(delegationRecord, "targets"),
      },
      signature: expectByteArray(signedDelegationRecord, "signature"),
    },
    expiration: expectBigInt(record, "expiration"),
  };
};

const parseDelegationJson = (jsonText: string): unknown =>
  JSON.parse(
    quoteBigIntFields(jsonText, new Set(["expiration"])),
    (_key, value) => (isBigIntString(value) ? BigInt(value) : value),
  );

const quoteBigIntFields = (
  jsonText: string,
  fieldNames: Set<string>,
): string => {
  let result = "";
  let index = 0;

  while (index < jsonText.length) {
    const current = jsonText[index];
    if (current !== '"') {
      result += current;
      index += 1;
      continue;
    }

    const stringToken = readJsonStringToken(jsonText, index);
    result += stringToken.literal;
    index = stringToken.nextIndex;

    const afterString = consumeWhitespace(jsonText, index);
    if (!fieldNames.has(stringToken.value) || jsonText[afterString] !== ":") {
      continue;
    }

    result += jsonText.slice(index, afterString + 1);
    const valueStart = consumeWhitespace(jsonText, afterString + 1);
    result += jsonText.slice(afterString + 1, valueStart);
    const valueInfo = readJsonNumber(jsonText, valueStart);
    if (valueInfo === undefined) {
      throw new Error(
        `expected numeric JSON value for field ${stringToken.value}`,
      );
    }
    result += `"${valueInfo.value}"`;
    index = valueInfo.nextIndex;
  }

  return result;
};

const readJsonStringToken = (
  jsonText: string,
  quoteIndex: number,
): { literal: string; value: string; nextIndex: number } => {
  let index = quoteIndex + 1;
  let escaped = false;
  let value = "";

  while (index < jsonText.length) {
    const current = jsonText[index];
    if (escaped) {
      value += current;
      escaped = false;
    } else if (current === "\\") {
      escaped = true;
    } else if (current === '"') {
      return {
        literal: jsonText.slice(quoteIndex, index + 1),
        value,
        nextIndex: index + 1,
      };
    } else {
      value += current;
    }
    index += 1;
  }

  throw new Error("unterminated JSON string");
};

const readJsonNumber = (
  jsonText: string,
  startIndex: number,
): { value: string; nextIndex: number } | undefined => {
  let index = startIndex;
  let value = "";
  if (jsonText[index] === "-") {
    value += "-";
    index += 1;
  }
  while (index < jsonText.length && isDigit(jsonText[index])) {
    value += jsonText[index];
    index += 1;
  }
  return value.length > 0 && value !== "-"
    ? { value, nextIndex: index }
    : undefined;
};

const consumeWhitespace = (jsonText: string, startIndex: number): number => {
  let index = startIndex;
  while (index < jsonText.length && /\s/.test(jsonText[index])) {
    index += 1;
  }
  return index;
};

const isDigit = (value: string): boolean => value >= "0" && value <= "9";

const isBigIntString = (value: unknown): value is string =>
  typeof value === "string" && /^-?\d+$/.test(value);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const expectRecord = (
  value: unknown,
  label: string,
): Record<string, unknown> => {
  if (!isRecord(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
};

const expectString = (
  record: Record<string, unknown>,
  field: string,
): string => {
  const value = record[field];
  if (typeof value !== "string") {
    throw new Error(`${field} must be a string`);
  }
  return value;
};

const expectBigInt = (
  record: Record<string, unknown>,
  field: string,
): bigint => {
  const value = record[field];
  if (typeof value !== "bigint") {
    throw new Error(`${field} must be a bigint`);
  }
  return value;
};

const expectSafeInteger = (
  record: Record<string, unknown>,
  field: string,
): number => {
  const value = record[field];
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new Error(`${field} must be a safe integer`);
  }
  return value;
};

const expectByteArray = (
  record: Record<string, unknown>,
  field: string,
): Uint8Array => {
  const value = record[field];
  if (
    !Array.isArray(value) ||
    value.some(
      (item) =>
        typeof item !== "number" ||
        !Number.isInteger(item) ||
        item < 0 ||
        item > 255,
    )
  ) {
    throw new Error(`${field} must be a byte array`);
  }
  return Uint8Array.from(value);
};

const expectTargets = (
  record: Record<string, unknown>,
  field: string,
): [] | [Principal[]] => {
  const value = record[field];
  if (value === null) {
    return [];
  }
  if (
    Array.isArray(value) &&
    value.every((target) => typeof target === "string")
  ) {
    return [value.map((target) => Principal.fromText(target))];
  }
  throw new Error(`${field} must be null or an array of principal strings`);
};
