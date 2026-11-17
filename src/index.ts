/**
 * eckey-utils — convert raw EC key material to and from PEM, DER and JWK.
 *
 * `crypto.createECDH()` hands out raw keys only, while `crypto.sign()` and
 * `crypto.verify()` need PEM (or a `KeyObject`). These helpers bridge the gap,
 * and parse key material back out of the encodings.
 */
import {
  decodePrivateKeyDer,
  decodePublicKeyDer,
  encodePrivateKeyDer,
  encodePublicKeyDer,
  fromPem,
  PEM_LABELS,
  toPem,
  type KeyInfo,
} from './der.js';
import { resolveCurveName, type CurveName } from './curves.js';
import { decodeJwk, encodeJwk, type EcJsonWebKey, type JwkKeyPair } from './jwk.js';

export type { CurveName, AnsiCurveName } from './curves.js';
export type { KeyInfo } from './der.js';
export type { EcJsonWebKey, JwkKeyPair } from './jwk.js';
export { CURVE_NAMES, CURVE_OIDS, ANSI_CURVES } from './curves.js';

/** Raw key material. `sk`/`pk` are the short aliases of `privateKey`/`publicKey`. */
export interface RawKeyMaterial {
  /** Raw EC private key (`d`). */
  sk?: Buffer | undefined;
  /** Raw EC private key (`d`); alias of {@link RawKeyMaterial.sk}. */
  privateKey?: Buffer | undefined;
  /** Raw uncompressed EC public key (`04 || x || y`). */
  pk?: Buffer | undefined;
  /** Raw uncompressed EC public key; alias of {@link RawKeyMaterial.pk}. */
  publicKey?: Buffer | undefined;
}

/** Curve name aliases accepted in the object form of the generate functions. */
export interface CurveAliases {
  /** Curve name; valid in the object form. */
  crv?: string | undefined;
  /** Curve name; alias of {@link CurveAliases.crv}. */
  curve?: string | undefined;
  /** Curve name; alias of {@link CurveAliases.crv}. */
  curveName?: string | undefined;
}

/**
 * What the generate functions accept: either a curve name plus optional key
 * material, or a single object carrying both.
 */
export type GenerateInput = string | (CurveAliases & RawKeyMaterial);

/** DER encoded key pair; a member is present only if it was requested. */
export interface DerKeyPair {
  privateKey?: Buffer | undefined;
  publicKey?: Buffer | undefined;
}

/** PEM encoded key pair; a member is present only if it was requested. */
export interface PemKeyPair {
  privateKey?: string | undefined;
  publicKey?: string | undefined;
}

const RAW_KEY_TYPE_ERROR = 'Only supports raw keys in Buffer';

interface NormalizedArgs {
  curve: unknown;
  privateKey: Buffer | undefined;
  publicKey: Buffer | undefined;
}

/** Flatten the two accepted argument forms into one shape. */
function normalizeArgs(input: GenerateInput, keys?: RawKeyMaterial): NormalizedArgs {
  const fromInput: RawKeyMaterial & CurveAliases = input && typeof input === 'object' ? input : {};
  const curve =
    typeof input === 'string' ? input : (fromInput.crv ?? fromInput.curve ?? fromInput.curveName);
  const privateKey = fromInput.sk || fromInput.privateKey || keys?.sk || keys?.privateKey;
  const publicKey = fromInput.pk || fromInput.publicKey || keys?.pk || keys?.publicKey;
  return { curve, privateKey, publicKey };
}

/** Validate the curve name and key material shared by every generate function. */
function resolveArgs(
  input: GenerateInput,
  keys?: RawKeyMaterial
): {
  curveName: CurveName;
  privateKey: Buffer | undefined;
  publicKey: Buffer | undefined;
} {
  const { curve, privateKey, publicKey } = normalizeArgs(input, keys);
  const curveName = resolveCurveName(curve);
  if (!privateKey && !publicKey) {
    throw new Error('Either privateKey or publicKey is required');
  }
  if ((privateKey && !Buffer.isBuffer(privateKey)) || (publicKey && !Buffer.isBuffer(publicKey))) {
    throw new Error(RAW_KEY_TYPE_ERROR);
  }
  return { curveName, privateKey, publicKey };
}

/**
 * Encode raw keys as DER.
 *
 * @example
 * ```ts
 * const ecdh = crypto.createECDH('prime256v1');
 * ecdh.generateKeys();
 * const { privateKey } = generateDer('prime256v1', {
 *   sk: ecdh.getPrivateKey(),
 *   pk: ecdh.getPublicKey(),
 * });
 * ```
 */
export function generateDer(input: GenerateInput, keys?: RawKeyMaterial): DerKeyPair {
  const { curveName, privateKey, publicKey } = resolveArgs(input, keys);
  const result: DerKeyPair = {};
  if (privateKey) {
    result.privateKey = encodePrivateKeyDer(curveName, privateKey, publicKey);
  }
  if (publicKey) {
    result.publicKey = encodePublicKeyDer(curveName, publicKey);
  }
  return result;
}

/**
 * Encode raw keys as PEM, ready for `crypto.sign()` / `crypto.verify()`.
 *
 * @example
 * ```ts
 * const { privateKey, publicKey } = generatePem('prime256v1', {
 *   sk: ecdh.getPrivateKey(),
 *   pk: ecdh.getPublicKey(),
 * });
 * ```
 */
export function generatePem(input: GenerateInput, keys?: RawKeyMaterial): PemKeyPair {
  const { curveName, privateKey, publicKey } = resolveArgs(input, keys);
  const result: PemKeyPair = {};
  if (privateKey) {
    result.privateKey = toPem(
      PEM_LABELS.privateKey,
      encodePrivateKeyDer(curveName, privateKey, publicKey)
    );
  }
  if (publicKey) {
    result.publicKey = toPem(PEM_LABELS.publicKey, encodePublicKeyDer(curveName, publicKey));
  }
  return result;
}

/** Parse an `ECPrivateKey` (RFC 5915) DER buffer. */
export function parseSkDer(der: Buffer): KeyInfo {
  return decodePrivateKeyDer(der);
}

/** Parse a `SubjectPublicKeyInfo` (RFC 5480) DER buffer. */
export function parsePkDer(der: Buffer): KeyInfo {
  return decodePublicKeyDer(der);
}

/**
 * Parse key material from a PEM block.
 *
 * Handles `EC PRIVATE KEY` (RFC 5915) and `PUBLIC KEY` (RFC 5480) blocks, with
 * LF or CRLF line endings, and returns the curve name plus raw keys.
 */
export function parsePem(pem: string): KeyInfo {
  if (!pem) {
    throw new Error('PEM content is not optional');
  }
  const { tag, der } = fromPem(pem);
  if (tag === PEM_LABELS.privateKey) {
    return decodePrivateKeyDer(der);
  }
  if (tag === PEM_LABELS.publicKey) {
    return decodePublicKeyDer(der);
  }
  throw new Error(
    `Unsupported PEM label "${tag}": expected "${PEM_LABELS.privateKey}" or "${PEM_LABELS.publicKey}"`
  );
}

/**
 * Build JWKs from raw keys.
 *
 * Supported curves are P-256, P-384 and P-521. A private JWK needs the raw
 * public key as well, since RFC 7518 requires `x` and `y` next to `d`.
 */
export function generateJwk(input: GenerateInput, keys?: RawKeyMaterial): JwkKeyPair {
  const { curveName, privateKey, publicKey } = resolveArgs(input, keys);
  return encodeJwk(curveName, privateKey, publicKey);
}

/** Rebuild raw key material from an EC JWK. */
export function parseJwk(jwk: EcJsonWebKey): KeyInfo {
  return decodeJwk(jwk);
}

/**
 * The 0.7 module shape: the same seven functions as a single object.
 *
 * Kept as the default export so `import ecKeyUtils from 'eckey-utils'` — the
 * pattern TypeScript and Babel users compile against a CommonJS package —
 * keeps working after the move to named exports.
 */
const ecKeyUtils = {
  generateDer,
  generateJwk,
  generatePem,
  parseJwk,
  parsePem,
  parsePkDer,
  parseSkDer,
};

export default ecKeyUtils;
