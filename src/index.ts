/**
 * eckey-utils — convert raw EC key material to and from PEM, DER and JWK.
 *
 * `crypto.createECDH()` hands out raw keys only, while `crypto.sign()` and
 * `crypto.verify()` need PEM (or a `KeyObject`). These helpers bridge the gap,
 * and parse key material back out of the encodings.
 */
import {
  decodeAnyPrivateKeyDer,
  decodePkcs8Der,
  decodePrivateKeyDer,
  decodePublicKeyDer,
  encodePkcs8Der,
  encodePrivateKeyDer,
  encodePublicKeyDer,
  fromPem,
  PEM_LABELS,
  toPem,
  type KeyInfo,
} from './der.js';
import { CURVE_KEY_BYTES, resolveCurveName, type CurveName } from './curves.js';
import {
  decodeOkpJwk,
  encodeOkpJwk,
  isOkpCurveName,
  type OkpCurveName,
  type OkpJsonWebKey,
  type OkpKeyInfo,
  type OkpKeyPair,
} from './okp.js';
import { decodeJwk, encodeJwk, type EcJsonWebKey, type JwkKeyPair } from './jwk.js';

export type { CurveName, AnsiCurveName } from './curves.js';
export type { KeyInfo } from './der.js';
export type { EcJsonWebKey, JwkKeyPair } from './jwk.js';
export type { OkpCurveName, OkpJsonWebKey, OkpKeyInfo, OkpKeyPair } from './okp.js';
export { OKP_CURVES } from './okp.js';
export { CURVE_NAMES, CURVE_OIDS, CURVE_KEY_BYTES, ANSI_CURVES } from './curves.js';

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

/** How private keys are encoded by the generate functions. */
export interface GenerateOptions {
  /**
   * Private key encoding: `sec1` (RFC 5915, `EC PRIVATE KEY`, the default) or
   * `pkcs8` (RFC 5958, `PRIVATE KEY`). Public keys are unaffected.
   */
  type?: 'sec1' | 'pkcs8' | undefined;
}

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

function resolveKeyType(options?: GenerateOptions): 'sec1' | 'pkcs8' {
  const type = options?.type ?? 'sec1';
  if (type !== 'sec1' && type !== 'pkcs8') {
    throw new Error(`Unsupported private key type: ${String(type)}`);
  }
  return type;
}

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

/**
 * Check that raw keys have the size the curve expects.
 *
 * A key from another curve, a truncated buffer or a hex string decodes to a
 * plausible-looking encoding, so the size is the only local signal that
 * something is wrong. The expected point length depends on the prefix, which
 * also keeps an uncompressed point of one curve from passing as a compressed
 * point of another.
 */
function checkKeyLengths(curveName: CurveName, privateKey?: Buffer, publicKey?: Buffer): void {
  const keyBytes = CURVE_KEY_BYTES[curveName];
  if (privateKey && privateKey.length > keyBytes) {
    throw new Error(
      `Private key length ${privateKey.length} does not match curve ${curveName} (expected at most ${keyBytes})`
    );
  }
  if (!publicKey) {
    return;
  }
  const compressed = 1 + keyBytes;
  const uncompressed = 1 + 2 * keyBytes;
  const expected =
    publicKey[0] === 0x04
      ? uncompressed
      : publicKey[0] === 0x02 || publicKey[0] === 0x03
        ? compressed
        : undefined;
  if (expected !== undefined && publicKey.length !== expected) {
    throw new Error(
      `Public key length ${publicKey.length} does not match curve ${curveName} ` +
        `(expected ${uncompressed} for an uncompressed point, ${compressed} for a compressed one)`
    );
  }
}

/** Require at least one key, and require both to be `Buffer`s. */
function assertRawKeys(privateKey: Buffer | undefined, publicKey: Buffer | undefined): void {
  if (!privateKey && !publicKey) {
    throw new Error('Either privateKey or publicKey is required');
  }
  if ((privateKey && !Buffer.isBuffer(privateKey)) || (publicKey && !Buffer.isBuffer(publicKey))) {
    throw new Error(RAW_KEY_TYPE_ERROR);
  }
}

/** Validate the curve name and key material shared by the EC generate functions. */
function resolveArgs(normalized: NormalizedArgs): {
  curveName: CurveName;
  privateKey: Buffer | undefined;
  publicKey: Buffer | undefined;
} {
  const { curve, privateKey, publicKey } = normalized;
  const curveName = resolveCurveName(curve);
  assertRawKeys(privateKey, publicKey);
  checkKeyLengths(curveName, privateKey, publicKey);
  return { curveName, privateKey, publicKey };
}

/**
 * Encode raw keys as DER.
 *
 * Pass `{ type: 'pkcs8' }` as the third argument for PKCS#8 private keys.
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
export function generateDer(
  input: GenerateInput,
  keys?: RawKeyMaterial,
  options?: GenerateOptions
): DerKeyPair {
  const { curveName, privateKey, publicKey } = resolveArgs(normalizeArgs(input, keys));
  const type = resolveKeyType(options);
  const result: DerKeyPair = {};
  if (privateKey) {
    result.privateKey =
      type === 'pkcs8'
        ? encodePkcs8Der(curveName, privateKey, publicKey)
        : encodePrivateKeyDer(curveName, privateKey, publicKey);
  }
  if (publicKey) {
    result.publicKey = encodePublicKeyDer(curveName, publicKey);
  }
  return result;
}

/**
 * Encode raw keys as PEM, ready for `crypto.sign()` / `crypto.verify()`.
 *
 * Pass `{ type: 'pkcs8' }` as the third argument to write PKCS#8 private keys
 * instead of RFC 5915 ones.
 *
 * @example
 * ```ts
 * const { privateKey, publicKey } = generatePem('prime256v1', {
 *   sk: ecdh.getPrivateKey(),
 *   pk: ecdh.getPublicKey(),
 * });
 * ```
 */
export function generatePem(
  input: GenerateInput,
  keys?: RawKeyMaterial,
  options?: GenerateOptions
): PemKeyPair {
  const { curveName, privateKey, publicKey } = resolveArgs(normalizeArgs(input, keys));
  const type = resolveKeyType(options);
  const result: PemKeyPair = {};
  if (privateKey) {
    const tag = type === 'pkcs8' ? PEM_LABELS.pkcs8 : PEM_LABELS.privateKey;
    const der =
      type === 'pkcs8'
        ? encodePkcs8Der(curveName, privateKey, publicKey)
        : encodePrivateKeyDer(curveName, privateKey, publicKey);
    result.privateKey = toPem(tag, der);
  }
  if (publicKey) {
    result.publicKey = toPem(PEM_LABELS.publicKey, encodePublicKeyDer(curveName, publicKey));
  }
  return result;
}

/**
 * Parse a private key DER buffer: `ECPrivateKey` (RFC 5915) or PKCS#8
 * `PrivateKeyInfo` (RFC 5958). The two are told apart by their version number.
 */
export function parseSkDer(der: Buffer): KeyInfo {
  return decodeAnyPrivateKeyDer(der);
}

/** Parse a `SubjectPublicKeyInfo` (RFC 5480) DER buffer. */
export function parsePkDer(der: Buffer): KeyInfo {
  return decodePublicKeyDer(der);
}

/**
 * Parse key material from a PEM block.
 *
 * Handles `EC PRIVATE KEY` (RFC 5915), `PRIVATE KEY` (PKCS#8, RFC 5958) and
 * `PUBLIC KEY` (RFC 5480) blocks, with LF or CRLF line endings, and returns the
 * curve name plus raw keys.
 */
export function parsePem(pem: string): KeyInfo {
  if (!pem) {
    throw new Error('PEM content is not optional');
  }
  const { tag, der } = fromPem(pem);
  if (tag === PEM_LABELS.privateKey) {
    return decodePrivateKeyDer(der);
  }
  if (tag === PEM_LABELS.pkcs8) {
    return decodePkcs8Der(der);
  }
  if (tag === PEM_LABELS.publicKey) {
    return decodePublicKeyDer(der);
  }
  throw new Error(
    `Unsupported PEM label "${tag}": expected "${PEM_LABELS.privateKey}", "${PEM_LABELS.pkcs8}" or "${PEM_LABELS.publicKey}"`
  );
}

/**
 * Build JWKs from raw keys.
 *
 * EC curves produce RFC 7518 keys (`P-256`, `P-384`, `P-521`) and RFC 8812 keys
 * (`secp256k1`) with `x`, `y` and `d`; `Ed25519` and `Ed448` produce RFC 8037
 * OKP keys with `x` and `d`. A private JWK needs the raw public key as well,
 * because both standards require the public half next to `d`.
 */
export function generateJwk(curve: OkpCurveName, keys?: RawKeyMaterial): OkpKeyPair;
export function generateJwk(input: GenerateInput, keys?: RawKeyMaterial): JwkKeyPair;
export function generateJwk(input: GenerateInput, keys?: RawKeyMaterial): JwkKeyPair | OkpKeyPair {
  const normalized = normalizeArgs(input, keys);
  if (isOkpCurveName(normalized.curve)) {
    assertRawKeys(normalized.privateKey, normalized.publicKey);
    return encodeOkpJwk(normalized.curve, normalized.privateKey, normalized.publicKey);
  }
  const { curveName, privateKey, publicKey } = resolveArgs(normalized);
  return encodeJwk(curveName, privateKey, publicKey);
}

/**
 * Rebuild raw key material from a JWK.
 *
 * Accepts EC keys (`kty: "EC"`) and OKP keys (`kty: "OKP"`, Ed25519/Ed448).
 */
export function parseJwk(jwk: OkpJsonWebKey): OkpKeyInfo;
export function parseJwk(jwk: EcJsonWebKey): KeyInfo;
export function parseJwk(jwk: EcJsonWebKey | OkpJsonWebKey): KeyInfo | OkpKeyInfo {
  return jwk && jwk.kty === 'OKP' ? decodeOkpJwk(jwk) : decodeJwk(jwk as EcJsonWebKey);
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
