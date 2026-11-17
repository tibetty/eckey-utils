/**
 * DER and PEM encoding of EC keys:
 *
 * - `ECPrivateKey` (RFC 5915), wrapped as `-----BEGIN EC PRIVATE KEY-----`.
 * - `SubjectPublicKeyInfo` (RFC 5480), wrapped as `-----BEGIN PUBLIC KEY-----`.
 *
 * Only raw key material is handled here; keys are always encoded on a named
 * curve, never with explicit domain parameters.
 */
import {
  decodeOid,
  decodeTlv,
  encodeBitString,
  encodeOctetString,
  encodeOid,
  encodeSmallInteger,
  encodeTlv,
} from './asn1.js';
import { curveFromOid, CURVE_OIDS, type CurveName } from './curves.js';

/** OID of the `id-ecPublicKey` algorithm (RFC 5480). */
const ID_EC_PUBLIC_KEY = encodeOid('1.2.840.10045.2.1');

/** Key material recovered from a DER or PEM encoded key. */
export interface KeyInfo {
  /** Curve the key belongs to. */
  curveName: CurveName;
  /** Raw EC private key (`d`), present for private keys that carry it. */
  privateKey?: Buffer | undefined;
  /** Raw uncompressed EC point (`04 || x || y`), when the encoding includes it. */
  publicKey?: Buffer | undefined;
}

const TAG = {
  integer: 0x02,
  bitString: 0x03,
  octetString: 0x04,
  oid: 0x06,
  sequence: 0x30,
  context0: 0xa0,
  context1: 0xa1,
} as const;

/**
 * Encode an `ECPrivateKey` (RFC 5915).
 *
 * @param curve  Curve the key belongs to.
 * @param sk     Raw private key.
 * @param pk     Raw public key, embedded when supplied.
 */
export function encodePrivateKeyDer(curve: CurveName, sk: Buffer, pk?: Buffer): Buffer {
  const parameters = encodeTlv(TAG.context0, encodeOid(CURVE_OIDS[curve]));
  const publicKey = pk ? encodeTlv(TAG.context1, encodeBitString(pk)) : Buffer.alloc(0);
  return encodeTlv(
    TAG.sequence,
    Buffer.concat([
      encodeSmallInteger(1), // ECPrivateKey version 1
      encodeOctetString(sk),
      parameters,
      publicKey,
    ])
  );
}

/**
 * Encode a `SubjectPublicKeyInfo` (RFC 5480) for an EC public key.
 *
 * @param curve Curve the key belongs to.
 * @param pk    Raw public key.
 */
export function encodePublicKeyDer(curve: CurveName, pk: Buffer): Buffer {
  const algorithm = encodeTlv(
    TAG.sequence,
    Buffer.concat([ID_EC_PUBLIC_KEY, encodeOid(CURVE_OIDS[curve])])
  );
  return encodeTlv(TAG.sequence, Buffer.concat([algorithm, encodeBitString(pk)]));
}

const INVALID_PRIVATE_KEY = 'Invalid DER encoding of ECPrivateKey';
const INVALID_PUBLIC_KEY = 'Invalid DER encoding of SubjectPublicKeyInfo';

/** Read a TLV of the expected tag at `start`, or fail with `error`. */
function expectTlv(
  buf: Buffer,
  start: number,
  tag: number,
  error: Error
): { tag: number; start: number; end: number } {
  let tlv;
  try {
    tlv = decodeTlv(buf, start);
  } catch {
    throw error;
  }
  if (tlv.tag !== tag) {
    throw error;
  }
  return tlv;
}

/** Read a named-curve OID TLV that must end within `limit`, and resolve it. */
function readCurveOid(
  buf: Buffer,
  start: number,
  limit: number,
  error: Error
): { curve: CurveName } {
  const { start: contentStart, end } = expectTlv(buf, start, TAG.oid, error);
  if (end > limit) {
    throw error;
  }
  const oid = decodeOid(buf, contentStart, end - contentStart);
  const curve = curveFromOid(oid);
  if (!curve) {
    throw new Error(`Unsupported elliptic curve OID: ${oid}`);
  }
  return { curve };
}

/**
 * Decode an `ECPrivateKey` (RFC 5915) DER buffer.
 *
 * The public key is present only when the encoding embeds it.
 */
export function decodePrivateKeyDer(buf: Buffer): KeyInfo {
  const error = new Error(INVALID_PRIVATE_KEY);
  const sequence = expectTlv(buf, 0, TAG.sequence, error);
  if (sequence.end !== buf.length) {
    throw error;
  }
  let pos = sequence.start;

  const version = expectTlv(buf, pos, TAG.integer, error);
  if (version.end - version.start !== 1 || buf[version.start] !== 1) {
    throw error;
  }
  pos = version.end;

  const privateKey = expectTlv(buf, pos, TAG.octetString, error);
  pos = privateKey.end;

  let curve: CurveName | undefined;
  let publicKey: Buffer | undefined;
  while (pos < sequence.end) {
    const tag = buf[pos];
    if (tag === TAG.context0) {
      const body = expectTlv(buf, pos, TAG.context0, error);
      curve = readCurveOid(buf, body.start, body.end, error).curve;
      pos = body.end;
    } else if (tag === TAG.context1) {
      const body = expectTlv(buf, pos, TAG.context1, error);
      const bitString = expectTlv(buf, body.start, TAG.bitString, error);
      // First content octet is the unused-bit count, always 0 for an EC point.
      publicKey = buf.subarray(bitString.start + 1, bitString.end);
      pos = body.end;
    } else {
      throw error;
    }
  }

  if (!curve) {
    throw new Error('ECPrivateKey without named-curve parameters is not supported');
  }
  const info: KeyInfo = {
    curveName: curve,
    privateKey: buf.subarray(privateKey.start, privateKey.end),
  };
  if (publicKey) {
    info.publicKey = publicKey;
  }
  return info;
}

/**
 * Decode a `SubjectPublicKeyInfo` (RFC 5480) DER buffer.
 *
 * Throws if the buffer holds a non-EC key or an unsupported curve.
 */
export function decodePublicKeyDer(buf: Buffer): KeyInfo {
  const error = new Error(INVALID_PUBLIC_KEY);
  const sequence = expectTlv(buf, 0, TAG.sequence, error);
  if (sequence.end !== buf.length) {
    throw error;
  }
  const algorithm = expectTlv(buf, sequence.start, TAG.sequence, error);

  const algorithmOid = expectTlv(buf, algorithm.start, TAG.oid, error);
  const oid = decodeOid(buf, algorithmOid.start, algorithmOid.end - algorithmOid.start);
  if (oid !== '1.2.840.10045.2.1') {
    throw new Error(`Not an EC public key (algorithm OID: ${oid})`);
  }
  const { curve } = readCurveOid(buf, algorithmOid.end, algorithm.end, error);

  const bitString = expectTlv(buf, algorithm.end, TAG.bitString, error);
  if (bitString.end !== sequence.end) {
    throw error;
  }
  return { curveName: curve, publicKey: buf.subarray(bitString.start + 1, bitString.end) };
}

/** Wrap DER content in a PEM block, base64 lines of 64 characters. */
export function toPem(tag: string, der: Buffer): string {
  const body = der.toString('base64').replace(/.{64}/g, '$&\n').replace(/\n$/, '');
  return `-----BEGIN ${tag}-----\n${body}\n-----END ${tag}-----`;
}

const PEM_BLOCK = /^\s*-----BEGIN ([A-Z0-9 ]+)-----\r?\n([\s\S]+?)\r?\n-----END \1-----\s*$/;

/**
 * Split a PEM block into its label and DER content.
 *
 * Accepts CRLF line endings and surrounding whitespace; whitespace inside the
 * base64 body is ignored by the decoder.
 */
export function fromPem(pem: string): { tag: string; der: Buffer } {
  const match = PEM_BLOCK.exec(pem);
  if (!match) {
    throw new Error('Invalid or unsupported PEM content');
  }
  return { tag: match[1], der: Buffer.from(match[2], 'base64') };
}

/** PEM labels this library reads and writes. */
export const PEM_LABELS = {
  /** RFC 5915 `ECPrivateKey`. */
  privateKey: 'EC PRIVATE KEY',
  /** RFC 5480 `SubjectPublicKeyInfo`. */
  publicKey: 'PUBLIC KEY',
} as const;
