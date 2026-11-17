/**
 * DER and PEM encoding of EC keys:
 *
 * - `ECPrivateKey` (RFC 5915), wrapped as `-----BEGIN EC PRIVATE KEY-----`.
 * - `PrivateKeyInfo` (RFC 5958), wrapped as `-----BEGIN PRIVATE KEY-----`.
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
import { createPublicKey } from 'node:crypto';
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
 * @param curve          Curve the key belongs to.
 * @param sk             Raw private key.
 * @param pk             Raw public key, embedded when supplied.
 * @param withParameters Whether to include the `[0] namedCurve` element. PKCS#8
 *                       omits it, because the outer algorithm carries the curve.
 */
export function encodePrivateKeyDer(
    curve: CurveName,
    sk: Buffer,
    pk?: Buffer,
    withParameters = true
): Buffer {
    const parameters = withParameters
        ? encodeTlv(TAG.context0, encodeOid(CURVE_OIDS[curve]))
        : Buffer.alloc(0);
    const publicKey = pk
        ? encodeTlv(TAG.context1, encodeBitString(toUncompressedPoint(curve, pk)))
        : Buffer.alloc(0);
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
 * Encode a PKCS#8 `PrivateKeyInfo` (RFC 5958) around an `ECPrivateKey`.
 *
 * OpenSSL omits the inner `[0] namedCurve` here, so this is not a plain
 * re-wrap of {@link encodePrivateKeyDer}.
 */
export function encodePkcs8Der(curve: CurveName, sk: Buffer, pk?: Buffer): Buffer {
    const algorithm = encodeTlv(
        TAG.sequence,
        Buffer.concat([ID_EC_PUBLIC_KEY, encodeOid(CURVE_OIDS[curve])])
    );
    return encodeTlv(
        TAG.sequence,
        Buffer.concat([
            encodeSmallInteger(0), // PrivateKeyInfo version 0
            algorithm,
            encodeOctetString(encodePrivateKeyDer(curve, sk, pk, false)),
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
    return encodeSpki(curve, toUncompressedPoint(curve, pk));
}

/** `SubjectPublicKeyInfo` around `pk`, with no point normalisation. */
function encodeSpki(curve: CurveName, pk: Buffer): Buffer {
    const algorithm = encodeTlv(
        TAG.sequence,
        Buffer.concat([ID_EC_PUBLIC_KEY, encodeOid(CURVE_OIDS[curve])])
    );
    return encodeTlv(TAG.sequence, Buffer.concat([algorithm, encodeBitString(pk)]));
}

const POINT_PREFIX_ERROR = 'Public key must be an uncompressed (04) or compressed (02/03) EC point';

/**
 * Return `pk` as an uncompressed point (`04 || x || y`).
 *
 * A compressed point (SEC 1 v2 section 2.3.3, `02 || x` or `03 || x`) is
 * decompressed by OpenSSL through `node:crypto`, so the library carries no
 * field arithmetic of its own.
 */
export function toUncompressedPoint(curve: CurveName, pk: Buffer): Buffer {
    if (pk[0] === 0x04) {
        return pk;
    }
    if ((pk[0] !== 0x02 && pk[0] !== 0x03) || pk.length % 2 === 0) {
        throw new Error(POINT_PREFIX_ERROR);
    }
    try {
        const jwk = createPublicKey({
            key: encodeSpki(curve, pk),
            format: 'der',
            type: 'spki',
        }).export({ format: 'jwk' }) as { x: string; y: string };
        const coordinates = [jwk.x, jwk.y].map((value) =>
            Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
        );
        return Buffer.concat([Buffer.from([0x04]), ...coordinates]);
    } catch (error) {
        throw new Error(`Cannot decompress the public key point on ${curve}: ${String(error)}`, {
            cause: error,
        });
    }
}

const INVALID_PRIVATE_KEY = 'Invalid DER encoding of ECPrivateKey';
const INVALID_PKCS8 = 'Invalid DER encoding of PrivateKeyInfo';
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

interface Sec1Key {
    privateKey: Buffer;
    curveName?: CurveName | undefined;
    publicKey?: Buffer | undefined;
}

/**
 * Read an `ECPrivateKey` structure, tolerating the missing `[0] namedCurve`
 * that PKCS#8 uses.
 */
function parseSec1(buf: Buffer, error: Error): Sec1Key {
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

    const result: Sec1Key = { privateKey: buf.subarray(privateKey.start, privateKey.end) };
    while (pos < sequence.end) {
        const tag = buf[pos];
        if (tag === TAG.context0) {
            const body = expectTlv(buf, pos, TAG.context0, error);
            result.curveName = readCurveOid(buf, body.start, body.end, error).curve;
            pos = body.end;
        } else if (tag === TAG.context1) {
            const bits = readBitString(buf, pos, error);
            result.publicKey = bits.publicKey;
            pos = bits.next;
        } else {
            throw error;
        }
    }
    return result;
}

/** Read a `BIT STRING` wrapped in a `[1]` context tag, skipping unused bits. */
function readBitString(
    buf: Buffer,
    start: number,
    error: Error
): { publicKey: Buffer; next: number } {
    const body = expectTlv(buf, start, TAG.context1, error);
    const bitString = expectTlv(buf, body.start, TAG.bitString, error);
    // First content octet is the unused-bit count, always 0 for an EC point.
    return { publicKey: buf.subarray(bitString.start + 1, bitString.end), next: body.end };
}

/**
 * Decode an `ECPrivateKey` (RFC 5915) DER buffer.
 *
 * The public key is present only when the encoding embeds it.
 */
export function decodePrivateKeyDer(buf: Buffer): KeyInfo {
    const parsed = parseSec1(buf, new Error(INVALID_PRIVATE_KEY));
    if (!parsed.curveName) {
        throw new Error('ECPrivateKey without named-curve parameters is not supported');
    }
    const info: KeyInfo = { curveName: parsed.curveName, privateKey: parsed.privateKey };
    if (parsed.publicKey) {
        info.publicKey = toUncompressedPoint(parsed.curveName, parsed.publicKey);
    }
    return info;
}

/**
 * Decode a PKCS#8 `PrivateKeyInfo` (RFC 5958) or `OneAsymmetricKey` DER buffer.
 *
 * Throws if the buffer holds a non-EC key; the curve may come from either the
 * algorithm identifier or the inner `ECPrivateKey`, and must not disagree.
 */
export function decodePkcs8Der(buf: Buffer): KeyInfo {
    const error = new Error(INVALID_PKCS8);
    const sequence = expectTlv(buf, 0, TAG.sequence, error);
    if (sequence.end !== buf.length) {
        throw error;
    }

    const version = expectTlv(buf, sequence.start, TAG.integer, error);
    if (version.end - version.start !== 1 || buf[version.start] > 1) {
        throw error;
    }

    const algorithm = expectTlv(buf, version.end, TAG.sequence, error);
    const algorithmOid = expectTlv(buf, algorithm.start, TAG.oid, error);
    const oid = decodeOid(buf, algorithmOid.start, algorithmOid.end - algorithmOid.start);
    if (oid !== '1.2.840.10045.2.1') {
        throw new Error(`Not an EC private key (algorithm OID: ${oid})`);
    }
    const { curve: outerCurve } = readCurveOid(buf, algorithmOid.end, algorithm.end, error);

    const inner = expectTlv(buf, algorithm.end, TAG.octetString, error);
    const parsed = parseSec1(buf.subarray(inner.start, inner.end), error);

    // OneAsymmetricKey may carry attributes [0] and a public key [1] after the key.
    let pos = inner.end;
    let outerPublicKey: Buffer | undefined;
    while (pos < sequence.end) {
        if (buf[pos] === TAG.context0) {
            pos = expectTlv(buf, pos, TAG.context0, error).end;
        } else if (buf[pos] === TAG.context1) {
            const parsedBits = readBitString(buf, pos, error);
            outerPublicKey = parsedBits.publicKey;
            pos = parsedBits.next;
        } else {
            throw error;
        }
    }

    if (parsed.curveName && outerCurve && parsed.curveName !== outerCurve) {
        throw new Error(
            `Curve mismatch: PKCS#8 algorithm says ${outerCurve}, inner ECPrivateKey says ${parsed.curveName}`
        );
    }
    const curveName = parsed.curveName ?? outerCurve;
    const info: KeyInfo = { curveName, privateKey: parsed.privateKey };
    const publicKey = parsed.publicKey ?? outerPublicKey;
    if (publicKey) {
        info.publicKey = toUncompressedPoint(curveName, publicKey);
    }
    return info;
}

/**
 * Decode a private key DER buffer, either `ECPrivateKey` (RFC 5915) or
 * PKCS#8 `PrivateKeyInfo` (RFC 5958), told apart by their version number.
 */
export function decodeAnyPrivateKeyDer(buf: Buffer): KeyInfo {
    return isPkcs8(buf) ? decodePkcs8Der(buf) : decodePrivateKeyDer(buf);
}

/**
 * Both structures start with a SEQUENCE, an INTEGER version, then either the
 * algorithm SEQUENCE (PKCS#8) or the private key OCTET STRING (SEC1).
 */
function isPkcs8(buf: Buffer): boolean {
    try {
        const sequence = decodeTlv(buf, 0);
        if (sequence.tag !== TAG.sequence) {
            return false;
        }
        const version = decodeTlv(buf, sequence.start);
        if (version.tag !== TAG.integer || version.end - version.start !== 1) {
            return false;
        }
        const versionValue = buf[version.start];
        if (versionValue > 1) {
            return false;
        }
        try {
            return decodeTlv(buf, version.end).tag === TAG.sequence;
        } catch {
            // Truncated: only PKCS#8 can start with version 0.
            return versionValue === 0;
        }
    } catch {
        return false;
    }
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
    return {
        curveName: curve,
        publicKey: toUncompressedPoint(curve, buf.subarray(bitString.start + 1, bitString.end)),
    };
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
 * Accepts CRLF line endings, a byte order mark, an indented block and trailing
 * whitespace on any line; whitespace inside the base64 body is ignored by the
 * decoder either way.
 */
export function fromPem(pem: string): { tag: string; der: Buffer } {
    const normalized = pem.replace(/^\uFEFF/, '').replace(/^[ \t]+|[ \t]+$/gm, '');
    const match = PEM_BLOCK.exec(normalized);
    if (!match) {
        throw new Error('Invalid or unsupported PEM content');
    }
    if (/^(Proc-Type|DEK-Info):/m.test(match[2])) {
        throw new Error('Encrypted PEM is not supported');
    }
    return { tag: match[1], der: Buffer.from(match[2], 'base64') };
}

/** PEM labels this library reads and writes. */
export const PEM_LABELS = {
    /** RFC 5915 `ECPrivateKey`. */
    privateKey: 'EC PRIVATE KEY',
    /** RFC 5958 `PrivateKeyInfo`. */
    pkcs8: 'PRIVATE KEY',
    /** RFC 5480 `SubjectPublicKeyInfo`. */
    publicKey: 'PUBLIC KEY',
} as const;
