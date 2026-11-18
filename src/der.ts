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
import { createPrivateKey } from 'node:crypto';
import { curveFromOid, CURVE_OIDS, type CurveName } from './curves.js';
import { toUncompressedPoint } from './points.js';

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
    implicit1: 0x81,
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
    const algorithm = encodeTlv(
        TAG.sequence,
        Buffer.concat([ID_EC_PUBLIC_KEY, encodeOid(CURVE_OIDS[curve])])
    );
    return encodeTlv(
        TAG.sequence,
        Buffer.concat([algorithm, encodeBitString(toUncompressedPoint(curve, pk))])
    );
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

/** Read a named-curve OID TLV that must end exactly at `limit`, and resolve it. */
function readCurveOid(
    buf: Buffer,
    start: number,
    limit: number,
    error: Error
): { curve: CurveName } {
    const { start: contentStart, end } = expectTlv(buf, start, TAG.oid, error);
    if (end !== limit) {
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

/**
 * Read the content of a BIT STRING TLV (or one implicitly retagged as `tag`)
 * holding an EC point: the leading unused-bit count must be 0.
 */
function readPointBits(
    buf: Buffer,
    start: number,
    tag: number,
    error: Error
): { publicKey: Buffer; end: number } {
    const bits = expectTlv(buf, start, tag, error);
    if (bits.end - bits.start < 2 || buf[bits.start] !== 0) {
        throw error;
    }
    return { publicKey: buf.subarray(bits.start + 1, bits.end), end: bits.end };
}

/** Read the `[1] EXPLICIT BIT STRING` public key of an `ECPrivateKey` (RFC 5915). */
function readBitString(
    buf: Buffer,
    start: number,
    error: Error
): { publicKey: Buffer; next: number } {
    const body = expectTlv(buf, start, TAG.context1, error);
    const bits = readPointBits(buf, body.start, TAG.bitString, error);
    if (bits.end !== body.end) {
        throw error;
    }
    return { publicKey: bits.publicKey, next: body.end };
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

    // OneAsymmetricKey (RFC 5958) may carry attributes `[0] IMPLICIT SET` and
    // a public key `[1] IMPLICIT BIT STRING` after the key.
    let pos = inner.end;
    let outerPublicKey: Buffer | undefined;
    while (pos < sequence.end) {
        if (buf[pos] === TAG.context0) {
            pos = expectTlv(buf, pos, TAG.context0, error).end;
        } else if (buf[pos] === TAG.implicit1) {
            const bits = readPointBits(buf, pos, TAG.implicit1, error);
            outerPublicKey = bits.publicKey;
            pos = bits.end;
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

    const bits = readPointBits(buf, algorithm.end, TAG.bitString, error);
    if (bits.end !== sequence.end) {
        throw error;
    }
    return { curveName: curve, publicKey: toUncompressedPoint(curve, bits.publicKey) };
}

/** Wrap DER content in a PEM block, base64 lines of 64 characters. */
export function toPem(tag: string, der: Buffer): string {
    const body = der.toString('base64').replace(/.{64}/g, '$&\n').replace(/\n$/, '');
    return `-----BEGIN ${tag}-----\n${body}\n-----END ${tag}-----`;
}

const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----\r?\n([\s\S]+?)\r?\n-----END \1-----/g;

/** Label of the curve block `openssl ecparam -genkey` writes ahead of the key. */
const EC_PARAMETERS = 'EC PARAMETERS';

/**
 * Whether a PEM string holds an encrypted private key.
 *
 * Covers both containers: PKCS#8 `ENCRYPTED PRIVATE KEY` and the legacy
 * `EC PRIVATE KEY` block with `Proc-Type: 4,ENCRYPTED` headers.
 */
export function isEncryptedPem(pem: string): boolean {
    return (
        /-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem) ||
        /^Proc-Type:\s*4,\s*ENCRYPTED/m.test(pem)
    );
}

/**
 * The structure a DER buffer starting with a SEQUENCE of an AlgorithmIdentifier
 * holds: PKCS#8 `EncryptedPrivateKeyInfo` follows it with an OCTET STRING,
 * `SubjectPublicKeyInfo` with a BIT STRING. SEC1 and plain PKCS#8 start with a
 * version INTEGER instead, and are `undefined` here.
 */
export function algorithmFirstStructure(der: Buffer): 'encrypted' | 'spki' | undefined {
    try {
        const sequence = decodeTlv(der, 0);
        const algorithm = decodeTlv(der, sequence.start);
        if (sequence.tag !== TAG.sequence || algorithm.tag !== TAG.sequence) {
            return undefined;
        }
        const next = decodeTlv(der, algorithm.end).tag;
        return next === TAG.octetString ? 'encrypted' : next === TAG.bitString ? 'spki' : undefined;
    } catch {
        return undefined;
    }
}

/**
 * Decrypt an encrypted private key with OpenSSL and return its SEC1 DER.
 *
 * The library never implements PBES2 itself: the passphrase goes to
 * `crypto.createPrivateKey`, and only the decrypted, unencrypted encoding is
 * parsed here.
 */
export function decryptPrivateKey(
    input: string | Buffer,
    format: 'pem' | 'der',
    passphrase: string | Buffer
): Buffer {
    try {
        // DER carries no label, so the type has to be stated; encrypted DER is
        // always PKCS#8 EncryptedPrivateKeyInfo.
        const key =
            format === 'der'
                ? createPrivateKey({
                      key: input as Buffer,
                      format: 'der',
                      type: 'pkcs8',
                      passphrase,
                  })
                : createPrivateKey({ key: input as string, format: 'pem', passphrase });
        return key.export({ format: 'der', type: 'sec1' }) as Buffer;
    } catch (error) {
        throw new Error(`Cannot decrypt the private key: ${String(error)}`, { cause: error });
    }
}

/**
 * Encrypt a private key with OpenSSL.
 *
 * Parameters follow OpenSSL's own defaults, so the result is interchangeable
 * with `openssl pkcs8 -topk8 -v2 aes-256-cbc`: PKCS#8 `PBES2`, `PBKDF2` with a
 * 16-byte salt, 2048 iterations and hmacWithSHA256, then the given cipher.
 * `sec1` is the legacy `Proc-Type: 4,ENCRYPTED` container, which OpenSSL still
 * writes for `openssl ec -aes256`.
 */
export function encryptPrivateKey(
    der: Buffer,
    options: {
        container: 'sec1' | 'pkcs8';
        format: 'pem' | 'der';
        cipher: string;
        passphrase: string | Buffer;
    }
): string | Buffer {
    const { container, format, cipher, passphrase } = options;
    try {
        const key = createPrivateKey({ key: der, format: 'der', type: container });
        return key.export({ format, type: container, cipher, passphrase });
    } catch (error) {
        throw new Error(`Cannot encrypt the private key: ${String(error)}`, { cause: error });
    }
}

/**
 * Find the key block in PEM content and split it into its label and DER.
 *
 * Accepts CRLF line endings, a byte order mark, an indented block and trailing
 * whitespace on any line; whitespace inside the base64 body is ignored by the
 * decoder either way. Text outside the block is ignored (RFC 7468 section 2),
 * and so is the `EC PARAMETERS` block that `openssl ecparam -genkey` writes
 * before the key. More than one key block is refused rather than guessed at.
 *
 * @returns the label, the decoded body, and the block's own text.
 */
export function fromPem(pem: string): { tag: string; der: Buffer; text: string } {
    const normalized = pem.replace(/^\uFEFF/, '').replace(/^[ \t]+|[ \t]+$/gm, '');
    const blocks = [...normalized.matchAll(PEM_BLOCK)];
    const keys = blocks.filter((block) => block[1] !== EC_PARAMETERS);
    const candidates = keys.length > 0 ? keys : blocks;
    if (candidates.length === 0) {
        throw new Error('Invalid or unsupported PEM content');
    }
    if (candidates.length > 1) {
        const labels = candidates.map((block) => block[1]).join(', ');
        throw new Error(
            `PEM content holds ${candidates.length} blocks (${labels}); expected one key`
        );
    }
    const [text, tag, body] = candidates[0];
    return { tag, der: Buffer.from(body, 'base64'), text };
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
