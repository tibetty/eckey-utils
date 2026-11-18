/**
 * JWK (RFC 8037) encoding of Ed25519 and Ed448 keys.
 *
 * OKP keys are not EC points: `x` is the raw 32 or 57-byte public key and `d`
 * the raw private seed, so nothing is shared with the EC encoding beyond the
 * base64url helpers and the shape of the key pair.
 */
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { jwkThumbprint } from './thumbprint.js';

/** Curves with an OKP JWK representation, and their raw key size in bytes. */
export const OKP_CURVES = { Ed25519: 32, Ed448: 57 } as const;

/** A curve name accepted by the OKP JWK functions. */
export type OkpCurveName = keyof typeof OKP_CURVES;

/** An OKP JSON Web Key. `x` is always present; `d` marks a private key. */
export interface OkpJsonWebKey {
    kty: 'OKP';
    crv: OkpCurveName;
    /** Raw public key, base64url encoded. */
    x: string;
    /** Raw private key (seed), base64url encoded. Present on private JWKs only. */
    d?: string | undefined;
    key_ops?: string[] | undefined;
    kid?: string | undefined;
}

/** Public/private OKP JWK pair. */
export interface OkpKeyPair {
    privateKey?: OkpJsonWebKey | undefined;
    publicKey?: OkpJsonWebKey | undefined;
}

/** Raw key material recovered from an OKP JWK. */
export interface OkpKeyInfo {
    /** `Ed25519` or `Ed448`. */
    curveName: OkpCurveName;
    /** Raw private key (seed), when the JWK carried `d`. */
    privateKey?: Buffer | undefined;
    /** Raw public key. */
    publicKey?: Buffer | undefined;
}

const OKP_CURVE_ERROR = 'OKP JWK supports only Ed25519 and Ed448';

/** Whether `curve` names an OKP curve rather than an EC one. */
export function isOkpCurveName(curve: unknown): curve is OkpCurveName {
    return typeof curve === 'string' && Object.hasOwn(OKP_CURVES, curve);
}

function checkLength(curve: OkpCurveName, key: Buffer, kind: 'Private' | 'Public'): void {
    const expected = OKP_CURVES[curve];
    if (key.length !== expected) {
        throw new Error(
            `${kind} key length ${key.length} does not match curve ${curve} (expected ${expected})`
        );
    }
}

/** PKCS#8 `PrivateKeyInfo` header in front of a raw Ed25519 or Ed448 seed (RFC 8410). */
const PKCS8_PREFIX: Readonly<Record<OkpCurveName, string>> = {
    Ed25519: '302e020100300506032b657004220420',
    Ed448: '3047020100300506032b6571043b0439',
};

/** Derive the raw public key of an Ed25519 or Ed448 seed through OpenSSL. */
function deriveOkpPublicKey(curve: OkpCurveName, privateKey: Buffer): Buffer {
    const key = createPrivateKey({
        key: Buffer.concat([Buffer.from(PKCS8_PREFIX[curve], 'hex'), privateKey]),
        format: 'der',
        type: 'pkcs8',
    });
    const spki = createPublicKey(key).export({ format: 'der', type: 'spki' });
    return spki.subarray(spki.length - OKP_CURVES[curve]);
}

/**
 * Build OKP JWKs from raw keys.
 *
 * RFC 8037 requires `x` next to `d`; it is derived from the private key when
 * not given, and checked against it when it is. `kid` is the RFC 7638
 * thumbprint, shared by both halves of the pair.
 */
export function encodeOkpJwk(
    curve: OkpCurveName,
    privateKey?: Buffer,
    publicKey?: Buffer
): OkpKeyPair {
    if (publicKey) {
        checkLength(curve, publicKey, 'Public');
    }
    if (privateKey) {
        checkLength(curve, privateKey, 'Private');
        const derived = deriveOkpPublicKey(curve, privateKey);
        if (publicKey && !derived.equals(publicKey)) {
            throw new Error(`Public key does not match the private key on ${curve}`);
        }
        publicKey = derived;
    }

    const x = (publicKey as Buffer).toString('base64url');
    const kid = jwkThumbprint({ crv: curve, kty: 'OKP', x });
    const result: OkpKeyPair = {};

    if (privateKey) {
        result.privateKey = {
            kty: 'OKP',
            crv: curve,
            key_ops: ['sign'],
            kid,
            x,
            d: privateKey.toString('base64url'),
        };
    }
    result.publicKey = { kty: 'OKP', crv: curve, key_ops: ['verify'], kid, x };
    return result;
}

/** Rebuild raw key material from an OKP JWK. */
export function decodeOkpJwk(jwk: OkpJsonWebKey): OkpKeyInfo {
    if (!isOkpCurveName(jwk.crv)) {
        throw new Error(OKP_CURVE_ERROR);
    }
    if (typeof jwk.x !== 'string') {
        throw new Error('OKP JSON Web Key requires "x"');
    }

    const publicKey = Buffer.from(jwk.x, 'base64url');
    checkLength(jwk.crv, publicKey, 'Public');
    const info: OkpKeyInfo = { curveName: jwk.crv, publicKey };

    if (typeof jwk.d === 'string') {
        const privateKey = Buffer.from(jwk.d, 'base64url');
        checkLength(jwk.crv, privateKey, 'Private');
        info.privateKey = privateKey;
    }
    return info;
}
