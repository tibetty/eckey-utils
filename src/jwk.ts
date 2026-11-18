/**
 * JWK (RFC 7517 / RFC 7518) encoding of EC keys.
 *
 * Covers the curves with a registered JWK `crv` value: `P-256`, `P-384` and
 * `P-521` (RFC 7518) plus `secp256k1` (RFC 8812).
 */
import {
    ANSI_CURVES,
    CURVE_KEY_BYTES,
    CURVE_PRIVATE_KEY_BYTES,
    CURVE_TO_ANSI,
    padPrivateKey,
    type AnsiCurveName,
    type CurveName,
} from './curves.js';
import { jwkThumbprint } from './thumbprint.js';
import type { KeyInfo } from './der.js';
import { toUncompressedPoint } from './points.js';

/** An EC JSON Web Key. `x`/`y` are always present; `d` marks a private key. */
export interface EcJsonWebKey {
    kty: 'EC';
    crv: AnsiCurveName;
    x: string;
    y: string;
    /** Raw private key, base64url encoded. Present on private JWKs only. */
    d?: string | undefined;
    key_ops?: string[] | undefined;
    kid?: string | undefined;
}

/** Public/private JWK pair produced by {@link encodeJwk}. */
export interface JwkKeyPair {
    privateKey?: EcJsonWebKey | undefined;
    publicKey?: EcJsonWebKey | undefined;
}

const JWK_CURVES = Object.keys(ANSI_CURVES).join(', ');
const JWK_CURVE_ERROR = `JWK supports only ${JWK_CURVES}`;

/** Split a raw uncompressed EC point into its affine coordinates. */
function splitPoint(publicKey: Buffer): { x: Buffer; y: Buffer } {
    const half = (publicKey.length - 1) / 2;
    return { x: publicKey.subarray(1, half + 1), y: publicKey.subarray(half + 1) };
}

/** The JWK `crv` value of `curve`, or an error naming the curves JWK supports. */
export function jwkCurve(curve: CurveName): AnsiCurveName {
    const crv = CURVE_TO_ANSI[curve];
    if (!crv) {
        throw new Error(JWK_CURVE_ERROR);
    }
    return crv;
}

/**
 * Build JWKs from raw key material.
 *
 * RFC 7518 requires `x` and `y` alongside `d`, so the public key must be given
 * with a private key, or derived from it by the caller. `kid` is the RFC 7638
 * thumbprint, shared by both halves of the pair.
 */
export function encodeJwk(curve: CurveName, privateKey?: Buffer, publicKey?: Buffer): JwkKeyPair {
    const crv = jwkCurve(curve);
    if (!publicKey) {
        throw new Error('Raw public key is required to build a private JWK');
    }

    const point = splitPoint(toUncompressedPoint(curve, publicKey));
    const x = point.x.toString('base64url');
    const y = point.y.toString('base64url');
    const kid = jwkThumbprint({ crv, kty: 'EC', x, y });
    const result: JwkKeyPair = {};

    if (privateKey) {
        result.privateKey = {
            kty: 'EC',
            crv,
            key_ops: ['deriveBits', 'deriveKey', 'sign'],
            kid,
            x,
            y,
            d: privateKey.toString('base64url'),
        };
    }
    result.publicKey = { kty: 'EC', crv, key_ops: ['verify'], kid, x, y };
    return result;
}

/** Rebuild raw key material from an EC JWK. */
export function decodeJwk(jwk: EcJsonWebKey): KeyInfo {
    if (!jwk || jwk.kty !== 'EC') {
        throw new Error('Not an EC JSON Web Key');
    }
    const curve: CurveName | undefined = Object.hasOwn(ANSI_CURVES, String(jwk.crv))
        ? ANSI_CURVES[jwk.crv as AnsiCurveName]
        : undefined;
    if (!curve) {
        throw new Error(JWK_CURVE_ERROR);
    }
    if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
        throw new Error('EC JSON Web Key requires both "x" and "y"');
    }

    const keyBytes = CURVE_KEY_BYTES[curve];
    const [x, y] = [jwk.x, jwk.y].map((value) => Buffer.from(value, 'base64url'));
    if (x.length !== keyBytes || y.length !== keyBytes) {
        const lengths = x.length === y.length ? `${x.length}` : `${x.length} and ${y.length}`;
        throw new Error(
            `Coordinate length ${lengths} does not match curve ${curve} (expected ${keyBytes} each)`
        );
    }

    const info: KeyInfo = {
        curveName: curve,
        publicKey: Buffer.concat([Buffer.from([0x04]), x, y]),
    };
    if (typeof jwk.d === 'string') {
        const privateKey = Buffer.from(jwk.d, 'base64url');
        if (privateKey.length === 0) {
            throw new Error('EC JSON Web Key has an empty "d"');
        }
        const privateKeyBytes = CURVE_PRIVATE_KEY_BYTES[curve];
        if (privateKey.length > privateKeyBytes) {
            throw new Error(
                `Private key length ${privateKey.length} does not match curve ${curve} (expected at most ${privateKeyBytes})`
            );
        }
        // Earlier releases wrote `d` without its leading zero bytes; read those too.
        info.privateKey = padPrivateKey(curve, privateKey);
    }
    return info;
}
