/**
 * EC point and private key checks, delegated to OpenSSL through `node:crypto`
 * so the library carries no field arithmetic of its own.
 */
import { createECDH, ECDH, getCurves } from 'node:crypto';
import type { CurveName } from './curves.js';

let opensslCurves: ReadonlySet<string> | undefined;

/**
 * Whether the running OpenSSL implements `curve`. Builds differ: some drop the
 * binary curves, for instance, and such a curve can still be encoded, only not
 * checked.
 */
function isOpensslCurve(curve: CurveName): boolean {
    opensslCurves ??= new Set(getCurves());
    return opensslCurves.has(curve);
}

const POINT_PREFIX_ERROR = 'Public key must be an uncompressed (04) or compressed (02/03) EC point';

/**
 * Return `pk` as an uncompressed point (`04 || x || y`), after checking that it
 * lies on the curve.
 *
 * A compressed point (SEC 1 v2 section 2.3.3, `02 || x` or `03 || x`) is
 * expanded. On a curve the running OpenSSL lacks, an uncompressed point passes
 * through unchecked and a compressed one cannot be expanded.
 */
export function toUncompressedPoint(curve: CurveName, pk: Buffer): Buffer {
    const prefix = pk[0];
    if (prefix !== 0x02 && prefix !== 0x03 && prefix !== 0x04) {
        throw new Error(POINT_PREFIX_ERROR);
    }
    if (!isOpensslCurve(curve)) {
        if (prefix === 0x04) {
            return pk;
        }
        throw new Error(`Cannot decompress a point on ${curve}: the curve is not in this OpenSSL`);
    }
    try {
        return ECDH.convertKey(pk, curve, undefined, undefined, 'uncompressed') as Buffer;
    } catch (error) {
        throw new Error(`Public key is not a point on ${curve}`, { cause: error });
    }
}

/**
 * Check that `sk` is a valid private key on `curve` (from 1 to the order minus
 * one) and return its public key, or `undefined` when the running OpenSSL
 * lacks the curve.
 */
export function derivePublicKey(curve: CurveName, sk: Buffer): Buffer | undefined {
    if (!isOpensslCurve(curve)) {
        return undefined;
    }
    const ecdh = createECDH(curve);
    try {
        ecdh.setPrivateKey(sk);
    } catch (error) {
        throw new Error(`Private key is out of range for curve ${curve}`, { cause: error });
    }
    return ecdh.getPublicKey();
}
