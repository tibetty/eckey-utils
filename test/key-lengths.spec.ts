import { describe, expect, it } from 'vitest';
import { createPrivateKey } from 'node:crypto';
import {
    CURVE_KEY_BYTES,
    CURVE_NAMES,
    CURVE_PRIVATE_KEY_BYTES,
    generateDer,
    generateJwk,
    generatePem,
    parsePem,
} from '../src/index.js';
import {
    defined,
    generateRawKeyPair,
    generateShortKeyPair,
    opensslPrivateKeyWidth,
} from './helpers.js';

const COORDINATE_SIZES = new Map([
    ['prime256v1', 32],
    ['secp521r1', 66],
    ['secp112r1', 14],
    ['sect233k1', 30],
    ['c2pnb163v1', 21],
    ['brainpoolP512t1', 64],
]);

describe('curve key sizes', () => {
    it('covers every supported curve exactly once', () => {
        expect(Object.keys(CURVE_KEY_BYTES).sort()).toEqual([...CURVE_NAMES].sort());
    });

    it.each([...COORDINATE_SIZES])('%s is %i bytes', (curve, bytes) => {
        expect(CURVE_KEY_BYTES[curve as keyof typeof CURVE_KEY_BYTES]).toBe(bytes);
    });
});

describe.each(CURVE_NAMES)('key length validation on %s', (curve) => {
    const { sk, pk } = generateRawKeyPair(curve);
    const keyBytes = CURVE_KEY_BYTES[curve];

    it('accepts keys of the right size', () => {
        expect(pk).toHaveLength(1 + 2 * keyBytes);
        expect(generatePem(curve, { sk, pk }).privateKey).toBeDefined();
        expect(generateDer(curve, { pk }).publicKey).toBeDefined();
    });

    it('sizes private keys the way OpenSSL does', () => {
        expect(CURVE_PRIVATE_KEY_BYTES[curve]).toBe(opensslPrivateKeyWidth(curve));
    });

    it('rejects a private key that is too long for the curve', () => {
        const width = CURVE_PRIVATE_KEY_BYTES[curve];
        const tooLong = Buffer.alloc(width + 1, 0x01);
        expect(() => generatePem(curve, { sk: tooLong })).toThrow(
            `Private key length ${tooLong.length} does not match curve ${curve} (expected 1 to ${width})`
        );
    });

    it('writes a key with a stripped leading zero exactly as OpenSSL does', () => {
        const short = generateShortKeyPair(curve);
        const pem = defined(generatePem(curve, short).privateKey);
        const reference = createPrivateKey(pem).export({ format: 'pem', type: 'sec1' });
        expect(pem).toBe(reference.toString().trimEnd());
        expect(parsePem(pem).privateKey).toHaveLength(CURVE_PRIVATE_KEY_BYTES[curve]);
    });

    it('reads back an OpenSSL key and writes it again', () => {
        const pem = createPrivateKey(
            defined(generatePem(curve, generateRawKeyPair(curve)).privateKey)
        )
            .export({ format: 'pem', type: 'sec1' })
            .toString();
        const info = parsePem(pem);
        expect(generatePem(curve, { sk: info.privateKey, pk: info.publicKey }).privateKey).toBe(
            pem.trimEnd()
        );
    });

    it('rejects a public key of the wrong length', () => {
        expect(() => generateDer(curve, { pk: pk.subarray(0, pk.length - 1) })).toThrow(
            `Public key length ${pk.length - 1} does not match curve ${curve} ` +
                `(expected ${1 + 2 * keyBytes} for an uncompressed point, ${1 + keyBytes} for a compressed one)`
        );
    });

    it('rejects another key of another curve', () => {
        const otherCurve = curve === 'prime256v1' ? 'secp384r1' : 'prime256v1';
        const other = generateRawKeyPair(otherCurve);
        if (other.pk.length === pk.length) {
            // The two curves share a coordinate width, so only the point check can tell.
            expect(() => generatePem(curve, { pk: other.pk })).toThrow(
                `Public key is not a point on ${curve}`
            );
            return;
        }
        expect(() => generatePem(curve, { pk: other.pk })).toThrow(/does not match curve/);
    });
});

describe('length validation reporting', () => {
    it('names both the curve and the sizes', () => {
        const { pk } = generateRawKeyPair('prime256v1');
        expect(() => generatePem('sect233k1', { pk })).toThrow(
            'Public key length 65 does not match curve sect233k1 ' +
                '(expected 61 for an uncompressed point, 31 for a compressed one)'
        );
        expect(() => generatePem('prime256v1', { sk: Buffer.alloc(33) })).toThrow(
            'Private key length 33 does not match curve prime256v1 (expected 1 to 32)'
        );
        expect(() => generatePem('prime256v1', { sk: Buffer.alloc(0) })).toThrow(
            'Private key length 0 does not match curve prime256v1 (expected 1 to 32)'
        );
    });

    it('pads a short private key to the full width in a JWK, as RFC 7518 requires', () => {
        const short = generateShortKeyPair('prime256v1');
        const jwk = defined(generateJwk('prime256v1', short).privateKey);
        expect(Buffer.from(defined(jwk.d), 'base64url')).toHaveLength(32);
    });

    it('accepts a private key shorter than the coordinate size', () => {
        const { sk } = generateRawKeyPair('prime256v1');
        const shorter = sk.subarray(1); // leading zero byte stripped
        expect(() => generatePem('prime256v1', { sk: shorter })).not.toThrow();
    });
});
