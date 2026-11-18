import { describe, expect, it, vi } from 'vitest';
import { generateRawKeyPair } from './helpers.js';

// A build without some curves, as some OpenSSL builds drop the binary ones.
const { MISSING, MISSING_JWK } = vi.hoisted(() => ({
    MISSING: 'sect283k1',
    MISSING_JWK: 'secp256k1',
}));
vi.mock('node:crypto', async (importOriginal) => {
    const actual = await importOriginal<typeof import('node:crypto')>();
    const missing = new Set([MISSING, MISSING_JWK]);
    return { ...actual, getCurves: () => actual.getCurves().filter((c) => !missing.has(c)) };
});

const { generateJwk, generatePem, parsePem } = await import('../src/index.js');

describe('a curve the running OpenSSL lacks', () => {
    const { sk, pk } = generateRawKeyPair(MISSING);

    it('still encodes and parses keys, unchecked', () => {
        const pair = generatePem(MISSING, { sk, pk });
        expect(parsePem(pair.privateKey as string)).toEqual({
            curveName: MISSING,
            privateKey: sk,
            publicKey: pk,
        });
    });

    it('cannot expand a compressed point', () => {
        const compressed = Buffer.concat([Buffer.from([0x02]), pk.subarray(1, 37)]);
        expect(() => generatePem(MISSING, { pk: compressed })).toThrow(
            `Cannot decompress a point on ${MISSING}: the curve is not in this OpenSSL`
        );
    });

    it('cannot derive the public key of a private JWK', () => {
        const { sk } = generateRawKeyPair(MISSING_JWK);
        expect(() => generateJwk(MISSING_JWK, { sk })).toThrow(
            'Raw public key is required to build a private JWK'
        );
    });
});
