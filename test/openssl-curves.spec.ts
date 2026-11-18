import { describe, expect, it, vi } from 'vitest';
import { generateRawKeyPair } from './helpers.js';

// A build without one of the curves, as some OpenSSL builds drop the binary ones.
const MISSING = 'sect283k1';
vi.mock('node:crypto', async (importOriginal) => {
    const actual = await importOriginal<typeof import('node:crypto')>();
    return { ...actual, getCurves: () => actual.getCurves().filter((c) => c !== MISSING) };
});

const { generatePem, parsePem } = await import('../src/index.js');

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
});
