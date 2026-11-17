import { createPrivateKey, createPublicKey, createSign, createVerify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
    ANSI_CURVES,
    CURVE_KEY_BYTES,
    CURVE_NAMES,
    generateDer,
    generateJwk,
    generatePem,
    parseJwk,
    parsePem,
    parsePkDer,
    parseSkDer,
} from '../src/index.js';
import type { CurveName } from '../src/index.js';
import { defined, generateRawKeyPair } from './helpers.js';

const MESSAGE = Buffer.from('corpus');
const KEY_TYPES = ['sec1', 'pkcs8'] as const;

/**
 * Every supported curve, through every encoding. The named tests elsewhere use a
 * handful of curves to keep the output readable; this one is the regression net
 * for the other 75, including the long lengths that only show up above 127 and
 * 255 bytes.
 */
describe.each(CURVE_NAMES)('corpus: %s', (curve) => {
    const { sk, pk } = generateRawKeyPair(curve);

    it('round-trips both private key encodings', () => {
        for (const type of KEY_TYPES) {
            const pem = defined(generatePem(curve, { sk, pk }, { type }).privateKey);
            expect(parsePem(pem)).toEqual({ curveName: curve, privateKey: sk, publicKey: pk });

            const der = defined(generateDer(curve, { sk, pk }, { type }).privateKey);
            expect(parseSkDer(der)).toEqual({ curveName: curve, privateKey: sk, publicKey: pk });
        }
    });

    it('round-trips the public key', () => {
        const pem = defined(generatePem(curve, { pk }).publicKey);
        expect(parsePem(pem)).toEqual({ curveName: curve, publicKey: pk });
        expect(parsePkDer(defined(generateDer(curve, { pk }).publicKey))).toEqual({
            curveName: curve,
            publicKey: pk,
        });
    });

    it('produces keys OpenSSL accepts', () => {
        const sec1 = createPrivateKey(defined(generatePem(curve, { sk, pk }).privateKey));
        const pkcs8 = createPrivateKey(
            defined(generatePem(curve, { sk, pk }, { type: 'pkcs8' }).privateKey)
        );
        const spki = createPublicKey(defined(generatePem(curve, { pk }).publicKey));

        for (const key of [sec1, pkcs8, spki]) {
            expect(key.asymmetricKeyType).toBe('ec');
            expect(key.asymmetricKeyDetails?.namedCurve).toBe(curve);
        }
    });

    it('signs and verifies through the generated PEM', () => {
        const { privateKey, publicKey } = generatePem(curve, { sk, pk });
        const signature = createSign('sha256').update(MESSAGE).sign(defined(privateKey));

        expect(createVerify('sha256').update(MESSAGE).verify(defined(publicKey), signature)).toBe(
            true
        );
    });

    it('re-encodes to identical bytes after parsing', () => {
        for (const type of KEY_TYPES) {
            const pem = defined(generatePem(curve, { sk, pk }, { type }).privateKey);
            const info = parsePem(pem);
            expect(
                generatePem(curve, { sk: defined(info.privateKey), pk: info.publicKey }, { type })
                    .privateKey
            ).toBe(pem);
        }
        const publicPem = defined(generatePem(curve, { pk }).publicKey);
        expect(generatePem(curve, { pk }).publicKey).toBe(publicPem);
    });

    it('measures keys the way CURVE_KEY_BYTES says', () => {
        expect(sk.length).toBeLessThanOrEqual(CURVE_KEY_BYTES[curve]);
        expect(pk).toHaveLength(1 + 2 * CURVE_KEY_BYTES[curve]);
    });
});

describe('corpus: JWK curves', () => {
    // Curves with a registered JWK crv value; the rest are PEM/DER only. Taken
    // from the table so a curve added there is covered without touching the test.
    const curves = Object.values(ANSI_CURVES).map((curve) => curve as CurveName);

    it.each(curves)('round-trips %s through a private JWK and back to PEM', (curve) => {
        const { sk, pk } = generateRawKeyPair(curve);
        const jwk = defined(generateJwk(curve, { sk, pk }).privateKey);
        const info = parseJwk(jwk);

        expect(info).toEqual({ curveName: curve, privateKey: sk, publicKey: pk });
        expect(generatePem(curve, { sk, pk }).privateKey).toBe(
            generatePem(curve, { sk: defined(info.privateKey), pk: info.publicKey }).privateKey
        );
    });

    it.each(curves)('survives a JSON round trip for %s', (curve) => {
        const { sk, pk } = generateRawKeyPair(curve);
        const jwk = defined(generateJwk(curve, { sk, pk }).privateKey);
        const revived = JSON.parse(JSON.stringify(jwk));
        expect(parseJwk(revived)).toEqual({ curveName: curve, privateKey: sk, publicKey: pk });
    });
});

describe('corpus: largest and smallest curves', () => {
    it('handles long-form lengths for the largest curve', () => {
        // sect571r1: a 145-byte point, so SEC1 and PKCS#8 both need long-form lengths.
        const { sk, pk } = generateRawKeyPair('sect571r1');
        const sec1 = defined(generateDer('sect571r1', { sk, pk }).privateKey);
        const pkcs8 = defined(generateDer('sect571r1', { sk, pk }, { type: 'pkcs8' }).privateKey);

        expect(sec1[1] & 0x80).toBe(0x80);
        expect(pkcs8[1] & 0x80).toBe(0x80);
        expect(parseSkDer(sec1)).toEqual({ curveName: 'sect571r1', privateKey: sk, publicKey: pk });
        expect(parseSkDer(pkcs8)).toEqual({
            curveName: 'sect571r1',
            privateKey: sk,
            publicKey: pk,
        });
        expect(generateDer('sect571r1', { sk, pk }).privateKey).toEqual(sec1);
    });

    it('handles the smallest curve', () => {
        const { sk, pk } = generateRawKeyPair('secp112r1');
        const info = parsePem(defined(generatePem('secp112r1', { sk, pk }).privateKey));

        expect(info.privateKey).toHaveLength(14);
        expect(info.publicKey).toHaveLength(29);
    });
});
