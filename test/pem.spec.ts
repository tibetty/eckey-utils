import { createSign, createVerify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
    CURVE_NAMES,
    generateDer,
    generatePem,
    parsePem,
    parsePkDer,
    parseSkDer,
} from '../src/index.js';
import { defined, generateRawKeyPair } from './helpers.js';

const MESSAGE = Buffer.from('Hello, World!');

describe.each(CURVE_NAMES)('curve %s', (curve) => {
    const { sk, pk } = generateRawKeyPair(curve);

    it('round-trips raw keys through a private key PEM', () => {
        const { privateKey } = generatePem(curve, { sk, pk });
        const info = parsePem(defined(privateKey));

        expect(info.curveName).toBe(curve);
        expect(info.privateKey).toEqual(sk);
        expect(info.publicKey).toEqual(pk);
    });

    it('round-trips raw keys through a public key PEM', () => {
        const { publicKey } = generatePem(curve, { pk });
        const info = parsePem(defined(publicKey));

        expect(info.curveName).toBe(curve);
        expect(info.publicKey).toEqual(pk);
        expect(info.privateKey).toBeUndefined();
    });

    it('round-trips raw keys through DER', () => {
        const der = generateDer(curve, { sk, pk });

        expect(parseSkDer(defined(der.privateKey))).toEqual({
            curveName: curve,
            privateKey: sk,
            publicKey: pk,
        });
        expect(parsePkDer(defined(der.publicKey))).toEqual({ curveName: curve, publicKey: pk });
    });

    it('produces a PEM pair that crypto.sign and crypto.verify accept', () => {
        const { privateKey, publicKey } = generatePem(curve, { sk, pk });

        const signer = createSign('sha256');
        signer.update(MESSAGE);
        const signature = signer.sign(defined(privateKey));

        const verifier = createVerify('sha256');
        verifier.update(MESSAGE);
        expect(verifier.verify(defined(publicKey), signature)).toBe(true);
    });
});

describe('PEM layout', () => {
    const { sk, pk } = generateRawKeyPair('prime256v1');

    it('wraps the private key in an EC PRIVATE KEY block of 64-character lines', () => {
        const { privateKey } = generatePem('prime256v1', { sk, pk });
        expect(privateKey).toMatch(/^-----BEGIN EC PRIVATE KEY-----\n/);
        expect(privateKey).toMatch(/\n-----END EC PRIVATE KEY-----$/);
        const lines = defined(privateKey).split('\n');
        expect(lines.slice(1, -1).every((line) => line.length <= 64)).toBe(true);
        expect(lines.slice(1, -2).every((line) => line.length === 64)).toBe(true);
    });

    it('wraps the public key in a PUBLIC KEY block', () => {
        const { publicKey } = generatePem('prime256v1', { pk });
        expect(publicKey).toMatch(
            /^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----$/
        );
    });
});
