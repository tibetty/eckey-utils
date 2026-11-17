import { createPrivateKey, createPublicKey, createSign, createVerify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { generateJwk, parseJwk, type EcJsonWebKey } from '../src/index.js';
import { defined, generateRawKeyPair } from './helpers.js';

const MESSAGE = Buffer.from('Hello, World!');

/** Node types `d` as required on an EC JWK; ours is optional by design. */
const toNodeKey = (jwk: EcJsonWebKey) => ({ key: jwk, format: 'jwk' }) as unknown;
const privateKeyInput = toNodeKey as (jwk: EcJsonWebKey) => Parameters<typeof createPrivateKey>[0];
const publicKeyInput = toNodeKey as (jwk: EcJsonWebKey) => Parameters<typeof createPublicKey>[0];
const JWK_CURVE_CASES = [
    ['prime256v1', 'P-256'],
    ['secp384r1', 'P-384'],
    ['secp521r1', 'P-521'],
    ['secp256k1', 'secp256k1'],
] as const;

describe.each(JWK_CURVE_CASES)('curve %s', (curve, ansiName) => {
    const { sk, pk } = generateRawKeyPair(curve);

    it('builds private and public JWKs', () => {
        const { privateKey, publicKey } = generateJwk(curve, { sk, pk });

        expect(privateKey).toMatchObject({ kty: 'EC', crv: ansiName });
        expect(privateKey).toHaveProperty('d');
        expect(publicKey).toMatchObject({ kty: 'EC', crv: ansiName });
        expect(publicKey).not.toHaveProperty('d');
        expect({ x: publicKey?.x, y: publicKey?.y }).toEqual({
            x: privateKey?.x,
            y: privateKey?.y,
        });
    });

    it('round-trips raw keys through a private JWK', () => {
        const { privateKey } = generateJwk(curve, { sk, pk });
        const info = parseJwk(defined(privateKey));

        expect(info.curveName).toBe(curve);
        expect(info.privateKey).toEqual(sk);
        expect(info.publicKey).toEqual(pk);
    });

    it('round-trips raw keys through a public JWK', () => {
        const { publicKey } = generateJwk(curve, { pk });
        const info = parseJwk(defined(publicKey));

        expect(info.curveName).toBe(curve);
        expect(info.publicKey).toEqual(pk);
        expect(info.privateKey).toBeUndefined();
    });

    it('is accepted by Node as a signing and verifying key', () => {
        const { privateKey, publicKey } = generateJwk(curve, { sk, pk });

        const signer = createSign('sha256');
        signer.update(MESSAGE);
        const signature = signer.sign(createPrivateKey(privateKeyInput(defined(privateKey))));

        const verifier = createVerify('sha256');
        verifier.update(MESSAGE);
        expect(
            verifier.verify(createPublicKey(publicKeyInput(defined(publicKey))), signature)
        ).toBe(true);
    });

    it('accepts the ANSI curve name as input', () => {
        expect(generateJwk(ansiName, { sk, pk })).toEqual(generateJwk(curve, { sk, pk }));
    });
});

describe('JWK input', () => {
    it('accepts a JWK without key_ops and kid', () => {
        const { pk } = generateRawKeyPair('prime256v1');
        const { publicKey } = generateJwk('prime256v1', { pk });
        const minimal = { kty: 'EC', crv: 'P-256', x: publicKey!.x, y: publicKey!.y } as const;

        expect(parseJwk(minimal).publicKey).toEqual(pk);
    });
});
