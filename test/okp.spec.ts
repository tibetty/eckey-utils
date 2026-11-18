import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { generateJwk, parseJwk, OKP_CURVES, type OkpJsonWebKey } from '../src/index.js';

const MESSAGE = Buffer.from('Hello, World!');

interface NodeOkpJwk {
    kty: 'OKP';
    crv: 'Ed25519' | 'Ed448';
    x: string;
    d: string;
}

/** Node types `d` as required on a JWK; ours is optional by design. */
const asPrivateJwk = (jwk: OkpJsonWebKey) =>
    ({ key: jwk, format: 'jwk' }) as unknown as Parameters<typeof createPrivateKey>[0];

const asPublicJwk = (jwk: OkpJsonWebKey) =>
    ({ key: jwk, format: 'jwk' }) as unknown as Parameters<typeof createPublicKey>[0];

/** Raw key material of a Node EdDSA key pair, plus the JWK Node exports. */
function nodeKeyPair(type: 'ed25519' | 'ed448') {
    const { privateKey, publicKey } =
        type === 'ed25519' ? generateKeyPairSync('ed25519') : generateKeyPairSync('ed448');
    const jwk = privateKey.export({ format: 'jwk' }) as unknown as NodeOkpJwk;
    return {
        sk: Buffer.from(jwk.d, 'base64url'),
        pk: Buffer.from(jwk.x, 'base64url'),
        jwk,
        privateKey,
        publicKey,
    };
}

const CASES = [
    ['ed25519', 'Ed25519', 32],
    ['ed448', 'Ed448', 57],
] as const;

describe.each(CASES)('%s (%s)', (type, curve, size) => {
    const keys = nodeKeyPair(type);

    it('reports the key size of the curve', () => {
        expect(OKP_CURVES[curve]).toBe(size);
        expect(keys.pk).toHaveLength(size);
    });

    it('builds the same key material Node exports', () => {
        const { privateKey, publicKey } = generateJwk(curve, { sk: keys.sk, pk: keys.pk });

        expect(privateKey).toMatchObject({ kty: 'OKP', crv: curve, x: keys.jwk.x, d: keys.jwk.d });
        expect(publicKey).toMatchObject({ kty: 'OKP', crv: curve, x: keys.jwk.x });
        expect(publicKey).not.toHaveProperty('d');
    });

    it('round-trips raw keys through a private JWK', () => {
        const { privateKey } = generateJwk(curve, { sk: keys.sk, pk: keys.pk });
        expect(parseJwk(privateKey as OkpJsonWebKey)).toEqual({
            curveName: curve,
            privateKey: keys.sk,
            publicKey: keys.pk,
        });
    });

    it('round-trips raw keys through a public JWK', () => {
        const { publicKey } = generateJwk(curve, { pk: keys.pk });
        const info = parseJwk(publicKey as OkpJsonWebKey);

        expect(info.curveName).toBe(curve);
        expect(info.publicKey).toEqual(keys.pk);
        expect(info.privateKey).toBeUndefined();
    });

    it('is accepted by Node for signing and verification', () => {
        const pair = generateJwk(curve, { sk: keys.sk, pk: keys.pk });
        const signingKey = createPrivateKey(asPrivateJwk(pair.privateKey as OkpJsonWebKey));
        const signature = sign(null, MESSAGE, signingKey);

        const verifyingKey = createPublicKey(asPublicJwk(pair.publicKey as OkpJsonWebKey));
        expect(verify(null, MESSAGE, verifyingKey, signature)).toBe(true);
    });

    it('reads a JWK Node exported', () => {
        const info = parseJwk(keys.jwk as OkpJsonWebKey);

        expect(info).toEqual({ curveName: curve, privateKey: keys.sk, publicKey: keys.pk });
    });
});

describe('OKP validation', () => {
    const keys = nodeKeyPair('ed25519');

    it('derives the public key when only the private key is given', () => {
        expect(generateJwk('Ed25519', { sk: keys.sk })).toEqual(
            generateJwk('Ed25519', { sk: keys.sk, pk: keys.pk })
        );
    });

    it('rejects a public key that belongs to another private key', () => {
        const other = Buffer.from(keys.pk);
        other[0] ^= 1;
        expect(() => generateJwk('Ed25519', { sk: keys.sk, pk: other })).toThrow(
            'Public key does not match the private key on Ed25519'
        );
    });

    it('requires at least one key', () => {
        expect(() => generateJwk('Ed25519', {})).toThrow(
            'Either privateKey or publicKey is required'
        );
    });

    it('rejects key material that is not a Buffer', () => {
        expect(() => generateJwk('Ed25519', { pk: 'abc' as unknown as Buffer })).toThrow(
            'Only supports raw keys in Buffer'
        );
    });

    it('rejects keys of the wrong size', () => {
        expect(() => generateJwk('Ed448', { pk: keys.pk })).toThrow(
            'Public key length 32 does not match curve Ed448 (expected 57)'
        );
        expect(() => generateJwk('Ed25519', { sk: keys.sk.subarray(1), pk: keys.pk })).toThrow(
            'Private key length 31 does not match curve Ed25519 (expected 32)'
        );
    });

    it('rejects a JWK without a public key', () => {
        expect(() =>
            parseJwk({ kty: 'OKP', crv: 'Ed25519', d: keys.jwk.d } as OkpJsonWebKey)
        ).toThrow('OKP JSON Web Key requires "x"');
    });

    it('rejects an unsupported OKP curve', () => {
        expect(() =>
            parseJwk({ kty: 'OKP', crv: 'X25519', x: keys.jwk.x } as unknown as OkpJsonWebKey)
        ).toThrow('OKP JWK supports only Ed25519 and Ed448');
    });

    it('rejects a JWK of the wrong size', () => {
        expect(() =>
            parseJwk({ kty: 'OKP', crv: 'Ed448', x: keys.jwk.x } as unknown as OkpJsonWebKey)
        ).toThrow('Public key length 32 does not match curve Ed448 (expected 57)');
    });

    it('rejects a JWK whose crv does not belong to its kty', () => {
        expect(() => parseJwk({ kty: 'EC', crv: 'Ed25519' } as unknown as OkpJsonWebKey)).toThrow(
            'JWK supports only P-256, P-384, P-521, secp256k1'
        );
        expect(() => generateJwk('Ed25519', { pk: Buffer.alloc(65) })).toThrow(
            'Public key length 65 does not match curve Ed25519 (expected 32)'
        );
    });
});
