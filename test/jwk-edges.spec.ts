import { describe, expect, it } from 'vitest';
import { generateJwk, parseJwk, type EcJsonWebKey, type OkpJsonWebKey } from '../src/index.js';
import { defined, generateRawKeyPair } from './helpers.js';

const { sk, pk } = generateRawKeyPair('prime256v1');
const jwk = defined(generateJwk('prime256v1', { sk, pk }).privateKey);

/** Every field of the JWK, varying the one under test. */
const withField = (field: keyof EcJsonWebKey, value: unknown): EcJsonWebKey =>
    ({ ...jwk, [field]: value }) as EcJsonWebKey;

describe('base64url handling', () => {
    it('accepts padded and unpadded values', () => {
        const padded = { ...jwk, x: `${jwk.x}==`, y: `${jwk.y}=` };
        expect(parseJwk(padded).publicKey).toEqual(pk);
    });

    it('accepts the standard base64 alphabet', () => {
        // '-' and '_' are the base64url variants of '+' and '/'; accept both.
        const standard = (value: string): string =>
            Buffer.from(value, 'base64url').toString('base64').replace(/=+$/, '');
        expect(parseJwk(withField('x', standard(jwk.x))).publicKey).toEqual(pk);
    });

    it('ignores whitespace in a value', () => {
        const spaced = `${jwk.x.slice(0, 10)}\n${jwk.x.slice(10)}`;
        expect(parseJwk(withField('x', spaced)).publicKey).toEqual(pk);
    });

    it('rejects an empty coordinate', () => {
        expect(() => parseJwk(withField('x', ''))).toThrow(/does not match curve/);
        expect(() => parseJwk(withField('y', ''))).toThrow(/does not match curve/);
    });

    it('rejects coordinates of the wrong size', () => {
        const short = Buffer.alloc(16).toString('base64url');
        expect(() => parseJwk(withField('x', short))).toThrow(/does not match curve/);
        const long = Buffer.alloc(33).toString('base64url');
        expect(() => parseJwk(withField('y', long))).toThrow(/does not match curve/);
    });

    it('rejects a private key of the wrong size', () => {
        expect(() => parseJwk(withField('d', Buffer.alloc(33).toString('base64url')))).toThrow(
            'Private key length 33 does not match curve prime256v1 (expected at most 32)'
        );
        expect(() => parseJwk(withField('d', ''))).toThrow('EC JSON Web Key has an empty "d"');
    });

    it('accepts a shorter private key, as stripped leading zeros are legal', () => {
        const shorter = sk.subarray(1);
        expect(parseJwk(withField('d', shorter.toString('base64url'))).privateKey).toEqual(shorter);
    });
});

describe('member handling', () => {
    it('ignores members it does not know', () => {
        const extra = { ...jwk, use: 'sig', alg: 'ES256', key_ops: ['sign'], kid: 'custom' };
        expect(parseJwk(extra as EcJsonWebKey)).toEqual({
            curveName: 'prime256v1',
            privateKey: sk,
            publicKey: pk,
        });
    });

    it('treats a null d as a public key', () => {
        expect(parseJwk(withField('d', null)).privateKey).toBeUndefined();
    });

    it('requires kty to match the curve family exactly', () => {
        expect(() => parseJwk(withField('kty', 'ec'))).toThrow('Not an EC JSON Web Key');
        expect(() => parseJwk(withField('kty', 'OKP'))).toThrow(/OKP/);
    });

    it('requires a known crv', () => {
        expect(() => parseJwk(withField('crv', 'P-192'))).toThrow(/JWK supports only/);
        expect(() => parseJwk(withField('crv', 'prime256v1'))).toThrow(/JWK supports only/);
    });

    it('round-trips a JWK it generated unchanged in shape', () => {
        const regenerated = defined(generateJwk('prime256v1', { sk, pk }).privateKey);
        expect(Object.keys(regenerated).sort()).toEqual([
            'crv',
            'd',
            'key_ops',
            'kid',
            'kty',
            'x',
            'y',
        ]);
        expect(regenerated.key_ops).toEqual(['deriveBits', 'deriveKey', 'sign']);
    });
});

describe('OKP member handling', () => {
    const ed25519: OkpJsonWebKey = {
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.alloc(32, 1).toString('base64url'),
        d: Buffer.alloc(32, 2).toString('base64url'),
    };

    it('round-trips a well-formed OKP key', () => {
        expect(parseJwk(ed25519).curveName).toBe('Ed25519');
    });

    it('requires the exact crv spelling', () => {
        expect(() => parseJwk({ ...ed25519, crv: 'ed25519' } as unknown as OkpJsonWebKey)).toThrow(
            'OKP JWK supports only Ed25519 and Ed448'
        );
        expect(() => parseJwk({ ...ed25519, crv: 'X25519' } as unknown as OkpJsonWebKey)).toThrow(
            'OKP JWK supports only Ed25519 and Ed448'
        );
    });

    it('rejects a seed of the wrong size', () => {
        expect(() =>
            parseJwk({ ...ed25519, d: Buffer.alloc(31).toString('base64url') } as OkpJsonWebKey)
        ).toThrow('Private key length 31 does not match curve Ed25519 (expected 32)');
    });

    it('accepts a public-only OKP key', () => {
        const publicOnly: OkpJsonWebKey = { kty: 'OKP', crv: 'Ed25519', x: ed25519.x };
        const info = parseJwk(publicOnly);
        expect(info.privateKey).toBeUndefined();
        expect(info.publicKey).toHaveLength(32);
    });
});
