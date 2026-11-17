import { describe, expect, it } from 'vitest';
import {
    generateDer,
    generatePem,
    parsePem,
    type CurveName,
    type GenerateOptions,
    type RawKeyMaterial,
} from '../src/index.js';
import { defined, generateRawKeyPair } from './helpers.js';

const { sk, pk } = generateRawKeyPair('prime256v1');
const other = generateRawKeyPair('prime256v1');
const CURVE: CurveName = 'prime256v1';

describe('argument precedence', () => {
    it('prefers the keys the first argument provides', () => {
        const pair = generatePem({ curveName: CURVE, sk }, { sk: other.sk, pk: other.pk });
        const info = parsePem(defined(pair.privateKey));

        expect(info.privateKey).toEqual(sk);
        expect(info.publicKey).toEqual(other.pk);
    });

    it('fills only the keys missing from the first argument', () => {
        expect(generatePem({ curveName: CURVE, sk }, { pk })).toEqual(
            generatePem(CURVE, { sk, pk })
        );
    });

    it('does not mutate the objects it is given', () => {
        const first: RawKeyMaterial = { sk, pk };
        const second: RawKeyMaterial = { pk };
        generatePem(CURVE, first);
        generatePem({ curveName: CURVE }, second);

        expect(first).toEqual({ sk, pk });
        expect(second).toEqual({ pk });
        expect(Object.isFrozen(first)).toBe(false);
    });

    it('accepts frozen key objects', () => {
        expect(generatePem(CURVE, Object.freeze({ sk, pk }))).toEqual(
            generatePem(CURVE, { sk, pk })
        );
    });
});

describe('curve names', () => {
    it.each(['prime256v1', 'P-256'] as const)('accepts %s', (curve) => {
        expect(generatePem(curve, { pk })).toEqual(generatePem(CURVE, { pk }));
    });

    it('is case sensitive', () => {
        expect(() => generatePem('Prime256v1', { pk })).toThrow(
            'Unsupported elliptic curve: Prime256v1'
        );
    });

    it('does not accept object keys as curve names', () => {
        expect(() => generatePem({ EVP_PKEY: 'P-256' } as never, { pk })).toThrow(
            'Curve name is not optional'
        );
    });

    it('rejects an empty object', () => {
        expect(() => generatePem({}, { sk })).toThrow('Curve name is not optional');
    });

    it('rejects null, arrays and numbers as the first argument', () => {
        expect(() => generatePem(null as never, { sk })).toThrow('Curve name is not optional');
        expect(() => generatePem(['prime256v1'] as never, { sk })).toThrow(
            'Curve name is not optional'
        );
        expect(() => generatePem(42 as never, { sk })).toThrow('Unsupported elliptic curve: 42');
        expect(() => generatePem(true as never, { sk })).toThrow(
            'Unsupported elliptic curve: true'
        );
    });

    it('rejects a curve supplied in the second argument', () => {
        expect(() => generatePem({ sk }, { curveName: CURVE } as never)).toThrow(
            'Curve name is not optional'
        );
    });
});

describe('key material types', () => {
    it('accepts a Buffer view with a byte offset', () => {
        const padded = Buffer.concat([Buffer.alloc(16, 0xaa), sk]);
        const view = padded.subarray(16);

        expect(view.equals(sk)).toBe(true);
        expect(view.byteOffset).toBeGreaterThanOrEqual(16);
        expect(generatePem(CURVE, { sk: view }).privateKey).toBe(
            generatePem(CURVE, { sk }).privateKey
        );
    });

    it.each([
        ['Uint8Array', new Uint8Array(32)],
        ['ArrayBuffer', new ArrayBuffer(32)],
        ['string', 'sk'],
        ['number', 32],
        ['object', { length: 32 }],
    ])('rejects a %s in place of a private key', (_name, value) => {
        expect(() => generatePem(CURVE, { sk: value as unknown as Buffer })).toThrow(
            'Only supports raw keys in Buffer'
        );
    });

    it('treats explicit undefined and null as absent', () => {
        expect(generatePem(CURVE, { sk: undefined, pk })).toEqual(generatePem(CURVE, { pk }));
        expect(generatePem(CURVE, { sk: null as unknown as Buffer, pk })).toEqual(
            generatePem(CURVE, { pk })
        );
        expect(() => generatePem(CURVE, { sk: null as unknown as Buffer })).toThrow(
            'Either privateKey or publicKey is required'
        );
    });

    it('ignores unknown key properties', () => {
        const withExtras = { sk, pk, kek: Buffer.alloc(32), algorithm: 'EC' } as RawKeyMaterial;
        expect(generatePem(CURVE, withExtras)).toEqual(generatePem(CURVE, { sk, pk }));
    });
});

describe('options', () => {
    it('defaults to sec1', () => {
        expect(generatePem(CURVE, { sk }, {} as GenerateOptions)).toEqual(
            generatePem(CURVE, { sk }, { type: 'sec1' })
        );
        expect(generatePem(CURVE, { sk }, { type: undefined })).toEqual(
            generatePem(CURVE, { sk }, { type: 'sec1' })
        );
        expect(generatePem(CURVE, { sk }, undefined)).toEqual(generatePem(CURVE, { sk }));
    });

    it('ignores unknown option properties', () => {
        const options = { type: 'pkcs8', encrypt: true } as GenerateOptions;
        expect(generateDer(CURVE, { sk }, options)).toEqual(
            generateDer(CURVE, { sk }, { type: 'pkcs8' })
        );
    });

    it('does not apply to JWK or public keys', () => {
        const withOptions = generatePem(CURVE, { sk, pk }, { type: 'pkcs8' });
        expect(withOptions.publicKey).toBe(generatePem(CURVE, { pk }).publicKey);
        expect(generateDer(CURVE, { sk, pk }, { type: 'pkcs8' })).not.toEqual(
            generateDer(CURVE, { sk, pk })
        );
    });

    it('rejects an unknown key type', () => {
        for (const type of ['sec2', 'PEM', '']) {
            expect(() =>
                generatePem(CURVE, { sk }, { type: type as GenerateOptions['type'] })
            ).toThrow(`Unsupported private key type: ${type}`);
        }
    });
});

describe('return values', () => {
    it('contains only the members that were asked for', () => {
        expect(Object.keys(generatePem(CURVE, { sk }))).toEqual(['privateKey']);
        expect(Object.keys(generatePem(CURVE, { pk }))).toEqual(['publicKey']);
        expect(Object.keys(generateDer(CURVE, { sk, pk }))).toEqual(['privateKey', 'publicKey']);
    });

    it('returns new objects every call', () => {
        const first = generateDer(CURVE, { sk, pk });
        const second = generateDer(CURVE, { sk, pk });

        expect(first).toEqual(second);
        expect(first).not.toBe(second);
        expect(first.privateKey).not.toBe(second.privateKey);
    });

    it('is stable across repeated calls', () => {
        const pem = defined(generatePem(CURVE, { sk, pk }).privateKey);
        expect(generatePem(CURVE, { sk, pk }).privateKey).toBe(pem);
    });
});
