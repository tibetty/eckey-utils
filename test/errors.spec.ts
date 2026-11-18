import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
    generateDer,
    generateJwk,
    generatePem,
    parseJwk,
    parsePem,
    parsePkDer,
    parseSkDer,
} from '../src/index.js';
import { encodeBitString, encodeOid, encodeTlv } from '../src/asn1.js';
import { defined, generateRawKeyPair } from './helpers.js';

const { sk, pk } = generateRawKeyPair('prime256v1');
const { privateKey: validPem } = generatePem('prime256v1', { sk, pk });

describe('curve validation', () => {
    it('requires a curve name', () => {
        expect(() => generatePem({ sk })).toThrow('Curve name is not optional');
        expect(() => generatePem('', { sk })).toThrow('Curve name is not optional');
    });

    it('names the unsupported curve', () => {
        expect(() => generatePem('nope', { sk })).toThrow('Unsupported elliptic curve: nope');
        expect(() => generateDer('secp256k1x', { sk })).toThrow(
            'Unsupported elliptic curve: secp256k1x'
        );
    });

    it('rejects a curve name that is not a string', () => {
        expect(() => generatePem({ curveName: 42 as unknown as string, sk })).toThrow(
            'Unsupported elliptic curve: 42'
        );
    });
});

describe('key material validation', () => {
    it('requires at least one key', () => {
        expect(() => generatePem('prime256v1', {})).toThrow(
            'Either privateKey or publicKey is required'
        );
        expect(() => generateJwk('prime256v1', {})).toThrow(
            'Either privateKey or publicKey is required'
        );
    });

    it('rejects key material that is not a Buffer', () => {
        expect(() =>
            generatePem('prime256v1', { sk: 'not a buffer' as unknown as Buffer, pk })
        ).toThrow('Only supports raw keys in Buffer');
        expect(() =>
            generateDer('prime256v1', { sk, pk: new Uint8Array(65) as unknown as Buffer })
        ).toThrow('Only supports raw keys in Buffer');
    });
});

describe('DER validation', () => {
    const { privateKey: sec1 } = generateDer('prime256v1', { sk, pk });

    it('rejects an empty buffer', () => {
        expect(() => parseSkDer(Buffer.alloc(0))).toThrow('Invalid DER encoding of ECPrivateKey');
        expect(() => parsePkDer(Buffer.alloc(0))).toThrow(
            'Invalid DER encoding of SubjectPublicKeyInfo'
        );
    });

    it('rejects a truncated private key', () => {
        expect(() => parseSkDer(defined(sec1).subarray(0, 20))).toThrow(
            'Invalid DER encoding of ECPrivateKey'
        );
    });

    it('rejects a wrong ECPrivateKey version', () => {
        const tampered = Buffer.from(defined(sec1));
        tampered[4] = 0x02;
        expect(() => parseSkDer(tampered)).toThrow('Invalid DER encoding of ECPrivateKey');
    });

    it('rejects an unexpected element inside the private key', () => {
        const withNull = encodeTlv(
            0x30,
            Buffer.concat([
                encodeTlv(0x02, Buffer.from([0x01])),
                encodeTlv(0x04, sk),
                encodeTlv(0xa0, encodeOid('1.2.840.10045.3.1.7')),
                encodeTlv(0x05, Buffer.alloc(0)),
            ])
        );
        expect(() => parseSkDer(withNull)).toThrow('Invalid DER encoding of ECPrivateKey');
    });

    it('rejects trailing bytes after the private key', () => {
        const extended = Buffer.concat([defined(sec1), Buffer.from([0x00])]);
        expect(() => parseSkDer(extended)).toThrow('Invalid DER encoding of ECPrivateKey');
    });

    it('rejects a private key without named-curve parameters', () => {
        const withoutParams = encodeTlv(
            0x30,
            Buffer.concat([encodeTlv(0x02, Buffer.from([0x01])), encodeTlv(0x04, sk)])
        );
        expect(() => parseSkDer(withoutParams)).toThrow(
            'ECPrivateKey without named-curve parameters is not supported'
        );
    });

    it('reports an unsupported curve OID', () => {
        const unknownCurve = encodeTlv(
            0x30,
            Buffer.concat([
                encodeTlv(
                    0x30,
                    Buffer.concat([encodeOid('1.2.840.10045.2.1'), encodeOid('1.2.3.4')])
                ),
                encodeBitString(pk),
            ])
        );
        expect(() => parsePkDer(unknownCurve)).toThrow('Unsupported elliptic curve OID: 1.2.3.4');
    });

    it('rejects a key that is not EC', () => {
        const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
        const der = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
        expect(() => parsePkDer(der)).toThrow(
            'Not an EC public key (algorithm OID: 1.2.840.113549.1.1.1)'
        );
    });

    it('rejects an SPKI whose algorithm section is not an EC OID', () => {
        const notAnOid = encodeTlv(
            0x30,
            Buffer.concat([
                encodeTlv(0x30, encodeTlv(0x02, Buffer.from([0x01]))),
                encodeBitString(pk),
            ])
        );
        expect(() => parsePkDer(notAnOid)).toThrow('Invalid DER encoding of SubjectPublicKeyInfo');
    });

    it('rejects an SPKI whose curve OID overruns the algorithm section', () => {
        const overrun = encodeTlv(
            0x30,
            Buffer.concat([
                encodeTlv(
                    0x30,
                    Buffer.concat([
                        encodeOid('1.2.840.10045.2.1'),
                        encodeOid('1.2.840.10045.3.1.7'),
                    ]).subarray(0, 13)
                ),
                encodeBitString(pk),
            ])
        );
        expect(() => parsePkDer(overrun)).toThrow('Invalid DER encoding of SubjectPublicKeyInfo');
    });

    it('rejects an unexpected element after the public key bits', () => {
        const withNull = encodeTlv(
            0x30,
            Buffer.concat([
                encodeTlv(
                    0x30,
                    Buffer.concat([
                        encodeOid('1.2.840.10045.2.1'),
                        encodeOid('1.2.840.10045.3.1.7'),
                    ])
                ),
                encodeBitString(pk),
                encodeTlv(0x05, Buffer.alloc(0)),
            ])
        );
        expect(() => parsePkDer(withNull)).toThrow('Invalid DER encoding of SubjectPublicKeyInfo');
    });

    it('rejects trailing bytes after the public key', () => {
        const { publicKey: spki } = generateDer('prime256v1', { pk });
        const extended = Buffer.concat([defined(spki), Buffer.from([0x00])]);
        expect(() => parsePkDer(extended)).toThrow('Invalid DER encoding of SubjectPublicKeyInfo');
    });
});

describe('PEM validation', () => {
    it('requires PEM content', () => {
        expect(() => parsePem('')).toThrow('PEM content is not optional');
    });

    it('rejects content that is not PEM', () => {
        expect(() => parsePem('not a pem block')).toThrow('Invalid or unsupported PEM content');
        expect(() => parsePem('-----BEGIN PUBLIC KEY-----\nAAAA')).toThrow(
            'Invalid or unsupported PEM content'
        );
    });

    it('rejects mismatched BEGIN and END labels', () => {
        const mismatched = defined(validPem).replace('END EC PRIVATE KEY', 'END PRIVATE KEY');
        expect(() => parsePem(mismatched)).toThrow('Invalid or unsupported PEM content');
    });

    it('names the unsupported PEM label', () => {
        const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
        const rsaPem = privateKey.export({ format: 'pem', type: 'pkcs1' }).toString();
        expect(() => parsePem(rsaPem)).toThrow(
            'Unsupported PEM label "RSA PRIVATE KEY": expected "EC PRIVATE KEY", "PRIVATE KEY" or "PUBLIC KEY"'
        );
    });

    it('rejects a body that does not decode to DER', () => {
        expect(() =>
            parsePem('-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----')
        ).toThrow('Invalid DER encoding of SubjectPublicKeyInfo');
    });
});

describe('JWK validation', () => {
    it('rejects curves without a registered JWK crv value', () => {
        expect(() => generateJwk('brainpoolP256r1', { sk, pk })).toThrow(
            'JWK supports only P-256, P-384, P-521, secp256k1'
        );
    });

    it('derives the public key when only the private key is given', () => {
        expect(generateJwk('prime256v1', { sk })).toEqual(generateJwk('prime256v1', { sk, pk }));
    });

    it('rejects a non-EC key', () => {
        expect(() =>
            parseJwk({ kty: 'RSA', crv: 'P-256', x: 'a', y: 'b' } as unknown as never)
        ).toThrow('Not an EC JSON Web Key');
        expect(() => parseJwk(undefined as unknown as never)).toThrow('Not an EC JSON Web Key');
    });

    it('rejects an unsupported JWK curve', () => {
        expect(() =>
            parseJwk({ kty: 'EC', crv: 'P-192', x: 'a', y: 'b' } as unknown as never)
        ).toThrow('JWK supports only P-256, P-384, P-521, secp256k1');
    });

    it('requires x and y', () => {
        expect(() => parseJwk({ kty: 'EC', crv: 'P-256' } as unknown as never)).toThrow(
            'EC JSON Web Key requires both "x" and "y"'
        );
    });
});
