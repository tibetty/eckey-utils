import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { generateDer, generatePem, parsePem, parseSkDer } from '../src/index.js';
import {
    encodeBitString,
    encodeOctetString,
    encodeOid,
    encodeSmallInteger,
    encodeTlv,
} from '../src/asn1.js';
import { decodePkcs8Der } from '../src/der.js';
import { defined, generateRawKeyPair } from './helpers.js';

const decodeBase64Url = (value: string): Buffer =>
    Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

interface NodeEcJwk {
    crv: string;
    x: string;
    y: string;
    d: string;
}

const MESSAGE = Buffer.from('Hello, World!');

describe.each(['prime256v1', 'secp384r1', 'secp521r1', 'secp256k1'])(
    'PKCS#8 matches OpenSSL for %s',
    (curve) => {
        const { privateKey } = generateKeyPairSync('ec', { namedCurve: curve });
        const jwk = privateKey.export({ format: 'jwk' }) as unknown as NodeEcJwk;
        const sk = decodeBase64Url(jwk.d);
        const pk = Buffer.concat([
            Buffer.from([0x04]),
            decodeBase64Url(jwk.x),
            decodeBase64Url(jwk.y),
        ]);
        const pkcs8Pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString().trimEnd();
        const pkcs8Der = privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;

        it('encodes the same private key PEM', () => {
            expect(generatePem(curve, { sk, pk }, { type: 'pkcs8' }).privateKey).toBe(pkcs8Pem);
        });

        it('encodes the same private key DER', () => {
            expect(generateDer(curve, { sk, pk }, { type: 'pkcs8' }).privateKey).toEqual(pkcs8Der);
        });

        it('parses the PKCS#8 PEM OpenSSL exports', () => {
            expect(parsePem(pkcs8Pem)).toEqual({ curveName: curve, privateKey: sk, publicKey: pk });
        });

        it('parses the PKCS#8 DER OpenSSL exports', () => {
            expect(parseSkDer(pkcs8Der)).toEqual({
                curveName: curve,
                privateKey: sk,
                publicKey: pk,
            });
        });
    }
);

describe('PKCS#8 encoding', () => {
    const { sk, pk } = generateRawKeyPair('prime256v1');

    it('wraps the private key in a PRIVATE KEY block', () => {
        const { privateKey } = generatePem('prime256v1', { sk, pk }, { type: 'pkcs8' });
        expect(privateKey).toMatch(
            /^-----BEGIN PRIVATE KEY-----\n[\s\S]+\n-----END PRIVATE KEY-----$/
        );
    });

    it('keeps SEC1 as the default', () => {
        expect(generatePem('prime256v1', { sk, pk })).toEqual(
            generatePem('prime256v1', { sk, pk }, { type: 'sec1' })
        );
        expect(generateDer('prime256v1', { sk, pk })).toEqual(
            generateDer('prime256v1', { sk, pk }, { type: 'sec1' })
        );
    });

    it('is unaffected for public keys', () => {
        const withOptions = generatePem('prime256v1', { pk }, { type: 'pkcs8' });
        expect(withOptions.publicKey).toBe(generatePem('prime256v1', { pk }).publicKey);
        expect(withOptions.privateKey).toBeUndefined();
    });

    it('omits the public key when none is given', () => {
        const { privateKey } = generatePem('prime256v1', { sk }, { type: 'pkcs8' });
        const info = parsePem(defined(privateKey));

        expect(info.curveName).toBe('prime256v1');
        expect(info.privateKey).toEqual(sk);
        expect(info.publicKey).toBeUndefined();
    });

    it('produces a key Node can sign with', () => {
        const { privateKey, publicKey } = generatePem('prime256v1', { sk, pk }, { type: 'pkcs8' });
        const signature = sign('sha256', MESSAGE, defined(privateKey));

        expect(verify('sha256', MESSAGE, defined(publicKey), signature)).toBe(true);
    });
});

describe('PKCS#8 parsing', () => {
    const { sk, pk } = generateRawKeyPair('prime256v1');
    const innerKey = defined(generateDer('prime256v1', { sk }, { type: 'pkcs8' }).privateKey);

    it('tells SEC1 and PKCS#8 apart by version', () => {
        const sec1 = defined(generateDer('prime256v1', { sk, pk }).privateKey);

        expect(parseSkDer(sec1)).toEqual({
            curveName: 'prime256v1',
            privateKey: sk,
            publicKey: pk,
        });
        expect(parseSkDer(innerKey)).toEqual({ curveName: 'prime256v1', privateKey: sk });
    });

    it('reads a OneAsymmetricKey with attributes and an outer public key', () => {
        // version 1, algorithm, network-encoding-free inner key, attributes [0], public key [1]
        const inner = encodeTlv(
            0x30,
            Buffer.concat([encodeSmallInteger(1), encodeOctetString(sk)])
        );
        const oneAsymmetricKey = encodeTlv(
            0x30,
            Buffer.concat([
                encodeSmallInteger(1),
                encodeTlv(
                    0x30,
                    Buffer.concat([
                        encodeOid('1.2.840.10045.2.1'),
                        encodeOid('1.2.840.10045.3.1.7'),
                    ])
                ),
                encodeOctetString(inner),
                encodeTlv(0xa0, encodeTlv(0x31, Buffer.alloc(0))), // empty attributes
                encodeTlv(0xa1, encodeBitString(pk)),
            ])
        );

        expect(parseSkDer(oneAsymmetricKey)).toEqual({
            curveName: 'prime256v1',
            privateKey: sk,
            publicKey: pk,
        });
    });

    it('rejects a non-EC private key', () => {
        const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
        const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;

        expect(() => parseSkDer(pkcs8)).toThrow(
            'Not an EC private key (algorithm OID: 1.2.840.113549.1.1.1)'
        );
    });

    it('rejects a curve mismatch between the algorithm and the inner key', () => {
        const innerWithCurve = encodeTlv(
            0x30,
            Buffer.concat([
                encodeSmallInteger(1),
                encodeOctetString(sk),
                encodeTlv(0xa0, encodeOid('1.3.132.0.10')), // secp256k1
            ])
        );
        const mismatched = encodeTlv(
            0x30,
            Buffer.concat([
                encodeSmallInteger(0),
                encodeTlv(
                    0x30,
                    Buffer.concat([
                        encodeOid('1.2.840.10045.2.1'),
                        encodeOid('1.2.840.10045.3.1.7'),
                    ])
                ),
                encodeOctetString(innerWithCurve),
            ])
        );

        expect(() => parseSkDer(mismatched)).toThrow(
            'Curve mismatch: PKCS#8 algorithm says prime256v1, inner ECPrivateKey says secp256k1'
        );
    });

    it('rejects a malformed PKCS#8 buffer', () => {
        const withoutAlgorithmOid = encodeTlv(
            0x30,
            Buffer.concat([
                encodeSmallInteger(0),
                encodeTlv(0x30, encodeSmallInteger(1)), // algorithm is not an OID
                encodeOctetString(
                    encodeTlv(0x30, Buffer.concat([encodeSmallInteger(1), encodeOctetString(sk)]))
                ),
            ])
        );
        expect(() => parseSkDer(withoutAlgorithmOid)).toThrow(
            'Invalid DER encoding of PrivateKeyInfo'
        );

        expect(() => parseSkDer(encodeTlv(0x30, encodeSmallInteger(0)))).toThrow(
            'Invalid DER encoding of PrivateKeyInfo'
        );
    });
});

describe('PKCS#8 structure', () => {
    const { sk } = generateRawKeyPair('prime256v1');
    const inner = encodeTlv(0x30, Buffer.concat([encodeSmallInteger(1), encodeOctetString(sk)]));

    /** A well-formed PKCS#8 header around `inner`, with an optional extra element. */
    const wrap = (version: number, tail: Buffer = Buffer.alloc(0)): Buffer =>
        encodeTlv(
            0x30,
            Buffer.concat([
                encodeTlv(0x02, Buffer.from([version])),
                encodeTlv(
                    0x30,
                    Buffer.concat([
                        encodeOid('1.2.840.10045.2.1'),
                        encodeOid('1.2.840.10045.3.1.7'),
                    ])
                ),
                encodeOctetString(inner),
                tail,
            ])
        );

    it('accepts versions 0 and 1', () => {
        expect(parseSkDer(wrap(0)).curveName).toBe('prime256v1');
        expect(parseSkDer(wrap(1)).curveName).toBe('prime256v1');
    });

    it('rejects an unsupported version', () => {
        expect(() => decodePkcs8Der(wrap(2))).toThrow('Invalid DER encoding of PrivateKeyInfo');
    });

    it('rejects trailing bytes', () => {
        expect(() => decodePkcs8Der(Buffer.concat([wrap(0), Buffer.from([0x00])]))).toThrow(
            'Invalid DER encoding of PrivateKeyInfo'
        );
    });

    it('rejects an unexpected element after the private key', () => {
        expect(() => decodePkcs8Der(wrap(0, encodeTlv(0x05, Buffer.alloc(0))))).toThrow(
            'Invalid DER encoding of PrivateKeyInfo'
        );
    });

    it('falls back to the SEC1 error for buffers that are neither', () => {
        expect(() => parseSkDer(encodeTlv(0x04, sk))).toThrow(
            'Invalid DER encoding of ECPrivateKey'
        );
        expect(() => parseSkDer(encodeTlv(0x30, encodeOctetString(sk)))).toThrow(
            'Invalid DER encoding of ECPrivateKey'
        );
    });
});

describe('rejected PEM inputs', () => {
    const { sk, pk } = generateRawKeyPair('prime256v1');

    it('refuses an encrypted PEM', () => {
        const pem = defined(generatePem('prime256v1', { sk, pk }).privateKey);
        const body = pem.split('\n').slice(1, -1).join('\n');
        const encrypted = [
            '-----BEGIN EC PRIVATE KEY-----',
            'Proc-Type: 4,ENCRYPTED',
            'DEK-Info: AES-128-CBC,0123456789ABCDEF',
            '',
            body,
            '-----END EC PRIVATE KEY-----',
        ].join('\n');

        expect(() => parsePem(encrypted)).toThrow('Encrypted PEM is not supported');
    });

    it('rejects an unknown private key type option', () => {
        // @ts-expect-error -- 'der' is not a private key encoding
        expect(() => generatePem('prime256v1', { sk }, { type: 'der' })).toThrow(
            'Unsupported private key type: der'
        );
        // @ts-expect-error -- 'der' is not a private key encoding
        expect(() => generateDer('prime256v1', { sk }, { type: 'der' })).toThrow(
            'Unsupported private key type: der'
        );
    });

    it('names a label it does not handle', () => {
        const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
        const rsaPem = privateKey.export({ format: 'pem', type: 'pkcs1' }).toString();

        expect(() => parsePem(rsaPem)).toThrow(
            'Unsupported PEM label "RSA PRIVATE KEY": expected "EC PRIVATE KEY", "PRIVATE KEY" or "PUBLIC KEY"'
        );
    });
});
