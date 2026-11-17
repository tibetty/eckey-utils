import { describe, expect, it } from 'vitest';
import { generateDer, generateJwk, generatePem, parsePem, parseSkDer } from '../src/index.js';
import {
    encodeBitString,
    encodeOctetString,
    encodeOid,
    encodeSmallInteger,
    encodeTlv,
} from '../src/asn1.js';
import { CURVE_OIDS } from '../src/curves.js';
import { toPem } from '../src/der.js';
import { generateRawKeyPair } from './helpers.js';

const CURVES = ['prime256v1', 'secp384r1', 'secp521r1', 'secp256k1'] as const;
const JWK_CURVES = ['prime256v1', 'secp384r1', 'secp521r1'] as const;

/** Compress an uncompressed point to `02 || x` / `03 || x`, per the parity of y. */
function compressPoint(pk: Buffer): Buffer {
    const half = (pk.length - 1) / 2;
    const y = pk.subarray(half + 1);
    const prefix = (y[y.length - 1] & 1) === 0 ? 0x02 : 0x03;
    return Buffer.concat([Buffer.from([prefix]), pk.subarray(1, half + 1)]);
}

describe.each(CURVES)('compressed points on %s', (curve) => {
    const { sk, pk } = generateRawKeyPair(curve);
    const compressed = compressPoint(pk);

    it('writes the uncompressed point to PEM', () => {
        expect(generatePem(curve, { pk: compressed })).toEqual(generatePem(curve, { pk }));
        expect(generatePem(curve, { sk, pk: compressed })).toEqual(generatePem(curve, { sk, pk }));
    });

    it('writes the uncompressed point to DER', () => {
        expect(generateDer(curve, { pk: compressed })).toEqual(generateDer(curve, { pk }));
        expect(generateDer(curve, { sk, pk: compressed })).toEqual(generateDer(curve, { sk, pk }));
    });
});

describe.each(JWK_CURVES)('compressed points in JWK on %s', (curve) => {
    const { sk, pk } = generateRawKeyPair(curve);
    const compressed = compressPoint(pk);

    it('builds the same JWK as the uncompressed point', () => {
        expect(generateJwk(curve, { pk: compressed })).toEqual(generateJwk(curve, { pk }));
    });

    it('builds the same private JWK as the uncompressed point', () => {
        expect(generateJwk(curve, { sk, pk: compressed })).toEqual(generateJwk(curve, { sk, pk }));
    });
});

describe('parsing compressed points', () => {
    const { sk, pk } = generateRawKeyPair('prime256v1');
    const compressed = compressPoint(pk);

    it('expands a compressed point in a public key PEM', () => {
        const spki = encodeTlv(
            0x30,
            Buffer.concat([
                encodeTlv(
                    0x30,
                    Buffer.concat([
                        encodeOid('1.2.840.10045.2.1'),
                        encodeOid(CURVE_OIDS.prime256v1),
                    ])
                ),
                encodeBitString(compressed),
            ])
        );

        expect(parsePem(toPem('PUBLIC KEY', spki))).toEqual({
            curveName: 'prime256v1',
            publicKey: pk,
        });
    });

    it('expands a compressed point embedded in a private key', () => {
        const sec1 = encodeTlv(
            0x30,
            Buffer.concat([
                encodeSmallInteger(1),
                encodeOctetString(sk),
                encodeTlv(0xa0, encodeOid(CURVE_OIDS.prime256v1)),
                encodeTlv(0xa1, encodeBitString(compressed)),
            ])
        );

        expect(parseSkDer(sec1)).toEqual({
            curveName: 'prime256v1',
            privateKey: sk,
            publicKey: pk,
        });
    });
});

describe('rejected points', () => {
    const { pk } = generateRawKeyPair('prime256v1');

    it('rejects a point it cannot identify', () => {
        const hybrid = Buffer.concat([Buffer.from([0x05]), pk.subarray(1)]);
        const prefixError =
            'Public key must be an uncompressed (04) or compressed (02/03) EC point';
        expect(() => generatePem('prime256v1', { pk: hybrid })).toThrow(prefixError);
        expect(() => generateJwk('prime256v1', { pk: hybrid })).toThrow(prefixError);
    });

    it('rejects a compressed point that is not on the curve', () => {
        // The RFC 6979 A.2.5 P-256 x coordinate with its last byte incremented: not on the curve.
        const offCurve = Buffer.from(
            '0260fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb7',
            'hex'
        );
        expect(() => generateJwk('prime256v1', { pk: offCurve })).toThrow(
            /^Cannot decompress the public key point on prime256v1: /
        );
        expect(() => generatePem('prime256v1', { pk: offCurve })).toThrow(/Cannot decompress/);
    });

    it('rejects a compressed point of the wrong length for the curve', () => {
        expect(() => generatePem('secp384r1', { pk: compressPoint(pk) })).toThrow(
            'Public key length 33 does not match curve secp384r1 ' +
                '(expected 97 for an uncompressed point, 49 for a compressed one)'
        );
    });
});
