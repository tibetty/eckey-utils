import { describe, expect, it } from 'vitest';
import { decodeLength, decodeOid, encodeLength, encodeOid } from '../src/asn1.js';

describe('encodeLength and decodeLength', () => {
    it.each([0, 1, 127, 128, 255, 256, 65535, 65536, 16777215])('round-trips %i', (len) => {
        const encoded = encodeLength(len);
        const [decoded, next] = decodeLength(encoded, 0);
        expect(decoded).toBe(len);
        expect(next).toBe(encoded.length);
    });

    it('uses the short form below 0x80', () => {
        expect(encodeLength(0x7f)).toEqual(Buffer.from([0x7f]));
        expect(encodeLength(0x80)).toEqual(Buffer.from([0x81, 0x80]));
        expect(encodeLength(0x0102)).toEqual(Buffer.from([0x82, 0x01, 0x02]));
    });

    it('decodes at an offset', () => {
        expect(decodeLength(Buffer.from([0xff, 0x82, 0x01, 0x02, 0xff]), 1)).toEqual([258, 4]);
    });

    it('rejects invalid lengths to encode', () => {
        expect(() => encodeLength(-1)).toThrow('Invalid DER length: -1');
        expect(() => encodeLength(1.5)).toThrow('Invalid DER length: 1.5');
    });

    it('rejects truncated lengths', () => {
        expect(() => decodeLength(Buffer.alloc(0), 0)).toThrow('Truncated DER length');
        expect(() => decodeLength(Buffer.from([0x82, 0x01]), 0)).toThrow('Truncated DER length');
        expect(() => decodeLength(Buffer.from([0x80]), 0)).toThrow('Truncated DER length');
    });
});

describe('encodeOid and decodeOid', () => {
    const OIDS = [
        '1.2.840.10045.2.1', // id-ecPublicKey
        '1.2.840.10045.3.1.7', // prime256v1
        '1.3.132.0.10', // secp256k1
        '2.23.43.1.4.12', // wap-wsg-idm-ecid-wtls12
        '1.3.36.3.3.2.8.1.1.14', // brainpoolP512t1
        '1.2.3.4',
        '0.9.2342.19200300.100.1.1',
    ];

    it.each(OIDS)('round-trips %s', (oid) => {
        const encoded = encodeOid(oid);
        expect(encoded[0]).toBe(0x06);
        const [len, start] = decodeLength(encoded, 1);
        expect(decodeOid(encoded, start, len)).toBe(oid);
    });

    it('is stateless across repeated calls', () => {
        const oid = '1.2.840.10045.3.1.7';
        expect(encodeOid(oid)).toEqual(encodeOid(oid));
        expect(encodeOid(oid)).toEqual(encodeOid(oid));
    });

    it.each(['', '1', '3.1.2', '1.2.x', '.1.2', '1..2', '01.2'])(
        'rejects invalid OID %j',
        (oid) => {
            expect(() => encodeOid(oid)).toThrow('Invalid Object Identifier');
        }
    );

    it('rejects a truncated OID', () => {
        const encoded = encodeOid('1.2.840.10045.3.1.7');
        const [len, start] = decodeLength(encoded, 1);
        expect(() => decodeOid(encoded, start, len + 10)).toThrow('Truncated Object Identifier');
        expect(() => decodeOid(Buffer.from([0x81]), 0, 1)).toThrow('Truncated Object Identifier');
    });
});
