import { createPrivateKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { generateDer, generatePem, parsePem, parseSkDer } from '../src/index.js';
import { decodeOid, decodeTlv } from '../src/asn1.js';
import { fromPem } from '../src/der.js';
import { generateRawKeyPair } from './helpers.js';

const { sk, pk } = generateRawKeyPair('prime256v1');
const PASSPHRASE = 'correct horse battery staple';

/** Read the PBES2 parameters out of an EncryptedPrivateKeyInfo. */
function pbes2Params(der: Buffer) {
    const info = decodeTlv(der, 0);
    const algorithm = decodeTlv(der, info.start);
    const algorithmOid = decodeTlv(der, algorithm.start);
    const pbes2 = decodeTlv(der, algorithmOid.end);
    const kdf = decodeTlv(der, pbes2.start);
    const kdfOid = decodeTlv(der, kdf.start);
    const kdfParams = decodeTlv(der, kdfOid.end);
    const salt = decodeTlv(der, kdfParams.start);
    const iterations = decodeTlv(der, salt.end);
    const prf = decodeTlv(der, iterations.end);
    const prfOid = decodeTlv(der, prf.start);
    const cipherScheme = decodeTlv(der, kdf.end);
    const cipherOid = decodeTlv(der, cipherScheme.start);
    const oid = (tlv: { start: number; end: number }): string =>
        decodeOid(der, tlv.start, tlv.end - tlv.start);

    return {
        algorithm: oid(algorithmOid),
        kdf: oid(kdfOid),
        saltBytes: salt.end - salt.start,
        iterations: der.readUIntBE(iterations.start, iterations.end - iterations.start),
        prf: oid(prfOid),
        cipher: oid(cipherOid),
    };
}

describe('encrypted output follows OpenSSL parameters', () => {
    it('uses PBES2 with PBKDF2-HMAC-SHA256, 2048 iterations and aes-256-cbc', () => {
        const der = generateDer('prime256v1', { sk, pk }, { passphrase: PASSPHRASE }).privateKey;

        expect(pbes2Params(der as Buffer)).toMatchObject({
            algorithm: '1.2.840.113549.1.5.13', // id-PBES2
            kdf: '1.2.840.113549.1.5.12', // id-PBKDF2
            iterations: 2048,
            prf: '1.2.840.113549.2.9', // hmacWithSHA256
            cipher: '2.16.840.1.101.3.4.1.42', // aes-256-cbc
        });
    });

    it('matches what OpenSSL produces on this runtime, salt length included', () => {
        // The salt length is an OpenSSL default that differs between versions
        // (8 bytes on 3.0, 16 from 3.2), so compare against this runtime's own
        // output instead of pinning a number.
        const ours = generateDer('prime256v1', { sk, pk }, { passphrase: PASSPHRASE })
            .privateKey as Buffer;
        const reference = createPrivateKey({
            key: generateDer('prime256v1', { sk, pk }).privateKey as Buffer,
            format: 'der',
            type: 'sec1',
        }).export({ format: 'der', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase: PASSPHRASE });

        expect(pbes2Params(ours)).toEqual(pbes2Params(reference as Buffer));
        expect(pbes2Params(ours).saltBytes).toBeGreaterThanOrEqual(8);
    });

    it('honours an explicit cipher', () => {
        const der = generateDer(
            'prime256v1',
            { sk, pk },
            { passphrase: PASSPHRASE, cipher: 'aes-128-cbc' }
        ).privateKey as Buffer;

        expect(pbes2Params(der).cipher).toBe('2.16.840.1.101.3.4.1.2'); // aes-128-cbc
    });
});

describe('encrypted PEM output', () => {
    it('defaults to PKCS#8 when a passphrase is given', () => {
        const { privateKey } = generatePem('prime256v1', { sk, pk }, { passphrase: PASSPHRASE });

        expect(privateKey).toMatch(/^-----BEGIN ENCRYPTED PRIVATE KEY-----/);
        expect(parsePem(privateKey as string, { passphrase: PASSPHRASE })).toEqual({
            curveName: 'prime256v1',
            privateKey: sk,
            publicKey: pk,
        });
    });

    it('writes the legacy container when sec1 is asked for', () => {
        const { privateKey } = generatePem(
            'prime256v1',
            { sk, pk },
            { type: 'sec1', passphrase: PASSPHRASE }
        );

        expect(privateKey).toContain('Proc-Type: 4,ENCRYPTED');
        expect(privateKey).toContain('DEK-Info: AES-256-CBC,');
        expect(parsePem(privateKey as string, { passphrase: PASSPHRASE }).privateKey).toEqual(sk);
    });

    it('accepts the passphrase as a Buffer', () => {
        const { privateKey } = generatePem(
            'prime256v1',
            { sk, pk },
            { passphrase: Buffer.from(PASSPHRASE) }
        );
        expect(parsePem(privateKey as string, { passphrase: PASSPHRASE }).privateKey).toEqual(sk);
    });

    it('leaves the public key unencrypted', () => {
        const encrypted = generatePem('prime256v1', { sk, pk }, { passphrase: PASSPHRASE });
        expect(encrypted.publicKey).toBe(generatePem('prime256v1', { pk }).publicKey);
    });

    it('is readable by OpenSSL, not only by this library', () => {
        const { privateKey } = generatePem('prime256v1', { sk, pk }, { passphrase: PASSPHRASE });
        const decrypted = createPrivateKey({ key: privateKey as string, passphrase: PASSPHRASE });

        expect(decrypted.export({ format: 'der', type: 'sec1' })).toEqual(
            generateDer('prime256v1', { sk, pk }).privateKey
        );
    });
});

describe('encrypted DER output', () => {
    it('round-trips through parseSkDer', () => {
        const der = generateDer('prime256v1', { sk, pk }, { passphrase: PASSPHRASE }).privateKey;

        expect(parseSkDer(der as Buffer, { passphrase: PASSPHRASE })).toEqual({
            curveName: 'prime256v1',
            privateKey: sk,
            publicKey: pk,
        });
    });

    it('refuses sec1, which OpenSSL cannot encrypt as DER', () => {
        expect(() =>
            generateDer('prime256v1', { sk, pk }, { type: 'sec1', passphrase: PASSPHRASE })
        ).toThrow("Encrypted DER is PKCS#8 only: use { type: 'pkcs8' }");
    });
});

describe('encryption options', () => {
    it('requires a passphrase to use a cipher', () => {
        expect(() => generatePem('prime256v1', { sk, pk }, { cipher: 'aes-256-cbc' })).toThrow(
            'A passphrase is required to use a cipher'
        );
    });

    it('reports a cipher OpenSSL does not know', () => {
        expect(() =>
            generatePem('prime256v1', { sk }, { passphrase: PASSPHRASE, cipher: 'rot13' })
        ).toThrow(/^Cannot encrypt the private key: /);
    });

    it('cannot be decrypted with the wrong passphrase', () => {
        const { privateKey } = generatePem('prime256v1', { sk, pk }, { passphrase: PASSPHRASE });

        expect(() => parsePem(privateKey as string, { passphrase: 'nope' })).toThrow(
            /^Cannot decrypt the private key: /
        );
    });

    it('leaves unencrypted output byte-identical', () => {
        expect(generatePem('prime256v1', { sk, pk }, {})).toEqual(
            generatePem('prime256v1', { sk, pk })
        );
        expect(generatePem('prime256v1', { sk, pk }, { type: 'pkcs8' }).privateKey).toMatch(
            /^-----BEGIN PRIVATE KEY-----/
        );
        expect(fromPem(generatePem('prime256v1', { sk, pk }).privateKey as string).tag).toBe(
            'EC PRIVATE KEY'
        );
    });
});
