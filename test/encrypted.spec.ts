import { createPrivateKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { generateDer, generatePem, parsePem, parseSkDer } from '../src/index.js';
import { generateRawKeyPair } from './helpers.js';

/**
 * Encrypted keys are decrypted by OpenSSL through `node:crypto`; the fixtures
 * are produced the same way, so no test depends on the `openssl` CLI.
 */
const PASSPHRASE = 'correct horse battery staple';
const { sk, pk } = generateRawKeyPair('prime256v1');

/** The same key as a Node KeyObject, so it can be exported encrypted. */
const plainPem = generatePem('prime256v1', { sk, pk }).privateKey as string;
const keyObject = createPrivateKey({ key: plainPem, format: 'pem' });

const encryptedCases = [
    {
        name: 'legacy EC PRIVATE KEY with Proc-Type headers',
        pem: keyObject
            .export({ format: 'pem', type: 'sec1', cipher: 'aes-256-cbc', passphrase: PASSPHRASE })
            .toString(),
        marker: 'Proc-Type: 4,ENCRYPTED',
    },
    {
        name: 'PKCS#8 ENCRYPTED PRIVATE KEY',
        pem: keyObject
            .export({ format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase: PASSPHRASE })
            .toString(),
        marker: '-----BEGIN ENCRYPTED PRIVATE KEY-----',
    },
];

describe.each(encryptedCases)('encrypted key: $name', ({ pem, marker }) => {
    it('is the fixture we expect', () => {
        expect(pem).toContain(marker);
    });

    it('decrypts with a passphrase', () => {
        const info = parsePem(pem, { passphrase: PASSPHRASE });

        expect(info.curveName).toBe('prime256v1');
        expect(info.privateKey).toHaveLength(32);
        expect(info.publicKey).toHaveLength(65);
    });

    it('accepts the passphrase as a Buffer', () => {
        expect(parsePem(pem, { passphrase: Buffer.from(PASSPHRASE) }).privateKey).toHaveLength(32);
    });

    it('refuses to guess the passphrase', () => {
        expect(() => parsePem(pem)).toThrow(/requires a passphrase/);
        expect(() => parsePem(pem, {})).toThrow(/requires a passphrase/);
    });

    it('reports a wrong passphrase', () => {
        expect(() => parsePem(pem, { passphrase: 'wrong' })).toThrow(
            /^Cannot decrypt the private key: /
        );
    });
});

describe('encrypted PKCS#8 DER', () => {
    const der = keyObject.export({
        format: 'der',
        type: 'pkcs8',
        cipher: 'aes-256-cbc',
        passphrase: PASSPHRASE,
    }) as Buffer;

    it('decrypts with a passphrase', () => {
        const info = parseSkDer(der, { passphrase: PASSPHRASE });

        expect(info.curveName).toBe('prime256v1');
        expect(info.privateKey).toHaveLength(32);
    });

    it('requires the passphrase', () => {
        expect(() => parseSkDer(der)).toThrow('Encrypted PKCS#8 requires a passphrase');
        expect(() => parseSkDer(der, { passphrase: 'wrong' })).toThrow(/^Cannot decrypt/);
    });
});

describe('passphrase on unencrypted input', () => {
    it('is ignored, so one code path reads both kinds', () => {
        const plain = generatePem('prime256v1', { sk, pk });

        expect(parsePem(plain.privateKey as string, { passphrase: PASSPHRASE })).toEqual(
            parsePem(plain.privateKey as string)
        );
        expect(parsePem(plain.publicKey as string, { passphrase: PASSPHRASE }).publicKey).toEqual(
            pk
        );
        expect(
            parseSkDer(generateDer('prime256v1', { sk, pk }).privateKey as Buffer, {
                passphrase: PASSPHRASE,
            }).privateKey
        ).toEqual(sk);
    });

    it('does not stop a corrupt body from failing', () => {
        const garbage = '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----';
        expect(() => parsePem(garbage, { passphrase: PASSPHRASE })).toThrow(Error);
    });
});

describe('round trip', () => {
    it('decrypts back to the same raw keys the encoder produced', () => {
        const encrypted = keyObject
            .export({ format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase: PASSPHRASE })
            .toString();

        expect(parsePem(encrypted, { passphrase: PASSPHRASE })).toEqual({
            curveName: 'prime256v1',
            privateKey: sk,
            publicKey: pk,
        });
    });
});
