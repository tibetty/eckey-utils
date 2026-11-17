import { describe, expect, it } from 'vitest';
import { parsePem } from '../src/index.js';
import { defined, generateRawKeyPair } from './helpers.js';
import { generatePem } from '../src/index.js';

const { sk, pk } = generateRawKeyPair('prime256v1');
const { privateKey, publicKey } = generatePem('prime256v1', { sk, pk });
const PEM_PRIVATE = defined(privateKey);
const PEM_PUBLIC = defined(publicKey);

describe('PEM variants', () => {
    it('accepts CRLF line endings', () => {
        const crlf = PEM_PRIVATE.replace(/\n/g, '\r\n');
        expect(parsePem(crlf)).toEqual({ curveName: 'prime256v1', privateKey: sk, publicKey: pk });
        expect(parsePem(PEM_PUBLIC.replace(/\n/g, '\r\n'))).toEqual({
            curveName: 'prime256v1',
            publicKey: pk,
        });
    });

    it('accepts trailing whitespace after the END line', () => {
        expect(parsePem(`${PEM_PRIVATE}  \n`).privateKey).toEqual(sk);
        expect(parsePem(`${PEM_PRIVATE}\t\r\n`).privateKey).toEqual(sk);
    });

    it('accepts blank lines around the block', () => {
        expect(parsePem(`\n\n${PEM_PRIVATE}\n\n`).privateKey).toEqual(sk);
    });

    it('accepts a body on one long line', () => {
        const [begin, ...rest] = PEM_PRIVATE.split('\n');
        const end = rest.pop() as string;
        const singleLine = `${begin}\n${rest.join('')}\n${end}`;

        expect(singleLine.split('\n')).toHaveLength(3);
        expect(parsePem(singleLine).privateKey).toEqual(sk);
    });

    it('does not care whether the PEM has a trailing newline', () => {
        expect(parsePem(`${PEM_PRIVATE}\n`).privateKey).toEqual(sk);
        expect(parsePem(PEM_PRIVATE).privateKey).toEqual(sk);
    });
});
