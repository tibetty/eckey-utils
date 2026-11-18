import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { generateJwk } from '../src/index.js';
import { defined, generateRawKeyPair } from './helpers.js';

describe('JWK kid', () => {
    it('is the RFC 7638 thumbprint, checked against the RFC 8037 A.3 example', () => {
        const pk = Buffer.from('11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo', 'base64url');
        expect(generateJwk('Ed25519', { pk }).publicKey?.kid).toBe(
            'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k'
        );
    });

    it('hashes the EC members crv, kty, x and y in that order', () => {
        const { pk } = generateRawKeyPair('prime256v1');
        const jwk = defined(generateJwk('P-256', { pk }).publicKey);
        const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
        expect(jwk.kid).toBe(createHash('sha256').update(canonical).digest('base64url'));
    });

    it('is shared by both halves of a pair and differs between pairs', () => {
        const first = generateJwk('P-256', generateRawKeyPair('prime256v1'));
        const second = generateJwk('P-256', generateRawKeyPair('prime256v1'));
        expect(first.privateKey?.kid).toBe(first.publicKey?.kid);
        expect(first.publicKey?.kid).not.toBe(second.publicKey?.kid);

        const okp = generateJwk('Ed448', { sk: Buffer.alloc(57, 7) });
        expect(okp.privateKey?.kid).toBe(okp.publicKey?.kid);
    });
});
