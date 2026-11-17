import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { generateDer, generatePem, parseJwk, parsePem } from '../src/index.js';
import { defined, getPublicKeyOf } from './helpers.js';

interface NodeEcJwk {
  crv: string;
  x: string;
  y: string;
  d: string;
}

const decodeBase64Url = (value: string): Buffer =>
  Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

/** Raw key material of a Node key pair, plus the OpenSSL encodings to compare against. */
function nodeKeyPair(curve: string) {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: curve });
  const jwk = privateKey.export({ format: 'jwk' }) as unknown as NodeEcJwk;
  const publicKey = createPublicKey(privateKey);
  return {
    sk: decodeBase64Url(jwk.d),
    pk: Buffer.concat([Buffer.from([0x04]), decodeBase64Url(jwk.x), decodeBase64Url(jwk.y)]),
    sec1Pem: privateKey.export({ format: 'pem', type: 'sec1' }).toString(),
    spkiPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    sec1Der: privateKey.export({ format: 'der', type: 'sec1' }) as Buffer,
    spkiDer: publicKey.export({ format: 'der', type: 'spki' }) as Buffer,
  };
}

describe.each(['prime256v1', 'secp384r1', 'secp521r1', 'secp256k1'])(
  'binary output matches OpenSSL for %s',
  (curve) => {
    const keys = nodeKeyPair(curve);

    it('encodes the private key to the same RFC 5915 DER', () => {
      expect(generateDer(curve, { sk: keys.sk, pk: keys.pk }).privateKey).toEqual(keys.sec1Der);
    });

    it('encodes the public key to the same RFC 5480 DER', () => {
      expect(generateDer(curve, { pk: keys.pk }).publicKey).toEqual(keys.spkiDer);
    });

    it('encodes the same private key PEM', () => {
      expect(generatePem(curve, { sk: keys.sk, pk: keys.pk }).privateKey).toBe(
        keys.sec1Pem.trimEnd()
      );
    });

    it('encodes the same public key PEM', () => {
      expect(generatePem(curve, { pk: keys.pk }).publicKey).toBe(keys.spkiPem.trimEnd());
    });

    it('parses the PEM OpenSSL exports', () => {
      expect(parsePem(keys.sec1Pem)).toEqual({
        curveName: curve,
        privateKey: keys.sk,
        publicKey: keys.pk,
      });
      expect(parsePem(keys.spkiPem)).toEqual({ curveName: curve, publicKey: keys.pk });
    });
  }
);

describe('fixed test vector', () => {
  // RFC 6979 A.2.5 P-256 private key, so the encoding is pinned to a known value.
  const sk = Buffer.from('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721', 'hex');

  it('produces the expected PEM for a known private key', () => {
    const { privateKey, publicKey } = generatePem('prime256v1', {
      sk,
      pk: getPublicKeyOf('prime256v1', sk),
    });

    expect(privateKey).toBe(
      [
        '-----BEGIN EC PRIVATE KEY-----',
        'MHcCAQEEIMmvqdhFunUWa1whV2ex1pNOUMPbNuibEnuKYisSD2choAoGCCqGSM49',
        'AwEHoUQDQgAEYP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Z5A/4QCLi8',
        'maQa6elWKLxk8vGyDC1+n1F3o8KU1EYimQ==',
        '-----END EC PRIVATE KEY-----',
      ].join('\n')
    );
    expect(publicKey).toBe(
      [
        '-----BEGIN PUBLIC KEY-----',
        'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYP7UuiVanTHJYet0xjVtaMBJuJI7',
        'Yfps5mliLmDyn7Z5A/4QCLi8maQa6elWKLxk8vGyDC1+n1F3o8KU1EYimQ==',
        '-----END PUBLIC KEY-----',
      ].join('\n')
    );
  });

  it('leaves the public key out of the DER when only the private key is given', () => {
    const info = parsePem(defined(generatePem('prime256v1', { sk }).privateKey));
    // version + OCTET STRING(sk) + [0]{OID}, i.e. no [1]{BIT STRING} trailer.
    expect(defined(generateDer('prime256v1', { sk }).privateKey).length).toBe(51);
    expect(info.privateKey).toEqual(sk);
    expect(info.publicKey).toBeUndefined();
  });

  it('parses the same key material from its JWK', () => {
    const info = parseJwk({
      kty: 'EC',
      crv: 'P-256',
      x: 'YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y=',
      y: 'A/4QCLi8maQa6elWKLxk8vGyDC1+n1F3o8KU1EYimQ=',
      d: 'ya+p2EW6dRZrXCFXZ7HWk05Qw9s26JsSe4piKxIPZyE=',
    });
    expect(info.curveName).toBe('prime256v1');
    expect(info.privateKey).toEqual(sk);
  });
});
