import { createECDH } from 'node:crypto';

/** Generate a fresh raw key pair on `curve`, exactly as `crypto.ECDH` hands it out. */
export function generateRawKeyPair(curve: string): { sk: Buffer; pk: Buffer } {
  const ecdh = createECDH(curve);
  ecdh.generateKeys();
  return { sk: ecdh.getPrivateKey(), pk: ecdh.getPublicKey() };
}

/** Derive the raw public key of a known private key. */
export function getPublicKeyOf(curve: string, sk: Buffer): Buffer {
  const ecdh = createECDH(curve);
  ecdh.setPrivateKey(sk);
  return ecdh.getPublicKey();
}

/** Narrow away `undefined`, failing the test when the value is missing. */
export function defined<T>(value: T | undefined, what = 'value'): T {
  if (value === undefined) {
    throw new Error(`Expected ${what} to be defined`);
  }
  return value;
}

/** base64url encode without padding, as used by JWK. */
export function base64Url(buf: Buffer): string {
  return buf.toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
