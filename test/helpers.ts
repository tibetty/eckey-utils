import { createECDH, generateKeyPairSync } from 'node:crypto';

const privateKeyWidths = new Map<string, number>();

/**
 * Width OpenSSL writes a private key on `curve` with, read straight from its
 * own SEC1 export so the tests do not depend on the library's table.
 */
export function opensslPrivateKeyWidth(curve: string): number {
    let width = privateKeyWidths.get(curve);
    if (width === undefined) {
        const der = generateKeyPairSync('ec', { namedCurve: curve }).privateKey.export({
            format: 'der',
            type: 'sec1',
        }) as Buffer;
        // SEQUENCE header (short or long form), INTEGER 1, then the OCTET STRING.
        const sequenceHeader = der[1] & 0x80 ? 2 + (der[1] & 0x7f) : 2;
        width = der[sequenceHeader + 3 + 1];
        privateKeyWidths.set(curve, width);
    }
    return width;
}

/** Left-pad `sk` to the width OpenSSL uses on `curve`. */
export function padToOpenssl(curve: string, sk: Buffer): Buffer {
    const width = opensslPrivateKeyWidth(curve);
    return sk.length >= width ? sk : Buffer.concat([Buffer.alloc(width - sk.length), sk]);
}

/**
 * A raw key pair exactly as `crypto.ECDH` hands it out: the private key loses
 * its leading zero bytes, so it is shorter than the curve order now and then.
 */
export function generateEcdhKeyPair(curve: string): { sk: Buffer; pk: Buffer } {
    const ecdh = createECDH(curve);
    ecdh.generateKeys();
    return { sk: ecdh.getPrivateKey(), pk: ecdh.getPublicKey() };
}

/**
 * A raw key pair with the private key at the width the library returns it, so
 * round trips compare equal whatever the key's leading bytes are.
 */
export function generateRawKeyPair(curve: string): { sk: Buffer; pk: Buffer } {
    const { sk, pk } = generateEcdhKeyPair(curve);
    return { sk: padToOpenssl(curve, sk), pk };
}

/**
 * An ECDH key pair whose private key starts with a zero byte, so `ECDH` hands
 * it out one byte short — the case the library has to pad.
 */
export function generateShortKeyPair(curve: string): { sk: Buffer; pk: Buffer } {
    const width = opensslPrivateKeyWidth(curve);
    for (;;) {
        const { sk } = generateEcdhKeyPair(curve);
        const padded = padToOpenssl(curve, sk);
        const candidate = Buffer.concat([Buffer.alloc(1), padded.subarray(1)]);
        const ecdh = createECDH(curve);
        try {
            ecdh.setPrivateKey(candidate);
        } catch {
            continue; // zero is not a valid key; draw again
        }
        const short = ecdh.getPrivateKey();
        if (short.length < width) {
            return { sk: short, pk: ecdh.getPublicKey() };
        }
    }
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
