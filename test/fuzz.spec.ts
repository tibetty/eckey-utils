import { describe, expect, it } from 'vitest';
import {
  generateDer,
  generateJwk,
  generatePem,
  parseJwk,
  parsePem,
  parsePkDer,
  parseSkDer,
} from '../src/index.js';
import { defined, generateRawKeyPair } from './helpers.js';

/**
 * Whatever a caller feeds the parsers, the failure must be a plain `Error` with
 * a message. A `TypeError` from reading past the end of a buffer, a `RangeError`
 * from a negative length, or a hang would all leak an implementation detail to
 * someone handling a corrupted key file.
 */

const { sk, pk } = generateRawKeyPair('prime256v1');

const DER_CASES = {
  sec1WithPublicKey: defined(generateDer('prime256v1', { sk, pk }).privateKey),
  sec1WithoutPublicKey: defined(generateDer('prime256v1', { sk }).privateKey),
  pkcs8: defined(generateDer('prime256v1', { sk, pk }, { type: 'pkcs8' }).privateKey),
  spki: defined(generateDer('prime256v1', { pk }).publicKey),
} as const;

const PEM_CASES = {
  sec1: defined(generatePem('prime256v1', { sk, pk }).privateKey),
  pkcs8: defined(generatePem('prime256v1', { sk, pk }, { type: 'pkcs8' }).privateKey),
  spki: defined(generatePem('prime256v1', { pk }).publicKey),
} as const;

/** Deterministic PRNG so a failing mutation can be reproduced. */
function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

function expectPlainError(action: () => unknown): void {
  let outcome: unknown;
  try {
    outcome = action();
  } catch (error) {
    const failure = error as Error;
    expect(failure).toBeInstanceOf(Error);
    // A plain Error, not a subclass: error types are part of the public contract.
    expect(failure.constructor).toBe(Error);
    expect(failure.name).toBe('Error');
    expect(failure.message.length).toBeGreaterThan(0);
    expect(failure.message).not.toMatch(/Cannot read propert|undefined is not|out of range/i);
    return;
  }
  // Some mutations still decode; then the result must be well formed.
  expect(outcome).toBeTypeOf('object');
}

describe.each(Object.entries(DER_CASES))('truncating %s', (name, der) => {
  const parse = name === 'spki' ? parsePkDer : parseSkDer;

  it('never parses a truncated buffer', () => {
    for (let length = 0; length < der.length; length++) {
      expectPlainError(() => parse(der.subarray(0, length)));
      expect(() => parse(der.subarray(0, length))).toThrow();
    }
  });

  it('rejects a buffer with a single trailing byte', () => {
    expectPlainError(() => parse(Buffer.concat([der, Buffer.from([0x00])])));
  });

  it('reports errors the caller can act on', () => {
    expect(() => parse(der.subarray(0, 1))).toThrow(/Invalid DER encoding|Truncated/);
  });
});

describe.each(Object.entries(DER_CASES))('mutating %s', (name, der) => {
  const parse = name === 'spki' ? parsePkDer : parseSkDer;
  const next = random(0xc0ffee);

  it('always fails or returns a well-formed key', () => {
    for (let offset = 0; offset < der.length; offset++) {
      for (const mask of [0x01, 0x80, 0xff]) {
        const mutated = Buffer.from(der);
        mutated[offset] ^= mask;
        expectPlainError(() => parse(mutated));
      }
    }
    for (let i = 0; i < 200; i++) {
      const mutated = Buffer.from(der);
      const offset = Math.floor(next() * mutated.length);
      mutated[offset] = Math.floor(next() * 256);
      expectPlainError(() => parse(mutated));
    }
  });
});

describe.each(Object.entries(PEM_CASES))('mutating %s PEM text', (_name, pem) => {
  it('always fails or returns a well-formed key', () => {
    const next = random(0xbadf00d);
    for (let i = 0; i < 300; i++) {
      const offset = Math.floor(next() * pem.length);
      const operation = next();
      let mutated = pem;
      if (operation < 0.4) {
        mutated = `${pem.slice(0, offset)}${String.fromCharCode(33 + Math.floor(next() * 90))}${pem.slice(offset + 1)}`;
      } else if (operation < 0.7) {
        mutated = `${pem.slice(0, offset)}${pem.slice(offset + 1)}`;
      } else {
        mutated = `${pem.slice(0, offset)}x${pem.slice(offset)}`;
      }
      expectPlainError(() => parsePem(mutated));
    }
  });
});

describe('mutating a JWK', () => {
  const jwk = defined(generateJwk('prime256v1', { sk, pk }).privateKey);

  it('always fails or returns a well-formed key', () => {
    const next = random(0xfeed);
    for (let i = 0; i < 200; i++) {
      const mutated: Record<string, unknown> = { ...jwk };
      const member = (['x', 'y', 'd', 'crv', 'kty'] as const)[Math.floor(next() * 5)];
      if (next() < 0.5) {
        mutated[member] = String.fromCharCode(33 + Math.floor(next() * 60));
      }
      expectPlainError(() => parseJwk(mutated as never));
    }
  });
});

describe('hostile inputs', () => {
  it('rejects empty and non-PEM strings without throwing a TypeError', () => {
    for (const input of ['', ' ', '\n', '\u0000', '-----', '-----BEGIN ', '-----BEGIN X-----']) {
      expectPlainError(() => parsePem(input));
    }
  });

  it('rejects very large bodies quickly', () => {
    const huge = `-----BEGIN PUBLIC KEY-----\n${'A'.repeat(1_000_000)}\n-----END PUBLIC KEY-----`;
    const started = Date.now();
    expect(() => parsePem(huge)).toThrow();
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('rejects a body that decodes to an empty buffer', () => {
    expect(() => parsePem('-----BEGIN PUBLIC KEY-----\n\n-----END PUBLIC KEY-----')).toThrow();
  });

  it('rejects a DER buffer of random bytes', () => {
    const next = random(0x5eed);
    for (let i = 0; i < 200; i++) {
      const length = Math.floor(next() * 64);
      const buffer = Buffer.from(Array.from({ length }, () => Math.floor(next() * 256)));
      expectPlainError(() => parseSkDer(buffer));
      expectPlainError(() => parsePkDer(buffer));
    }
  });

  it('rejects hostile JWK objects', () => {
    const hostile: unknown[] = [
      {},
      { kty: 'EC' },
      { kty: 'EC', crv: 'P-256' },
      { kty: 'EC', crv: 'P-256', x: null, y: null },
      { kty: 'EC', crv: 'P-256', x: 1, y: 2 },
      { kty: 'OKP', crv: 'Ed25519' },
      { kty: 'OKP', crv: 'Ed25519', x: '' },
      { kty: 'EC', crv: 'P-256', x: '!!!', y: '!!!' },
      { kty: 'ec', crv: 'P-256', x: 'AA', y: 'AA' },
    ];
    for (const jwk of hostile) {
      expectPlainError(() => parseJwk(jwk as never));
    }
  });

  it('does not accept an oversized base64url value', () => {
    const tooLong = Buffer.alloc(64).toString('base64url');
    expectPlainError(() => parseJwk({ kty: 'EC', crv: 'P-256', x: tooLong, y: tooLong } as never));
  });
});
