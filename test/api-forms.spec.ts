import { describe, expect, it } from 'vitest';
import {
  CURVE_OIDS,
  generateDer,
  generatePem,
  type DerKeyPair,
  type PemKeyPair,
  type RawKeyMaterial,
} from '../src/index.js';
import { generateRawKeyPair } from './helpers.js';
import { expectTypeOf } from 'vitest';

const { sk, pk } = generateRawKeyPair('prime256v1');
const both: RawKeyMaterial = { sk, pk };

describe('argument forms', () => {
  it('accepts the curve name followed by key material', () => {
    expect(generatePem('prime256v1', both)).toEqual(
      generatePem({ curveName: 'prime256v1', ...both })
    );
  });

  it.each(['curveName', 'curve', 'crv'] as const)('accepts the %s alias', (alias) => {
    expect(generatePem({ [alias]: 'prime256v1', ...both })).toEqual(
      generatePem('prime256v1', both)
    );
    expect(generateDer({ [alias]: 'prime256v1', ...both })).toEqual(
      generateDer('prime256v1', both)
    );
  });

  it.each(['sk', 'privateKey'] as const)('accepts the %s alias', (alias) => {
    expect(generatePem('prime256v1', { [alias]: sk })).toEqual(generatePem('prime256v1', { sk }));
  });

  it.each(['pk', 'publicKey'] as const)('accepts the %s alias', (alias) => {
    expect(generatePem('prime256v1', { [alias]: pk })).toEqual(generatePem('prime256v1', { pk }));
  });

  it('takes the second argument only to fill in missing keys', () => {
    expect(generatePem({ curveName: 'prime256v1', sk }, { pk })).toEqual(
      generatePem('prime256v1', both)
    );
    expect(generatePem({ curveName: 'prime256v1', sk }, { sk: Buffer.alloc(32) })).toEqual(
      generatePem('prime256v1', { sk })
    );
  });

  it('returns only the keys that were requested', () => {
    expect(Object.keys(generatePem('prime256v1', { sk }))).toEqual(['privateKey']);
    expect(Object.keys(generatePem('prime256v1', { pk }))).toEqual(['publicKey']);
    expect(Object.keys(generateDer('prime256v1', { sk: undefined, pk }))).toEqual(['publicKey']);
  });
});

describe('exports', () => {
  it('exposes the supported curves', () => {
    expect(CURVE_OIDS.prime256v1).toBe('1.2.840.10045.3.1.7');
    expect(Object.keys(CURVE_OIDS)).toHaveLength(79);
  });
});

describe('types', () => {
  it('narrows the result types', () => {
    expectTypeOf(generatePem('prime256v1', both)).toEqualTypeOf<PemKeyPair>();
    expectTypeOf(generateDer('prime256v1', both)).toEqualTypeOf<DerKeyPair>();
    expectTypeOf(generatePem('prime256v1', both).privateKey).toEqualTypeOf<string | undefined>();
  });

  it('rejects an unknown curve name at compile time', () => {
    // @ts-expect-error -- only curve names from CURVE_OIDS are accepted in the object form
    expect(() => generatePem({ curveName: 1, sk })).toThrow();
  });
});

describe('module shape', () => {
  it('keeps the 0.7 default export: the same seven functions, nothing else', async () => {
    const { default: ecKeyUtils, ...named } = await import('../src/index.js');

    expect(Object.keys(ecKeyUtils).sort()).toEqual([
      'generateDer',
      'generateJwk',
      'generatePem',
      'parseJwk',
      'parsePem',
      'parsePkDer',
      'parseSkDer',
    ]);
    for (const [name, fn] of Object.entries(ecKeyUtils)) {
      expect(fn).toBe(named[name as keyof typeof named]);
    }
  });
});
