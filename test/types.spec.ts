import { describe, expect, expectTypeOf, it } from 'vitest';
import {
    generateDer,
    generateJwk,
    generatePem,
    parseJwk,
    type CurveName,
    type DerKeyPair,
    type EcJsonWebKey,
    type GenerateOptions,
    type JwkKeyPair,
    type KeyInfo,
    type OkpJsonWebKey,
    type OkpKeyInfo,
    type OkpKeyPair,
    type PemKeyPair,
} from '../src/index.js';
import { generateRawKeyPair } from './helpers.js';

/**
 * Compile-time assertions, checked by `tsc`. The calls live inside thunks so the
 * runtime never invokes them — only their types matter — and the
 * `@ts-expect-error` lines fail the typecheck if the call starts to compile.
 */

const { sk, pk } = generateRawKeyPair('prime256v1');
const EC_CURVE: CurveName = 'prime256v1';

describe('return types', () => {
    it('narrows the generate results', () => {
        expectTypeOf(() => generatePem(EC_CURVE, { sk, pk })).returns.toEqualTypeOf<PemKeyPair>();
        expectTypeOf(() =>
            generateDer(EC_CURVE, { sk, pk }, { type: 'pkcs8' })
        ).returns.toEqualTypeOf<DerKeyPair>();
        expectTypeOf(() => generatePem(EC_CURVE, { pk }).privateKey).returns.toEqualTypeOf<
            string | undefined
        >();
        expectTypeOf(() => generateDer(EC_CURVE, { pk }).publicKey).returns.toEqualTypeOf<
            Buffer | undefined
        >();
    });

    it('picks the JWK flavour from the curve name', () => {
        expectTypeOf(() => generateJwk('P-256', { sk, pk })).returns.toEqualTypeOf<JwkKeyPair>();
        expectTypeOf(() => generateJwk(EC_CURVE, { sk, pk })).returns.toEqualTypeOf<JwkKeyPair>();
        expectTypeOf(() => generateJwk('Ed25519', { sk, pk })).returns.toEqualTypeOf<OkpKeyPair>();
        expectTypeOf(() => generateJwk('Ed448', { pk })).returns.toEqualTypeOf<OkpKeyPair>();
    });

    it('picks the parse result from the key type', () => {
        expectTypeOf(() =>
            parseJwk({ kty: 'EC' } as EcJsonWebKey)
        ).returns.toEqualTypeOf<KeyInfo>();
        expectTypeOf(() =>
            parseJwk({ kty: 'OKP' } as OkpJsonWebKey)
        ).returns.toEqualTypeOf<OkpKeyInfo>();
    });

    it('keeps the result members optional', () => {
        const info: KeyInfo = { curveName: EC_CURVE };
        expectTypeOf(info.publicKey).toEqualTypeOf<Buffer | undefined>();
        expectTypeOf(info.curveName).toEqualTypeOf<CurveName>();
    });
});

describe('argument types', () => {
    it('accepts both argument forms', () => {
        expectTypeOf(() => generatePem(EC_CURVE, { sk })).returns.toEqualTypeOf<PemKeyPair>();
        expectTypeOf(() =>
            generatePem({ curveName: EC_CURVE, sk })
        ).returns.toEqualTypeOf<PemKeyPair>();
        expectTypeOf(() => generatePem({ crv: 'P-256', sk })).returns.toEqualTypeOf<PemKeyPair>();
        expectTypeOf(() =>
            generatePem({ curve: EC_CURVE }, { privateKey: sk })
        ).returns.toEqualTypeOf<PemKeyPair>();
    });

    it('accepts every documented option', () => {
        const options: GenerateOptions[] = [
            {},
            { type: 'sec1' },
            { type: 'pkcs8' },
            { type: undefined },
        ];
        expectTypeOf(options).toEqualTypeOf<GenerateOptions[]>();
    });

    it('rejects misuse at compile time', () => {
        // @ts-expect-error -- 'der' is not a private key encoding
        const badFormat = () => generatePem(EC_CURVE, { sk }, { type: 'der' });
        // @ts-expect-error -- a hex string is not raw key material
        const badKey = () => generatePem(EC_CURVE, { sk: 'deadbeef' });
        // @ts-expect-error -- an EC key pair is not an OKP key pair
        const ecPairIsNotOkp: OkpKeyPair = generateJwk(EC_CURVE, { sk, pk });

        expect([badFormat, badKey, ecPairIsNotOkp]).toHaveLength(3);
    });
});
