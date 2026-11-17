/**
 * Named curves understood by this library, and the ANSI names used by JWK.
 *
 * The curve names are the ones accepted by Node's `crypto.createECDH()`, so a
 * curve name taken from there can be passed straight in.
 */

/** Curve name (as used by Node and this library) to its OID. */
export const CURVE_OIDS = {
  // ANSI X9.62 prime
  prime192v1: '1.2.840.10045.3.1.1',
  prime192v2: '1.2.840.10045.3.1.2',
  prime192v3: '1.2.840.10045.3.1.3',
  prime239v1: '1.2.840.10045.3.1.4',
  prime239v2: '1.2.840.10045.3.1.5',
  prime239v3: '1.2.840.10045.3.1.6',
  prime256v1: '1.2.840.10045.3.1.7',

  // SEC 2 prime
  secp112r1: '1.3.132.0.6',
  secp112r2: '1.3.132.0.7',
  secp128r1: '1.3.132.0.28',
  secp128r2: '1.3.132.0.29',
  secp160k1: '1.3.132.0.9',
  secp160r1: '1.3.132.0.8',
  secp160r2: '1.3.132.0.30',
  secp192k1: '1.3.132.0.31',
  secp224k1: '1.3.132.0.32',
  secp224r1: '1.3.132.0.33',
  secp256k1: '1.3.132.0.10',
  secp384r1: '1.3.132.0.34',
  secp521r1: '1.3.132.0.35',

  // SEC 2 binary
  sect113r1: '1.3.132.0.4',
  sect113r2: '1.3.132.0.5',
  sect131r1: '1.3.132.0.22',
  sect131r2: '1.3.132.0.23',
  sect163k1: '1.3.132.0.1',
  sect163r1: '1.3.132.0.2',
  sect163r2: '1.3.132.0.15',
  sect193r1: '1.3.132.0.24',
  sect193r2: '1.3.132.0.25',
  sect233k1: '1.3.132.0.26',
  sect233r1: '1.3.132.0.27',
  sect239k1: '1.3.132.0.3',
  sect283k1: '1.3.132.0.16',
  sect283r1: '1.3.132.0.17',
  sect409k1: '1.3.132.0.36',
  sect409r1: '1.3.132.0.37',
  sect571k1: '1.3.132.0.38',
  sect571r1: '1.3.132.0.39',

  // ECC brainpool (RFC 5639)
  brainpoolP160r1: '1.3.36.3.3.2.8.1.1.1',
  brainpoolP160t1: '1.3.36.3.3.2.8.1.1.2',
  brainpoolP192r1: '1.3.36.3.3.2.8.1.1.3',
  brainpoolP192t1: '1.3.36.3.3.2.8.1.1.4',
  brainpoolP224r1: '1.3.36.3.3.2.8.1.1.5',
  brainpoolP224t1: '1.3.36.3.3.2.8.1.1.6',
  brainpoolP256r1: '1.3.36.3.3.2.8.1.1.7',
  brainpoolP256t1: '1.3.36.3.3.2.8.1.1.8',
  brainpoolP320r1: '1.3.36.3.3.2.8.1.1.9',
  brainpoolP320t1: '1.3.36.3.3.2.8.1.1.10',
  brainpoolP384r1: '1.3.36.3.3.2.8.1.1.11',
  brainpoolP384t1: '1.3.36.3.3.2.8.1.1.12',
  brainpoolP512r1: '1.3.36.3.3.2.8.1.1.13',
  brainpoolP512t1: '1.3.36.3.3.2.8.1.1.14',

  // ANSI X9.62 binary
  c2pnb163v1: '1.2.840.10045.3.0.1',
  c2pnb163v2: '1.2.840.10045.3.0.2',
  c2pnb163v3: '1.2.840.10045.3.0.3',
  c2pnb176v1: '1.2.840.10045.3.0.4',
  c2pnb208w1: '1.2.840.10045.3.0.10',
  c2pnb272w1: '1.2.840.10045.3.0.16',
  c2pnb304w1: '1.2.840.10045.3.0.17',
  c2pnb368w1: '1.2.840.10045.3.0.19',
  c2tnb191v1: '1.2.840.10045.3.0.5',
  c2tnb191v2: '1.2.840.10045.3.0.6',
  c2tnb191v3: '1.2.840.10045.3.0.7',
  c2tnb239v1: '1.2.840.10045.3.0.11',
  c2tnb239v2: '1.2.840.10045.3.0.12',
  c2tnb239v3: '1.2.840.10045.3.0.13',
  c2tnb359v1: '1.2.840.10045.3.0.18',
  c2tnb431r1: '1.2.840.10045.3.0.20',

  // WAP WSG (RFC 2409)
  'wap-wsg-idm-ecid-wtls1': '2.23.43.1.4.1',
  'wap-wsg-idm-ecid-wtls3': '2.23.43.1.4.3',
  'wap-wsg-idm-ecid-wtls4': '2.23.43.1.4.4',
  'wap-wsg-idm-ecid-wtls5': '2.23.43.1.4.5',
  'wap-wsg-idm-ecid-wtls6': '2.23.43.1.4.6',
  'wap-wsg-idm-ecid-wtls7': '2.23.43.1.4.7',
  'wap-wsg-idm-ecid-wtls8': '2.23.43.1.4.8',
  'wap-wsg-idm-ecid-wtls9': '2.23.43.1.4.9',
  'wap-wsg-idm-ecid-wtls10': '2.23.43.1.4.10',
  'wap-wsg-idm-ecid-wtls11': '2.23.43.1.4.11',
  'wap-wsg-idm-ecid-wtls12': '2.23.43.1.4.12',
} as const;

/** A curve name accepted by this library. */
export type CurveName = keyof typeof CURVE_OIDS;

/**
 * Curves that can be represented as a JWK (`crv` value to curve name).
 *
 * P-256/384/521 are registered by RFC 7518, secp256k1 by RFC 8812.
 */
export const ANSI_CURVES = {
  'P-256': 'prime256v1',
  'P-384': 'secp384r1',
  'P-521': 'secp521r1',
  secp256k1: 'secp256k1',
} as const;

/** The JWK `crv` value of a curve supported by {@link ANSI_CURVES}. */
export type AnsiCurveName = keyof typeof ANSI_CURVES;

/** Curve name to its JWK `crv` value. */
export const CURVE_TO_ANSI: Readonly<Record<string, AnsiCurveName>> = Object.fromEntries(
  Object.entries(ANSI_CURVES).map(([ansi, curve]) => [curve, ansi as AnsiCurveName])
);

const OID_TO_CURVE: Readonly<Record<string, CurveName>> = Object.fromEntries(
  Object.entries(CURVE_OIDS).map(([curve, oid]) => [oid, curve as CurveName])
);

/** All curve names this library can encode, in declaration order. */
export const CURVE_NAMES = Object.keys(CURVE_OIDS) as CurveName[];

/** Look up a curve name by OID, or `undefined` if the OID is not supported. */
export function curveFromOid(oid: string): CurveName | undefined {
  return OID_TO_CURVE[oid];
}

/**
 * Resolve a caller-supplied curve name to a supported one, throwing otherwise.
 *
 * Accepts both the Node curve name (`prime256v1`) and the JWK `crv` value
 * (`P-256`).
 */
export function resolveCurveName(curve: unknown): CurveName {
  if (!curve) {
    throw new Error('Curve name is not optional');
  }
  if (typeof curve === 'string') {
    if (Object.hasOwn(CURVE_OIDS, curve)) {
      return curve as CurveName;
    }
    if (Object.hasOwn(ANSI_CURVES, curve)) {
      return ANSI_CURVES[curve as AnsiCurveName];
    }
  }
  throw new Error(`Unsupported elliptic curve: ${String(curve)}`);
}
