# eckey-utils

[![npm](https://img.shields.io/npm/v/eckey-utils.svg)](https://www.npmjs.com/package/eckey-utils)
[![CI](https://github.com/tibetty/eckey-utils/actions/workflows/ci.yml/badge.svg)](https://github.com/tibetty/eckey-utils/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/eckey-utils.svg)](./LICENSE)
[![types](https://img.shields.io/badge/types-included-blue.svg)](./dist/index.d.ts)

Convert raw EC key material to and from PEM, DER and JWK.

`crypto.createECDH()` returns bare keys (the scalar `d` and the point `04 || x || y`), while
`crypto.sign()` and `crypto.verify()` want a PEM string or a `KeyObject`. This library bridges the
gap in both directions, so the same key pair can be generated raw, persisted as PEM, and parsed back
into raw keys.

- No runtime dependencies: nothing beyond `Buffer` and `node:crypto`.
- ESM and CommonJS builds with bundled TypeScript types.
- 79 named curves: NIST, SEC 2 prime and binary, Brainpool, ANSI X9.62 and WAP WSG.
- JWK support for the EC curves with a registered `crv` value (P-256, P-384, P-521, secp256k1),
  plus OKP keys for Ed25519 and Ed448.
- Compressed public points (`02 || x` / `03 || x`) accepted anywhere a key is read; output is always
  uncompressed.
- Key length checked against the curve, so a key from the wrong curve fails where it happens.

## Install

```bash
npm install eckey-utils
```

Node.js 18 or newer. CI covers 20, 22 and 24 (Node 18 is end-of-life).

## Quick start

Generate a PEM pair from raw keys and sign with it:

```ts
import { createECDH, createSign, createVerify } from 'node:crypto';
import { generatePem } from 'eckey-utils';

const ecdh = createECDH('prime256v1');
ecdh.generateKeys();

const { privateKey, publicKey } = generatePem('prime256v1', {
  sk: ecdh.getPrivateKey(),
  pk: ecdh.getPublicKey(),
});

const message = Buffer.from('Hello, World!');
const signature = createSign('sha256').update(message).sign(privateKey);

const verified = createVerify('sha256').update(message).verify(publicKey, signature);
console.log(verified); // true
```

Parse a PEM back into raw keys:

```ts
import { parsePem } from 'eckey-utils';

const { curveName, privateKey, publicKey } = parsePem(pem);
// curveName === 'prime256v1', privateKey and publicKey are Buffers
```

CommonJS works the same way: `const { generatePem } = require('eckey-utils');`

## API

### `generatePem(input, keys?, options?)` and `generateDer(input, keys?, options?)`

Encode raw keys. Both accept the same arguments and return a pair that only contains the keys you
passed in.

```ts
generatePem('prime256v1', { sk, pk }); // { privateKey: '-----BEGIN EC PRIVATE KEY-----…', publicKey: '…' }
generatePem({ curveName: 'prime256v1', privateKey: sk }); // { privateKey: '…' }
generateDer('prime256v1', { pk }); // { publicKey: <Buffer 30 59 …> }
generatePem('prime256v1', { sk, pk }, { type: 'pkcs8' }); // { privateKey: '-----BEGIN PRIVATE KEY-----…' }
```

| Argument  | Meaning                                                                |
| --------- | ---------------------------------------------------------------------- |
| `input`   | A curve name, or an object carrying the curve name and the keys        |
| `keys`    | Optional key material, used only for keys missing from `input`         |
| `options` | `{ type: 'sec1' \| 'pkcs8' }` — private key encoding, default `'sec1'` |

A compressed public point (`02 || x` or `03 || x`, SEC 1 v2 section 2.3.3) is accepted wherever a
public key is accepted and expanded to `04 || x || y` on the way out, so everything this library
writes is uncompressed. Decompression is delegated to OpenSSL through `node:crypto`.

Key aliases accepted in either argument: `sk` / `privateKey`, `pk` / `publicKey`. Curve aliases
accepted in the object form: `curveName` / `curve` / `crv`. A curve name can be the Node name
(`prime256v1`) or the JWK name (`P-256`).

Key material is checked against the curve before encoding: a private key may not be longer than the
curve's coordinate size, and a public point must be `1 + 2n` bytes uncompressed or `1 + n` bytes
compressed, where `n` is `CURVE_KEY_BYTES[curve]`. A key from another curve, a truncated buffer or a
hex string therefore fails at the call, with the curve and both sizes in the message.

The private key is encoded as `ECPrivateKey` (RFC 5915) by default, or as PKCS#8 `PrivateKeyInfo`
(RFC 5958) with `{ type: 'pkcs8' }`; the public key is always `SubjectPublicKeyInfo` (RFC 5480).
When both keys are passed, the public key is embedded in the private key structure, as OpenSSL does.
Both encodings are byte-identical to what OpenSSL produces for the same key.

### `parsePem(pem)`

Parse an `EC PRIVATE KEY` (RFC 5915), `PRIVATE KEY` (PKCS#8) or `PUBLIC KEY` (RFC 5480) block into
raw key material:

```ts
{ curveName: 'prime256v1', privateKey?: Buffer, publicKey?: Buffer }
```

LF and CRLF line endings, indented blocks and trailing whitespace are all accepted. A private key
that was encoded without an embedded public key parses back without `publicKey`. Encrypted PEM is
rejected with `Encrypted PEM is not supported` rather than silently misparsed.

### `parseSkDer(der)` and `parsePkDer(der)`

The DER-only counterparts of `parsePem`. `parseSkDer` accepts both private key structures; RFC 5915
and PKCS#8 are told apart by their version number.

### `generateJwk(input, keys?)` and `parseJwk(jwk)`

```ts
const { privateKey, publicKey } = generateJwk('P-256', { sk, pk });
// privateKey: { kty: 'EC', crv: 'P-256', x: '…', y: '…', d: '…', key_ops, kid }
parseJwk(privateKey); // back to { curveName, privateKey, publicKey }
```

JWK covers the curves with a registered `crv` value: P-256, P-384 and P-521 (RFC 7518) plus
secp256k1 (RFC 8812). A private JWK needs the raw public key as well: those RFCs require `x` and `y`
next to `d`, and `x`/`y` cannot be derived from `d` without EC point arithmetic.
Pass the curve either as the Node name (`secp256k1`) or as the JWK name (`P-256`).

### Errors

Every error is a plain `Error` with a message naming the problem, for example:

| Message                                      | Cause                                     |
| -------------------------------------------- | ----------------------------------------- |
| `Curve name is not optional`                 | No curve name was passed                  |
| `Unsupported elliptic curve: foo`            | The curve is not in the supported list    |
| `Either privateKey or publicKey is required` | No key material was passed                |
| `Only supports raw keys in Buffer`           | Key material is not a `Buffer`            |
| `Invalid DER encoding of ECPrivateKey`       | Malformed SEC1 private key DER            |
| `Invalid DER encoding of PrivateKeyInfo`     | Malformed PKCS#8 private key DER          |
| `Not an EC private key (algorithm OID: …)`   | PKCS#8 holding an RSA, OKP or other key   |
| `Encrypted PEM is not supported`             | PEM with `Proc-Type: 4,ENCRYPTED` headers |
| `Unsupported PEM label "…"`                  | A PEM block this library does not handle  |

## Supported curves

`CURVE_NAMES` lists all 79 names, `CURVE_OIDS` maps each one to its OID, and `CURVE_KEY_BYTES` gives
its coordinate size in bytes.

| Family               | Example                               |
| -------------------- | ------------------------------------- |
| ANSI X9.62 prime     | `prime256v1`                          |
| SEC 2 prime          | `secp256k1`, `secp384r1`, `secp521r1` |
| SEC 2 binary         | `sect233k1`, `sect571r1`              |
| Brainpool (RFC 5639) | `brainpoolP256r1`                     |
| ANSI X9.62 binary    | `c2pnb163v1`, `c2tnb431r1`            |
| WAP WSG (RFC 2409)   | `wap-wsg-idm-ecid-wtls12`             |

OKP curves are not EC curves and are not in that list: `OKP_CURVES` covers `Ed25519` and `Ed448`,
which are available for JWK only.

Not every curve is usable for signing: which curves OpenSSL accepts for ECDSA depends on the Node
and OpenSSL build you run.

## Caveats

- **Do not reuse one key pair for both ECDH and ECDSA** unless you are certain the risk does not
  apply to you. The original motivation for this library was convenience, not key separation.
- **PEM is EC only.** `Ed25519` and `Ed448` keys are supported as JWK, but a PKCS#8 PEM for them is
  rejected (`Not an EC private key`), because their PEM containers hold no EC parameters.
- **Encrypted and PKCS#1 PEM blocks are not handled.** Encrypted keys, `RSA PRIVATE KEY` blocks and
  certificates are rejected by name. Decrypt or convert them with Node first, for example
  `createPrivateKey(pkcs8Pem).export({ format: 'pem', type: 'sec1' })`.

- **Size is checked, membership is not.** Key length is validated against the curve, but two curves
  of the same size (P-256 and secp256k1, say) cannot be told apart from raw bytes; Node and OpenSSL
  reject such a mismatch when the key is used.
- **Modern Node can often skip this library.** `crypto.createPrivateKey({ key: jwk, format: 'jwk' })`
  builds a `KeyObject` from a JWK directly (Node 15.12+). This library remains useful when you have
  raw keys and need PEM, or need to parse PEM back into raw keys.

## Security

See [SECURITY.md](./SECURITY.md) for supported versions and how to report a vulnerability.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) for the local
workflow, and [CHANGELOG.md](./CHANGELOG.md) for release notes.

```bash
npm install
npm run check   # typecheck, lint, tests, build
```

## License

ISC © 2018-2026 tibetty
