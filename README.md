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

- Zero runtime dependencies, Node's own `Buffer` only.
- ESM and CommonJS builds with bundled TypeScript types.
- 79 named curves: NIST, SEC 2 prime and binary, Brainpool, ANSI X9.62 and WAP WSG.
- JWK support for P-256, P-384 and P-521.

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

### `generatePem(input, keys?)` and `generateDer(input, keys?)`

Encode raw keys. Both accept the same arguments and return a pair that only contains the keys you
passed in.

```ts
generatePem('prime256v1', { sk, pk }); // { privateKey: '-----BEGIN EC PRIVATE KEY-----…', publicKey: '…' }
generatePem({ curveName: 'prime256v1', privateKey: sk }); // { privateKey: '…' }
generateDer('prime256v1', { pk }); // { publicKey: <Buffer 30 59 …> }
```

| Argument | Meaning                                                         |
| -------- | --------------------------------------------------------------- |
| `input`  | A curve name, or an object carrying the curve name and the keys |
| `keys`   | Optional key material, used only for keys missing from `input`  |

Key aliases accepted in either argument: `sk` / `privateKey`, `pk` / `publicKey`. Curve aliases
accepted in the object form: `curveName` / `curve` / `crv`. A curve name can be the Node name
(`prime256v1`) or the JWK name (`P-256`).

The private key is encoded as `ECPrivateKey` (RFC 5915) and the public key as
`SubjectPublicKeyInfo` (RFC 5480). When both are passed, the public key is embedded in the private
key structure, as OpenSSL does.

### `parsePem(pem)`

Parse an `EC PRIVATE KEY` or `PUBLIC KEY` block into raw key material:

```ts
{ curveName: 'prime256v1', privateKey?: Buffer, publicKey?: Buffer }
```

LF and CRLF line endings, indented blocks and trailing whitespace are all accepted. A private key
that was encoded without an embedded public key parses back without `publicKey`.

### `parseSkDer(der)` and `parsePkDer(der)`

The DER-only counterparts of `parsePem`, for the same two structures.

### `generateJwk(input, keys?)` and `parseJwk(jwk)`

```ts
const { privateKey, publicKey } = generateJwk('P-256', { sk, pk });
// privateKey: { kty: 'EC', crv: 'P-256', x: '…', y: '…', d: '…', key_ops, kid }
parseJwk(privateKey); // back to { curveName, privateKey, publicKey }
```

JWK covers P-256, P-384 and P-521 only, because those are the curves RFC 7518 registers for JWK
use. A private JWK needs the raw public key as well: RFC 7518 requires `x` and `y` next to `d`, and
`x`/`y` cannot be derived from `d` without EC point arithmetic.

### Errors

Every error is a plain `Error` with a message naming the problem, for example:

| Message                                      | Cause                                        |
| -------------------------------------------- | -------------------------------------------- |
| `Curve name is not optional`                 | No curve name was passed                     |
| `Unsupported elliptic curve: foo`            | The curve is not in the supported list       |
| `Either privateKey or publicKey is required` | No key material was passed                   |
| `Only supports raw keys in Buffer`           | Key material is not a `Buffer`               |
| `Invalid DER encoding of ECPrivateKey`       | Malformed private key DER                    |
| `Unsupported PEM label "PRIVATE KEY"`        | PKCS#8 PEM, which this library does not read |

## Supported curves

`CURVE_NAMES` lists all 79 names and `CURVE_OIDS` maps each one to its OID.

| Family               | Example                               |
| -------------------- | ------------------------------------- |
| ANSI X9.62 prime     | `prime256v1`                          |
| SEC 2 prime          | `secp256k1`, `secp384r1`, `secp521r1` |
| SEC 2 binary         | `sect233k1`, `sect571r1`              |
| Brainpool (RFC 5639) | `brainpoolP256r1`                     |
| ANSI X9.62 binary    | `c2pnb163v1`, `c2tnb431r1`            |
| WAP WSG (RFC 2409)   | `wap-wsg-idm-ecid-wtls12`             |

Not every curve is usable for signing: which curves OpenSSL accepts for ECDSA depends on the Node
and OpenSSL build you run.

## Caveats

- **Do not reuse one key pair for both ECDH and ECDSA** unless you are certain the risk does not
  apply to you. The original motivation for this library was convenience, not key separation.
- **PKCS#8 is not supported.** Only `EC PRIVATE KEY` (RFC 5915) and `PUBLIC KEY` (RFC 5480) PEM
  blocks are read and written. Convert with Node if you have a `PRIVATE KEY` block:

  ```ts
  import { createPrivateKey } from 'node:crypto';
  const sec1 = createPrivateKey(pkcs8Pem).export({ format: 'pem', type: 'sec1' });
  ```

- **Raw keys only.** Keys must be `Buffer`s of the curve's own size; the library does not check that
  a key belongs to the curve you name. Node and OpenSSL reject mismatches when the key is used.
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
