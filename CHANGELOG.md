# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `CURVE_PRIVATE_KEY_BYTES`: the private key size of each curve, which is the byte length of the
  curve order and differs from `CURVE_KEY_BYTES` on 17 curves.

### Fixed

- Private keys shorter than the curve order are left-padded to full width. `ECDH#getPrivateKey()`
  drops leading zero bytes, so about one P-256 key in 256 was written short: PEM and DER differed
  from OpenSSL's, and the JWK `d` broke RFC 7518 section 6.2.2.1. `parseJwk` pads a short `d` written
  by earlier releases.
- Private key length is checked against the curve order instead of the coordinate size. On
  secp160k1/r1/r2, secp224k1 and two WAP curves the order is wider, so a key read from OpenSSL could
  not be written back (`Private key length 29 does not match curve secp224k1`).
- An empty private key is rejected instead of being encoded.

## [1.2.0] - 2026-11-17

### Added

- Encrypted private key output. `generatePem()` and `generateDer()` accept `{ passphrase }` plus an
  optional `{ cipher }`, and follow OpenSSL's own defaults for `openssl pkcs8 -topk8 -v2 aes-256-cbc`:
  PKCS#8 `PBES2` wrapping `PBKDF2` with 2048 iterations and hmacWithSHA256, with whatever salt length
  the running OpenSSL uses (8 bytes on 3.0, 16 from 3.2). OpenSSL reads the output back.
  `{ type: 'sec1', passphrase }` writes the legacy `Proc-Type: 4,ENCRYPTED` container for tooling
  that still needs it.

### Changed

- `passphrase` without `type` implies PKCS#8 rather than SEC1, and `cipher` without `passphrase`
  throws instead of being ignored. Encrypted DER with `type: 'sec1'` throws, because OpenSSL cannot
  write SEC1 DER encrypted.

### Fixed

- Test failures on Node 20 print the failing assertion again. Vitest's failure formatter uses
  `Map.groupBy`, which Node 21 added, so every failure on Node 20 reported only
  `TypeError: Map.groupBy is not a function`; `test/setup.ts` now supplies the method when the
  runtime is older.

## [1.1.0] - 2026-11-17

### Added

- Passphrase-protected private keys when parsing: `parsePem(pem, { passphrase })` reads legacy
  `EC PRIVATE KEY` blocks with `Proc-Type: 4,ENCRYPTED` headers and PKCS#8 `ENCRYPTED PRIVATE KEY`
  blocks, and `parseSkDer(der, { passphrase })` reads PKCS#8 `EncryptedPrivateKeyInfo`. Decryption
  is delegated to OpenSSL through `node:crypto`; the library implements no part of PBES2. The
  option is ignored for unencrypted input, so one code path reads both kinds.

### Changed

- An encrypted key without a passphrase now throws `Encrypted PEM requires a passphrase` (or
  `Encrypted PKCS#8 requires a passphrase` for DER) instead of the previous
  `Encrypted PEM is not supported`, and a failed decryption throws
  `Cannot decrypt the private key: …` with the OpenSSL error as `cause`.

## [1.0.0] - 2026-11-17

The first release of the rewrite: TypeScript sources, ESM and CommonJS builds with types, a test
suite that cross-checks every encoding against OpenSSL, and fixes for a set of input-handling bugs.

Existing code that calls the seven public functions keeps working unchanged. The default export
shape, the flexible argument forms and the PEM/DER/JWK output bytes are preserved — verified against
0.7.14 over all 79 curves — with one exception: invalid input is now rejected instead of silently
producing a broken key, as listed under "Changed".

New since 0.7: PKCS#8 private keys, compressed public points, key length validation, `secp256k1`
and Ed25519/Ed448 JWKs.

### Added

- A default export holding the seven functions, so `import ecKeyUtils from 'eckey-utils'` keeps
  working alongside the named imports. `require()` returns both.
- TypeScript sources with bundled type definitions, `exports` map, and ESM (`dist/index.js`) plus
  CommonJS (`dist/index.cjs`) builds.
- `CurveName`, `AnsiCurveName`, `KeyInfo`, `RawKeyMaterial`, `DerKeyPair`, `PemKeyPair` and
  `EcJsonWebKey` types, exported alongside the functions.
- `CURVE_NAMES`, `CURVE_OIDS` and `ANSI_CURVES` exports, so callers can enumerate what is supported
  instead of copying the list.
- Test suite with assertions, 100% statement and branch coverage, cross-checked against OpenSSL via
  Node: DER and PEM output is byte-identical to `KeyObject.export()` for P-256, P-384, P-521 and
  secp256k1.
- GitHub Actions CI on Node 20, 22 and 24.
- `LICENSE` file (ISC, as declared in `package.json` since 2018).
- `engines.node >= 18`, a `files` allowlist so only `dist` is published, and `sideEffects: false`.
- OKP JWK support (RFC 8037) for `Ed25519` and `Ed448`: `generateJwk('Ed25519', { sk, pk })` and
  `parseJwk({ kty: 'OKP', … })`, with `OKP_CURVES` describing the two curves. Output is accepted by
  `crypto.createPrivateKey({ format: 'jwk' })` and signs through `crypto.sign(null, …)`. PEM remains
  EC only.
- Compressed public points (SEC 1 v2 section 2.3.3) are accepted by every function that takes key
  material, and expanded to `04 || x || y`. This unblocks JWK generation from compressed points, which
  previously threw `Only uncompressed public keys are supported`. Decompression uses OpenSSL through
  `node:crypto`, so no field arithmetic is implemented here.
- PKCS#8 private keys (RFC 5958): `parsePem()` and `parseSkDer()` read `-----BEGIN PRIVATE KEY-----`
  blocks and PKCS#8 DER, and `generatePem()` / `generateDer()` write them with a third argument,
  `{ type: 'pkcs8' }`. Output is byte-identical to `KeyObject.export()` and to `openssl genpkey`;
  `sec1` remains the default. PKCS#8 without an inner named curve, `OneAsymmetricKey` version 1 with
  attributes, and a curve mismatch between the algorithm and the inner key are all handled.
- Encrypted PEM (`Proc-Type: 4,ENCRYPTED`) is now rejected with `Encrypted PEM is not supported`
  instead of failing later as undecodable content.
- JWK support for `secp256k1` (RFC 8812 `crv` value) in `generateJwk()` and `parseJwk()`. The curve
  already worked for PEM and DER; only the JWK path was refused. Output is accepted by
  `crypto.createPrivateKey({ format: 'jwk' })`.
- The JWK curve error now names every supported curve, derived from the curve table.

### Changed

- `generateJwk()` with only a private key now throws
  `Raw public key is required to build a private JWK` instead of returning an empty object.
- An unknown curve name now throws `Unsupported elliptic curve: <name>` instead of the misleading
  `Invalid Object Identifier`.
- A curve name may also be given as the JWK name (`P-256`), in every function.
- JWKs without `x`/`y` are rejected with `EC JSON Web Key requires both "x" and "y"` instead of a
  `TypeError` from internals, and the curve error names every supported curve.
- `parsePem()` accepts CRLF line endings and a base64 body on a single line.
- `parsePem()` throws `Unsupported PEM label "<label>"` for PEM blocks other than
  `EC PRIVATE KEY` / `PUBLIC KEY`, replacing the generic invalid-content error.
- `parsePem()` accepts a UTF-8 BOM, an indented block and trailing whitespace on any line, all of
  which real-world PEM files carry.
- Key material is validated against the named curve: a private key longer than the curve's coordinate
  size, or a public point that is not `1 + 2n` (uncompressed) or `1 + n` (compressed) bytes, throws
  with both sizes in the message. Input that used to produce an unusable encoding now fails at the
  call. `CURVE_KEY_BYTES` exposes the size of each curve.
- An unrecognised point prefix now reads `Public key must be an uncompressed (04) or compressed
(02/03) EC point`.
- Every public key the library writes or returns is uncompressed: a compressed point passed in, or
  found in a PEM or DER input, is expanded. Curves OpenSSL cannot decompress fail with
  `Cannot decompress the public key point on <curve>: …` instead of a generic error.
- `parseSkDer()` accepts SEC1 and PKCS#8 DER, told apart by version. A buffer that is neither still
  fails with `Invalid DER encoding of ECPrivateKey`.
- The unsupported-label error now lists all three accepted PEM labels.

### Fixed

- `npm publish` no longer fails its own gate: `attw --pack` starts an `npm pack`, which cannot run
  inside `npm publish`, so the publish-time check now stops before the packaging checks. They still
  run in CI on every pull request.
- The CommonJS build no longer sets `__esModule` without providing a default export, which made
  `import ecKeyUtils from 'eckey-utils'` resolve to `undefined` under TypeScript's `esModuleInterop`.
- Curve OID validation used a stateful regular expression, so re-encoding the same OID could fail.
- Public key bytes were sliced from the end of the DER buffer instead of the parsed BIT STRING
  position, which produced wrong keys for buffers with trailing bytes.
- `parsePem()` returned `curveName: undefined` for an unsupported curve OID; it now throws
  `Unsupported elliptic curve OID: <oid>`.
- DER decoders now reject trailing bytes, wrong version values and unexpected elements instead of
  parsing past them.
- The DER encoder and parser no longer keep encoded OIDs in the curve-name table, and
  `generateDer`/`generatePem` share one implementation instead of duplicated bodies.
- `parseJwk()` now validates the size of `x`, `y` and `d` against the curve instead of building a
  point from whatever came in, and rejects an empty `d`. A JWK for another curve, or a truncated one,
  previously produced a bogus key silently.
- All failures are plain `Error`; an internal DER error class no longer leaks a different
  `error.constructor` to callers.
- A curve argument that is neither a string nor an object is now named in the message
  (`Unsupported elliptic curve: 42`) instead of being reported as missing.

## Earlier versions

Versions 0.5.0 through 0.7.14 were published without a changelog; see the git log for their history.
