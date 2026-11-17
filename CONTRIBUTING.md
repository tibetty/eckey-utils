# Contributing

Thanks for taking the time to contribute. Bug reports, fixes, documentation improvements and new
tests are all welcome.

## Getting started

```bash
git clone https://github.com/tibetty/eckey-utils.git
cd eckey-utils
npm install
npm run check
```

`npm run check` runs the full gate, in this order:

| Script              | What it does                                                 |
| ------------------- | ------------------------------------------------------------ |
| `npm run typecheck` | `tsc --noEmit` over `src` and `test`                         |
| `npm run lint`      | ESLint with typescript-eslint                                |
| `npm run test`      | Vitest, no coverage                                          |
| `npm run build`     | tsup, emitting ESM, CommonJS and type definitions to `dist/` |

Add `npm run coverage` to see the coverage report, or `npm run test:watch` while iterating.

## Project layout

```text
src/
  index.ts    public API: generate*/parse* functions and argument handling
  curves.ts   supported curves, OIDs and the JWK names
  asn1.ts     DER primitives: lengths, TLVs and OBJECT IDENTIFIERs
  der.ts      ECPrivateKey (RFC 5915) and SubjectPublicKeyInfo (RFC 5480), PEM wrapping
  jwk.ts      JWK encoding and parsing
test/         Vitest suites, one file per module plus argument-form and error coverage
```

## What a change needs

- **A test that fails first.** Every fix or feature comes with a test that reproduces the problem;
  the suite must stay at 100% statement and branch coverage.
- **Evidence against an independent implementation.** Key encodings are checked byte-for-byte against
  OpenSSL through Node's `crypto` module, and against a fixed RFC 6979 test vector. A new encoding
  path should come with an equivalent cross-check rather than a self-generated expectation.
- **No runtime dependencies.** The package runs on `Buffer` alone. A dependency needs a strong
  justification in the pull request.
- **A changelog entry.** Add a line under `## [Unreleased]` in [CHANGELOG.md](./CHANGELOG.md),
  grouped as Added, Changed, Fixed or Removed.

## Compatibility promise

The public API is the seven functions in `src/index.ts` (`generatePem`, `generateDer`, `parsePem`,
`parseSkDer`, `parsePkDer`, `generateJwk`, `parseJwk`) plus the exported types and constants. Within
1.x:

- existing call signatures keep working, including both argument forms and the `sk`/`pk` aliases;
- generated PEM, DER and JWK bytes do not change;
- new behaviour is additive, and anything that stops being accepted is a major version bump.

Error **messages** are not part of that promise — they may be clarified in a minor release — but
error **types** are: every failure is a plain `Error`.

## Commit and pull request conventions

- Use [Conventional Commits](https://www.conventionalcommits.org/) prefixes: `fix:`, `feat:`,
  `docs:`, `test:`, `chore:`, `refactor:`.
- Keep a pull request to one logical change, and describe the behaviour before and after.
- Fill in the pull request template; state which Node versions you ran locally when changing
  anything curve-dependent.

## Releases

Maintainer only, and only from a green `master`:

1. Update `version` in `package.json` and move the `## [Unreleased]` entries in `CHANGELOG.md` under
   the new version heading, with the release date.
2. `npm run check` — this is also `prepublishOnly`, so a broken build cannot be published.
3. `npm publish`, then `git tag v<version> && git push --follow-tags`.
