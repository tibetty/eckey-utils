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

Maintainer only, published from CI so every tarball carries a provenance attestation.

### One-time setup on npm

1. Open the package on npmjs.com, then **Settings → Trusted publishing → Add a publisher**:
    - repository: `tibetty/eckey-utils`
    - workflow: `release.yml`
    - environment: leave empty
2. **Settings → Publishing access**: require two-factor authentication. Trusted publishing needs no
   token, so do not keep a long-lived publish token unless you want the fallback below.
3. Access level stays **public**; `publishConfig` in `package.json` states that explicitly, together
   with the registry.

### Cutting a release

1. Move the `## [Unreleased]` entries in `CHANGELOG.md` under a new version heading and bump
   `version` in `package.json` to match.
2. Merge to `master` and wait for CI to be green.
3. Tag and push:

    ```bash
    git tag -a v<version> -m v<version>
    git push origin v<version>
    ```

4. The `Release` workflow verifies that the tag matches `package.json`, runs `npm run check`, and
   publishes with `--provenance --access public` through the workflow's own OIDC identity. No secret
   is involved.

### Re-publishing an existing tag

The workflow runs on the tag push, so a tag that predates it has to be pushed again:

```bash
git push origin :refs/tags/v1.0.0
git tag -a v1.0.0 -m v1.0.0
git push origin v1.0.0
```

### Fallback: publishing from a workstation

When CI cannot be used, refresh the token and publish by hand:

```bash
npm run check    # includes the packaging checks
npm login
npm publish --otp <code>
```

`prepublishOnly` runs `npm run check:release`, the same gate without `publint`/`attw`, because
`attw --pack` starts an `npm pack` that cannot run inside `npm publish`. Such a tarball has no
provenance attestation, so prefer the workflow.
