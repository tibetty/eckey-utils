# Security Policy

## Supported versions

| Version | Supported           |
| ------- | ------------------- |
| 2.x     | Yes                 |
| 1.x     | No — upgrade to 2.x |
| 0.7.x   | No — upgrade to 2.x |

## Reporting a vulnerability

Do not open a public issue for a security problem. Report it privately through
[GitHub Security Advisories](https://github.com/tibetty/eckey-utils/security/advisories/new), or by
email to xihua.duan@gmail.com if you cannot use GitHub.

Please include:

- the affected version,
- a minimal reproduction (curve, encoding, and the failing call),
- the impact you expect, for example wrong key material being produced or accepted.

You can expect an initial response within 7 days. Fixes for confirmed issues are released as a patch
version, with the details published in [CHANGELOG.md](./CHANGELOG.md) once a fix is available.

## Scope

This library encodes and parses key material; it does not generate random numbers and does not
perform cryptography itself. Reports about the encodings it produces or accepts — for example key
material silently mis-serialised, or malformed input accepted and turned into a valid-looking key —
are in scope. Reports about `crypto.sign()` / `crypto.verify()` behaviour in Node itself are not.
