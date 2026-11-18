import { createHash } from 'node:crypto';

/**
 * RFC 7638 JWK thumbprint: SHA-256 over the key's required members, sorted by
 * name and serialized without whitespace, base64url encoded.
 *
 * Used as `kid`, so a key and its public half share one id and different keys
 * never collide.
 */
export function jwkThumbprint(required: Readonly<Record<string, string>>): string {
    const sorted = Object.fromEntries(
        Object.keys(required)
            .sort()
            .map((name) => [name, required[name]])
    );
    return createHash('sha256').update(JSON.stringify(sorted)).digest('base64url');
}
