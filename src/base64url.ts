/** base64url helpers shared by the JWK encodings (RFC 7515 section 2). */

/** Encode without padding, using `-` and `_` instead of `+` and `/`. */
export function encodeBase64Url(buf: Buffer): string {
  return buf.toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/** Decode unpadded base64url. */
export function decodeBase64Url(value: string): Buffer {
  return Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}
