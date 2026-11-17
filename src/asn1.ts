/**
 * Minimal ASN.1 DER primitives needed by EC key encoding: definite lengths and
 * OBJECT IDENTIFIER values.
 */

/**
 * Encode a DER length: short form below 0x80, long form above.
 *
 * @example encodeLength(32) // <Buffer 20>
 */
export function encodeLength(len: number): Buffer {
  if (!Number.isInteger(len) || len < 0) {
    throw new RangeError(`Invalid DER length: ${len}`);
  }
  if (len < 0x80) {
    return Buffer.from([len]);
  }
  const octets: number[] = [];
  for (let remaining = len; remaining > 0; remaining = Math.floor(remaining / 256)) {
    octets.unshift(remaining & 0xff);
  }
  return Buffer.from([0x80 | octets.length, ...octets]);
}

/**
 * Decode a DER length starting at `start`.
 *
 * @returns the decoded length and the position right after it.
 */
export function decodeLength(buf: Buffer, start: number): [number, number] {
  if (start >= buf.length) {
    throw new Error('Truncated DER length');
  }
  let pos = start;
  const first = buf[pos++];
  if (!(first & 0x80)) {
    return [first, pos];
  }
  const octetCount = first & 0x7f;
  if (octetCount === 0 || pos + octetCount > buf.length) {
    throw new Error('Truncated DER length');
  }
  let len = 0;
  for (let i = 0; i < octetCount; i++) {
    len = len * 256 + buf[pos++];
  }
  return [len, pos];
}

/** Encode a tag-length-value triple. */
export function encodeTlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

/** Parse the tag, content bounds and length of a TLV starting at `start`. */
export function decodeTlv(buf: Buffer, start: number): { tag: number; start: number; end: number } {
  if (start >= buf.length) {
    throw new Error('Truncated DER content');
  }
  const tag = buf[start];
  const [len, contentStart] = decodeLength(buf, start + 1);
  const end = contentStart + len;
  if (end > buf.length) {
    throw new Error('Truncated DER content');
  }
  return { tag, start: contentStart, end };
}

const OID_PATTERN = /^[0-2](\.(0|[1-9]\d*))+$/;

/**
 * Encode a dotted OBJECT IDENTIFIER, including its tag and length.
 *
 * @example encodeOid('1.2.840.10045.3.1.7') // prime256v1
 */
export function encodeOid(oid: string): Buffer {
  if (typeof oid !== 'string' || !OID_PATTERN.test(oid)) {
    throw new Error('Invalid Object Identifier');
  }
  const arcs = oid.split('.').map(Number);
  // The first two arcs are folded into a single subidentifier.
  const octets: number[] = [];
  const encodeArc = (value: number): void => {
    const groups = [value & 0x7f];
    for (let rest = Math.floor(value / 128); rest > 0; rest = Math.floor(rest / 128)) {
      groups.unshift(0x80 | (rest & 0x7f));
    }
    octets.push(...groups);
  };
  encodeArc(arcs[0] * 40 + arcs[1]);
  for (let i = 2; i < arcs.length; i++) {
    encodeArc(arcs[i]);
  }
  return encodeTlv(0x06, Buffer.from(octets));
}

/** Decode a dotted OBJECT IDENTIFIER from `len` content bytes at `start`. */
export function decodeOid(buf: Buffer, start: number, len: number): string {
  const end = start + len;
  if (end > buf.length) {
    throw new Error('Truncated Object Identifier');
  }
  let pos = start;
  const nextArc = (): number => {
    let value = 0;
    for (;;) {
      if (pos >= end) {
        throw new Error('Truncated Object Identifier');
      }
      const octet = buf[pos++];
      value = value * 128 + (octet & 0x7f);
      if (!(octet & 0x80)) {
        return value;
      }
    }
  };

  const first = nextArc();
  const arc0 = first < 40 ? 0 : first < 80 ? 1 : 2;
  const arcs = [arc0, first - 40 * arc0];
  while (pos < end) {
    arcs.push(nextArc());
  }
  return arcs.join('.');
}

/** Encode `buf` as a DER OCTET STRING. */
export function encodeOctetString(buf: Buffer): Buffer {
  return encodeTlv(0x04, buf);
}

/** Encode `buf` as a DER BIT STRING with zero unused bits. */
export function encodeBitString(buf: Buffer): Buffer {
  return encodeTlv(0x03, Buffer.concat([Buffer.from([0x00]), buf]));
}

/** Encode a non-negative integer value as a DER INTEGER. */
export function encodeSmallInteger(value: number): Buffer {
  return encodeTlv(0x02, Buffer.from([value]));
}
