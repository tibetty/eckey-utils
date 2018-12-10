let ecKeyUtils = (() => {
      // the map of curveName and its oid
      const curveToOidMaps = {
            // ANSI X9.62 prime
            'prime192v1':	'1.2.840.10045.3.1.1',
            'prime192v2':	'1.2.840.10045.3.1.2',
            'prime192v3':	'1.2.840.10045.3.1.3',
            'prime239v1':	'1.2.840.10045.3.1.4',
            'prime239v2':	'1.2.840.10045.3.1.5',
            'prime239v3':	'1.2.840.10045.3.1.6',
            'prime256v1':	'1.2.840.10045.3.1.7',
            
            // SEC-2 prime
            'secp112r1':	'1.3.132.0.6',
            'secp112r2':	'1.3.132.0.7',
            'secp128r1':	'1.3.132.0.28',
            'secp128r2':	'1.3.132.0.29',
            'secp160k1':	'1.3.132.0.9',
            'secp160r1':	'1.3.132.0.8',
            'secp160r2':	'1.3.132.0.30',
            'secp192k1':	'1.3.132.0.31',
            'secp224k1':	'1.3.132.0.32',
            'secp224r1':	'1.3.132.0.33',
            'secp256k1':	'1.3.132.0.10',
            'secp384r1':	'1.3.132.0.34',
            'secp521r1':	'1.3.132.0.35',

            // SEC-2 binary
            'sect113r1':	'1.3.132.0.4',
            'sect113r2':	'1.3.132.0.5',
            'sect131r1':	'1.3.132.0.22',
            'sect131r2':	'1.3.132.0.23',
            'sect163k1':	'1.3.132.0.1',
            'sect163r1':	'1.3.132.0.2',
            'sect163r2':	'1.3.132.0.15',
            'sect193r1':	'1.3.132.0.24',
            'sect193r2':	'1.3.132.0.25',
            'sect233k1':	'1.3.132.0.26',
            'sect233r1':	'1.3.132.0.27',
            'sect239k1':	'1.3.132.0.3',
            'sect283k1':	'1.3.132.0.16',
            'sect283r1':	'1.3.132.0.17',
            'sect409k1':	'1.3.132.0.36',
            'sect409r1':	'1.3.132.0.37',
            'sect571k1':	'1.3.132.0.38',
            'sect571r1':	'1.3.132.0.39',

            // ECC brainpool
            'brainpoolP160r1':	'1.3.36.3.3.2.8.1.1.1',
            'brainpoolP160t1':	'1.3.36.3.3.2.8.1.1.2',
            'brainpoolP192r1':	'1.3.36.3.3.2.8.1.1.3',
            'brainpoolP192t1':	'1.3.36.3.3.2.8.1.1.4',
            'brainpoolP224r1':	'1.3.36.3.3.2.8.1.1.5',
            'brainpoolP224t1':	'1.3.36.3.3.2.8.1.1.6',
            'brainpoolP256r1':	'1.3.36.3.3.2.8.1.1.7',
            'brainpoolP256t1':	'1.3.36.3.3.2.8.1.1.8',
            'brainpoolP320r1':	'1.3.36.3.3.2.8.1.1.9',
            'brainpoolP320t1':	'1.3.36.3.3.2.8.1.1.10',
            'brainpoolP384r1':	'1.3.36.3.3.2.8.1.1.11',
            'brainpoolP384t1':	'1.3.36.3.3.2.8.1.1.12',
            'brainpoolP512r1':	'1.3.36.3.3.2.8.1.1.13',
            'brainpoolP512t1':	'1.3.36.3.3.2.8.1.1.14',
            
            // ANSI X9.62 binary
            'c2pnb163v1':	'1.2.840.10045.3.0.1',
            'c2pnb163v2':	'1.2.840.10045.3.0.2',
            'c2pnb163v3':	'1.2.840.10045.3.0.3',
            'c2pnb176v1':	'1.2.840.10045.3.0.4',
            'c2pnb208w1':	'1.2.840.10045.3.0.10',
            'c2pnb272w1':	'1.2.840.10045.3.0.16',
            'c2pnb304w1':	'1.2.840.10045.3.0.17',
            'c2pnb368w1':	'1.2.840.10045.3.0.19',
            'c2tnb191v1':	'1.2.840.10045.3.0.5',
            'c2tnb191v2':	'1.2.840.10045.3.0.6',
            'c2tnb191v3':	'1.2.840.10045.3.0.7',
            'c2tnb239v1':	'1.2.840.10045.3.0.11',
            'c2tnb239v2':	'1.2.840.10045.3.0.12',
            'c2tnb239v3':	'1.2.840.10045.3.0.13',
            'c2tnb359v1':	'1.2.840.10045.3.0.18',
            'c2tnb431r1':	'1.2.840.10045.3.0.20',

            // wap-wsg
            'wap-wsg-idm-ecid-wtls1':	'2.23.43.1.4.1',
            'wap-wsg-idm-ecid-wtls10':	'2.23.43.1.4.10',
            'wap-wsg-idm-ecid-wtls11':	'2.23.43.1.4.11',
            'wap-wsg-idm-ecid-wtls12':	'2.23.43.1.4.12',
            'wap-wsg-idm-ecid-wtls3':	'2.23.43.1.4.3',
            'wap-wsg-idm-ecid-wtls4':	'2.23.43.1.4.4',
            'wap-wsg-idm-ecid-wtls5':	'2.23.43.1.4.5',
            'wap-wsg-idm-ecid-wtls6':	'2.23.43.1.4.6',
            'wap-wsg-idm-ecid-wtls7':	'2.23.43.1.4.7',
            'wap-wsg-idm-ecid-wtls8':	'2.23.43.1.4.8',
            'wap-wsg-idm-ecid-wtls9':	'2.23.43.1.4.9'
      };

      const oidedToAnsi = {
            'prime256v1':	'P-256',
            'secp384r1':      'P-384',
            'secp521r1':      'P-521'
      };


      const oidToCurveMaps = {};
      for (let [k, v] of Object.entries(curveToOidMaps))
            oidToCurveMaps[v] = k;

      const ansiToOided = {};
      for (let [k, v] of Object.entries(oidedToAnsi))
            ansiToOided[v] = k;

      const id_ecPublicKey = encodeOid('1.2.840.10045.2.1');
 
      function encodeLength(l) {
            if (l < 0x80) {
                  return Buffer.from([l]);
            } else {
                  let t = [];
                  while (l > 0) {
                        t.unshift(0x80 | (l & 0x7f));
                        l >>= 7;
                  }
                  return Buffer.from(t);
            }
      }

      function decodeLength(buf, pos) {
            let v = buf[pos++];
            if (v < 0x80)
                  return [v, pos];

            let l = 0;
            while (v > 0x80) {
                  l = (l << 7) | (v & 0x7f);
                  v = buf[pos++];
            }

            // Need to go back one byte
            return [l, pos - 1];
      }

      function encodeOid(oid) {
            if (!/^[012]{1}\.\d{1,2}(\.\d+)+$/g.test(oid))
                  throw Error('Invalid Object Identifier');

            let r = [], a = oid.split('.').map(v => parseInt(v));
            r.unshift(a[0] * 40 + a[1]);
            for (let i = 2; i < a.length; i++) {
                  let v = a[i];
                  let t = [];
                  t.unshift(v & 0x7f);
                  v >>= 7;
                  while (v > 0) {
                        t.unshift(0x80 | (v & 0x7f));
                        v >>= 7;
                  }
                  r = r.concat(t);
            }

            // Add tag of OBJECT IDENTIFIER & length
            return Buffer.concat([Buffer.from([0x06]), encodeLength(r.length), Buffer.from(r)]);
      }

      function decodeOid(buf, s, l) {
            let e = s + l;
            let r = Math.floor(buf[s] / 40) + '.' + buf[s++] % 40;

            while (s < e) {
                  let next = 0, v = 0;
                  do {
                        v = buf[s++];
                        next = next << 7 | (v & 0x7f);
                  }  while ((v & 0x80) !== 0);
                  r += '.' + next;
            }
            return r;
      }

      function encodeDerToPem(tag, der) {
            return `-----BEGIN ${tag}-----\n${der.toString('base64').replace(/.{64}/g, v => v + '\n').replace(/\n$/g, '')}\n-----END ${tag}-----`;
      }

      function encodeSkToDer(curve, sk, pk) {
            // Generate ECPrivateKey @ rfc5915 with simple Buffer concatenation
            /*
            ECPrivateKey ::= SEQUENCE {
                  version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
                  privateKey     OCTET STRING,
                  parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
                  publicKey  [1] BIT STRING OPTIONAL
            }
            */
            // privateKey     OCTET STRING,
            let ske = Buffer.concat([Buffer.from([0x04]), encodeLength(sk.length), sk]);        // tag of OCTET STRING
            // parameters [0] ECParameters {{ NamedCurve }} OPTIONAL
            let crve = curve;
            crve = Buffer.concat([Buffer.from([0xa0]), encodeLength(crve.length), crve]);       // tag of [0]
            // publicKey  [1] BIT STRING OPTIONAL
            let pke = Buffer.from([]);
            if (pk) {
                  pke = Buffer.concat([Buffer.from([0x00]), pk]);                               // 0 bit(s) unused
                  pke = Buffer.concat([Buffer.from([0x03]), encodeLength(pke.length), pke]);    // tag of BIT STRING
                  pke = Buffer.concat([Buffer.from([0xa1]), encodeLength(pke.length), pke]);    // tag of [1]
            }
            
            // version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1)
            let seqe = Buffer.concat([Buffer.from([0x02, 0x01, 0x01]), ske, crve, pke]);        // version: tag of INTEGER | length = 1 | value = 1
            seqe = Buffer.concat([Buffer.from([0x30]), encodeLength(seqe.length), seqe]);       // tag of SEQUENCE

            return seqe;
      }

      function encodeSkToPem(curve, sk, pk) {
            return encodeDerToPem('EC PRIVATE KEY', encodeSkToDer(curve, sk, pk));
      }

      function encodePkToDer(curve, pk) {
            // Generate ECC SubjectPublicKeyInfo @ rf5480 with simple Buffer concatenation
            /*
                 SubjectPublicKeyInfo  ::=  SEQUENCE  {
                        algorithm         AlgorithmIdentifier,
                        subjectPublicKey  BIT STRING
                 }
            */
            // algorithm         AlgorithmIdentifier
            let alge = curve;
            alge = Buffer.concat([Buffer.from([0x30]), encodeLength(id_ecPublicKey.length + alge.length), id_ecPublicKey, alge]);   // tag of SEQUENCE
            // subjectPublicKey  BIT STRING
            
            let pke = Buffer.concat([Buffer.from([0x00]), pk]);                                                   // 0 bit(s) unused
            pke = Buffer.concat([Buffer.from([0x03]), encodeLength(pke.length), pke]);                            // tag of BIT STRING

            return Buffer.concat([Buffer.from([0x30]), encodeLength(alge.length + pke.length), alge, pke]);       // tag of SEQUENCE
      }

      function encodePkToPem(curve, pk) {
            return encodeDerToPem('PUBLIC KEY', encodePkToDer(curve, pk));
      }

      // parse the DER encoded data of ECPrivateKey
      function parseDer$Ecsk(buf) {
            const err = Error('Invalid DER encoding of ECPrivateKey');

            let r = {};
            
            let pos = 0;
            if (buf[pos++] != 0x30) throw err;

            // A quick location for the encoded version (INTEGER = 02 | length = 01 | value = 01) and the type tag (OCTET STRING = 04) of privateKey
            pos = buf.indexOf(Buffer.from('02010104', 'hex'));
            if (pos < 0) throw err;
            pos += 4;                                       // skip all those bytes

            let len = 0;
            [len, pos] = decodeLength(buf, pos);
            
            r.privateKey = buf.slice(pos, pos + len);
            pos += len;            
            if (buf[pos++] != 0xa0) throw err;              // tag of [0]

            [len, pos] = decodeLength(buf, pos);
            if (buf[pos++] != 0x06) throw err;              // tag of OBJECT IDENTIFIER

            [len, pos] = decodeLength(buf, pos);
            let oid = decodeOid(buf, pos, len);
            r.curveName = oidToCurveMaps[oid];
            pos += len;
            
            // parse optional publicKey if exists
            if (pos < buf.length) {
                  if (buf[pos++] != 0xa1) throw err;        // tag of [1]
                  
                  [len, pos] = decodeLength(buf, pos);

                  if (pos + len > buf.length) throw err;
                  if (buf[pos++] != 0x03) throw err;        // tag of BIT STRING

                  [len, pos] = decodeLength(buf, pos);
                  // remove the leading 0
                  r.publicKey = buf.slice(-(len - 1));      // decoded length - 1 byte for unused bit(s)
            }
            return r;
      }

      // parse the DER encoded data of SubjectPublicKeyInfo
      function parseDer$Spki(buf) {
            const err = Error('Invalid DER encoding of SubjectPublicKeyInfo');
            let r = {};

            let pos = 0;
            if (buf[pos++] != 0x30) throw err;              // tag of SEQUENCE

            // a quick search for algorithm
            pos = buf.indexOf(id_ecPublicKey);
            if (pos < 0) throw err;
            
            // skip algorithm section
            pos += 9;
            if (buf[pos++] != 0x06) throw err;              // tag of OBJECT IDENTIFIER
            let len = 0;
            [len, pos] = decodeLength(buf, pos);
            let oid = decodeOid(buf, pos, len);
            r.curveName = oidToCurveMaps[oid];
            pos += len;

            if (buf[pos++] != 0x03) throw err;              // tag of BIT STRING
            [len, pos] = decodeLength(buf, pos);

            if (pos + len > buf.length) throw err;
            // remove the leading 0
            r.publicKey = buf.slice(-(len - 1));            // decoded length - 1 byte for unused bit(s)
            return r;
      }

      function parseParams(cnOrAio, keyPair) {
            let cname = cnOrAio;
            let sk = null, pk = null;                  
            if (typeof cnOrAio == 'object') {
                  cname = cnOrAio.curveName;
                  sk = cnOrAio.privateKey;
                  pk = cnOrAio.publicKey;
            }

            if (keyPair) {
                  sk = sk? sk : keyPair.privateKey;
                  pk = pk? pk : keyPair.publicKey;
            }

            return {cname, sk, pk};
      }

      function base64UrlEncode(buf) {
            return buf.toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      }

      function base64UrlDecode(s) {
            return Buffer.from(s.replace(/\-/g, '+').replace(/_/g, '/'), 'base64');
      }

      return {
            generateDer: (arg1, arg2) => {
                  let {cname, sk, pk} = parseParams(arg1, arg2);
                  if (!cname)
                        throw Error('Curve name is not optional');
                  let curve = curveToOidMaps[cname];
                  if (curve === null)
                        throw Error('Unsupported elliptic curve');
                  
                  if (!sk && !pk)
                        throw Error('Either privateKey or publicKey is required');

                  if (sk && !(sk instanceof Buffer) || pk && !(pk instanceof Buffer))
                        throw Error('Only supports raw keys in Buffer');

                  // To ensure the oid encoding happens once for all
                  if (!(curve instanceof Buffer)) {
                        curveToOidMaps[cname] = curve = encodeOid(curve);
                  }

                  let result = {};

                  if (sk) result.privateKey = encodeSkToDer(curve, sk, pk);
                  if (pk) result.publicKey = encodePkToDer(curve, pk);
                  
                  return result;
            },

            parseSkDer: (der) => parseDer$Ecsk(der),


            parsePkDer: (der) => parseDer$Spki(der),


            generatePem: (arg1, arg2) => {
                  let {cname, sk, pk} = parseParams(arg1, arg2);
                  if (!cname)
                        throw Error('Curve name is not optional');
                  let curve = curveToOidMaps[cname];
                  if (curve === null)
                        throw Error('Unsupported elliptic curve');
                  
                  if (!sk && !pk)
                        throw Error('Either privateKey or publicKey is required');

                  if (sk && !(sk instanceof Buffer) || pk && !(pk instanceof Buffer))
                        throw Error('Only supports raw keys in Buffer');

                  // To ensure the oid encoding happens once for all
                  if (!(curve instanceof Buffer)) {
                        curveToOidMaps[cname] = curve = encodeOid(curve);
                  }

                  let result = {};

                  if (sk) result.privateKey = encodeSkToPem(curve, sk, pk);
                  if (pk) result.publicKey = encodePkToPem(curve, pk);
                  
                  return result;
            },
            
            parsePem: (pemContent) => {
                  if (!pemContent) throw Error('PEM content is not optional');

                  let s = null;
                  // DER encoding of ECPrivateKey
                  if (s = /^\-\-\-\-\-BEGIN EC PRIVATE KEY\-\-\-\-\-\n([^]+)\n\-\-\-\-\-END EC PRIVATE KEY\-\-\-\-\-$/g.exec(pemContent))
                        return parseDer$Ecsk(Buffer.from(s[1], 'base64'));
                  // DER encoding of SubjectPublicKeyInfo
                  else if (s = /^\-\-\-\-\-BEGIN PUBLIC KEY\-\-\-\-\-\n([^]+)\n\-\-\-\-\-END PUBLIC KEY\-\-\-\-\-$/g.exec(pemContent))
                        return parseDer$Spki(Buffer.from(s[1], 'base64'));
                  else
                        throw Error('Invalid PEM content');
            },

            generateJwk: (arg1, arg2) => {
                  let {cname, sk, pk} = parseParams(arg1, arg2);
                  let ansiName = oidedToAnsi[cname];
                  if (!ansiName)
                        throw Error("JWK doesn't support curves outside of P-256/384/521");

                  let result = {};
                  if (sk && pk) {
                        let privateKey = {kty: 'EC', crv: ansiName, key_ops: ['deriveBits', 'deriveKey', 'sign'], kid: 'JWK-sk generated by ecKeyUtils'};
                        if (pk[0] !== 0x04)
                              throw Error('Only support uncompressed public key');

                        let x = pk.slice(1, (pk.length - 1) / 2 + 1), y = pk.slice(-(pk.length - 1) / 2);
                        privateKey.x = base64UrlEncode(x);
                        privateKey.y = base64UrlEncode(y);
                        privateKey.d = base64UrlEncode(sk);
                        result.privateKey = privateKey;
                  } 

                  if (pk) {
                        let publicKey = {kty: 'EC', crv: ansiName, key_ops: ['verify'], kid: 'JWK-pk generated by ecKeyUtils'};
                        if (pk[0] !== 0x04)
                              throw Error('Only support uncompressed public key');

                        let x = pk.slice(1, (pk.length - 1) / 2 + 1), y = pk.slice(- (pk.length - 1) / 2);
                        publicKey.x = base64UrlEncode(x);
                        publicKey.y = base64UrlEncode(y);
                        result.publicKey = publicKey;
                  }

                  return result;
            },

            parseJwk: (jwk) => {
                  if (jwk.kty !== 'EC')
                        throw Error('Not an EC JSON Web Key');

                  let oidedName = ansiToOided[jwk.crv];
                  if (!oidedName)
                        throw Error("JWK doesn't support curves outside of P-256/384/521");

                  let r = {curveName: oidedName};
                  if (jwk.d) {
                        r.privateKey = base64UrlDecode(jwk.d);
                  }
                  r.publicKey = Buffer.concat([Buffer.from([0x04]), base64UrlDecode(jwk.x), base64UrlDecode(jwk.y)]);

                  return r;
            }
      }
})();

module.exports = ecKeyUtils;