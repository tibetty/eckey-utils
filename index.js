let ecKeyUtils = (() => {
      // the map of curveName and its oid
      const curveToOidMaps = {
            // ANSI X9.62 prime
            'prime192v1': '1.2.840.10045.3.1.1',
            'prime192v2': '1.2.840.10045.3.1.2',
            'prime192v3': '1.2.840.10045.3.1.3',
            'prime239v1': '1.2.840.10045.3.1.4',
            'prime239v2': '1.2.840.10045.3.1.5',
            'prime239v3': '1.2.840.10045.3.1.6',
            'prime256v1': '1.2.840.10045.3.1.7',
            
            // SEC-2 prime
            'secp112r1': '1.3.132.0.6',
            'secp112r2': '1.3.132.0.7',
            'secp128r1': '1.3.132.0.28',
            'secp128r2': '1.3.132.0.29',
            'secp160k1': '1.3.132.0.9',
            'secp160r1': '1.3.132.0.8',
            'secp160r2': '1.3.132.0.30',
            'secp192k1': '1.3.132.0.31',
            'secp224k1': '1.3.132.0.32',
            'secp224r1': '1.3.132.0.33',
            'secp256k1': '1.3.132.0.10',
            'secp384r1': '1.3.132.0.34',
            'secp521r1': '1.3.132.0.35',

            // SEC-2 binary
            'sect113r1': '1.3.132.0.4',
            'sect113r2': '1.3.132.0.5',
            'sect131r1': '1.3.132.0.22',
            'sect131r2': '1.3.132.0.23',
            'sect163k1': '1.3.132.0.1',
            'sect163r1': '1.3.132.0.2',
            'sect163r2': '1.3.132.0.15',
            'sect193r1': '1.3.132.0.24',
            'sect193r2': '1.3.132.0.25',
            'sect233k1': '1.3.132.0.26',
            'sect233r1': '1.3.132.0.27',
            'sect239k1': '1.3.132.0.3',
            'sect283k1': '1.3.132.0.16',
            'sect283r1': '1.3.132.0.17',
            'sect409k1': '1.3.132.0.36',
            'sect409r1': '1.3.132.0.37',
            'sect571k1': '1.3.132.0.38',
            'sect571r1': '1.3.132.0.39',

            // ECC brainpool
            'brainpoolP160r1': '1.3.36.3.3.2.8.1.1.1',
            'brainpoolP160t1': '1.3.36.3.3.2.8.1.1.2',
            'brainpoolP192r1': '1.3.36.3.3.2.8.1.1.3',
            'brainpoolP192t1': '1.3.36.3.3.2.8.1.1.4',
            'brainpoolP224r1': '1.3.36.3.3.2.8.1.1.5',
            'brainpoolP224t1': '1.3.36.3.3.2.8.1.1.6',
            'brainpoolP256r1': '1.3.36.3.3.2.8.1.1.7',
            'brainpoolP256t1': '1.3.36.3.3.2.8.1.1.8',
            'brainpoolP320r1': '1.3.36.3.3.2.8.1.1.9',
            'brainpoolP320t1': '1.3.36.3.3.2.8.1.1.10',
            'brainpoolP384r1': '1.3.36.3.3.2.8.1.1.11',
            'brainpoolP384t1': '1.3.36.3.3.2.8.1.1.12',
            'brainpoolP512r1': '1.3.36.3.3.2.8.1.1.13',
            'brainpoolP512t1': '1.3.36.3.3.2.8.1.1.14',
            
            // ANSI X9.62 binary
            'c2pnb163v1': '1.2.840.10045.3.0.1',
            'c2pnb163v2': '1.2.840.10045.3.0.2',
            'c2pnb163v3': '1.2.840.10045.3.0.3',
            'c2pnb176v1': '1.2.840.10045.3.0.4',
            'c2pnb208w1': '1.2.840.10045.3.0.10',
            'c2pnb272w1': '1.2.840.10045.3.0.16',
            'c2pnb304w1': '1.2.840.10045.3.0.17',
            'c2pnb368w1': '1.2.840.10045.3.0.19',
            'c2tnb191v1': '1.2.840.10045.3.0.5',
            'c2tnb191v2': '1.2.840.10045.3.0.6',
            'c2tnb191v3': '1.2.840.10045.3.0.7',
            'c2tnb239v1': '1.2.840.10045.3.0.11',
            'c2tnb239v2': '1.2.840.10045.3.0.12',
            'c2tnb239v3': '1.2.840.10045.3.0.13',
            'c2tnb359v1': '1.2.840.10045.3.0.18',
            'c2tnb431r1': '1.2.840.10045.3.0.20',

            // wap-wsg
            'wap-wsg-idm-ecid-wtls1': '2.23.43.1.4.1',
            'wap-wsg-idm-ecid-wtls10': '2.23.43.1.4.10',
            'wap-wsg-idm-ecid-wtls11': '2.23.43.1.4.11',
            'wap-wsg-idm-ecid-wtls12': '2.23.43.1.4.12',
            'wap-wsg-idm-ecid-wtls3': '2.23.43.1.4.3',
            'wap-wsg-idm-ecid-wtls4': '2.23.43.1.4.4',
            'wap-wsg-idm-ecid-wtls5': '2.23.43.1.4.5',
            'wap-wsg-idm-ecid-wtls6': '2.23.43.1.4.6',
            'wap-wsg-idm-ecid-wtls7': '2.23.43.1.4.7',
            'wap-wsg-idm-ecid-wtls8': '2.23.43.1.4.8',
            'wap-wsg-idm-ecid-wtls9': '2.23.43.1.4.9'
      };

      // Encoded bytes of algorithm (id-ecPublicKey: 1.2.840.10045.2.1) and version (1) in BER/DER format
      const ecAnV = Buffer.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);

      function encodeLength(l) {
            if (l < 0x80) {
                  return Buffer.from([l]);
            } else {
                  let t = [];
                  while (l > 0) {
                        t.push(0x80 | (l & 0x7f));
                        l >>= 7;
                  }
                  return Buffer.from(t.reverse());
            }
      }

      function encodeOid(oid) {
            if (!/^[012]{1}\.\d{1,2}(\.\d+)+$/g.test(oid))
                  throw Error('Invalid Object Identifier')

            let r = [], a = oid.split('.').map(v => parseInt(v));
            r.push(a[0] * 40 + a[1]);
            for (let i = 2; i < a.length; i++) {
                  let v = a[i];
                  let t = [];
                  t.push(v & 0x7f);
                  v >>= 7;
                  while (v > 0) {
                        t.push(0x80 | (v & 0x7f));
                        v >>= 7;
                  }
                  r = r.concat(t.reverse());
            }
            // ASN.1 OBJECT IDENTIFIER
            return Buffer.concat([Buffer.from([0x06]), encodeLength(r.length), Buffer.from(r)]);
      }


      function rawSkToPem(curve, sk, pk) {
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
            let ske = Buffer.concat([Buffer.from([0x04]), encodeLength(sk.length), sk]);
            // parameters [0] ECParameters {{ NamedCurve }} OPTIONAL
            let crve = curve;
            crve = Buffer.concat([Buffer.from([0xa0]), encodeLength(crve.length), crve]);
            // publicKey  [1] BIT STRING OPTIONAL
            // leading 0 means 0 bit(s) unused
            let pke = Buffer.concat([Buffer.from([0x00]), pk]);
            pke = Buffer.concat([Buffer.from([0x03]), encodeLength(pke.length), pke]);
            pke = Buffer.concat([Buffer.from([0xa1]), encodeLength(pke.length), pke])
            
            // version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1)
            let seqe = Buffer.concat([Buffer.from([0x02, 0x01, 0x01]), ske, crve, pke]);
            seqe = Buffer.concat([Buffer.from([0x30]), encodeLength(seqe.length), seqe]);
             
            return '-----BEGIN EC PRIVATE KEY-----\n' + 
                  seqe.toString('base64').replace(/.{64}/g, v => v + '\n').replace(/\n$/g, '') +
                  '\n-----END EC PRIVATE KEY-----';
      }

      function rawPkToPem(curve, pk) {
            // Generate ECC SubjectPublicKeyInfo @ rf5480 with simple Buffer concatenation
            /*
                 SubjectPublicKeyInfo  ::=  SEQUENCE  {
                        algorithm         AlgorithmIdentifier,
                        subjectPublicKey  BIT STRING
                 }
            */
            // algorithm         AlgorithmIdentifier
            let alge = curve;
            alge = Buffer.concat([Buffer.from([0x30]), encodeLength(ecAnV.length + alge.length), ecAnV, alge]);
            // subjectPublicKey  BIT STRING
            // leading 0 means 0 bit(s) unused
            let pke = Buffer.concat([Buffer.from([0x00]), pk]);
            pke = Buffer.concat([Buffer.from([0x03]), encodeLength(pke.length), pke]);

            let seqe = Buffer.concat([Buffer.from([0x30]), encodeLength(alge.length + pke.length), alge, pke]);
             
            return '-----BEGIN PUBLIC KEY-----\n' + 
                  seqe.toString('base64').replace(/.{64}/g, v => v + '\n').replace(/\n$/g, '') +
                  '\n-----END PUBLIC KEY-----';
      }

      return {
            generatePemKeys: (curveName, keyPair) => {
                  let curve = curveToOidMaps[curveName];
                  if (curve === null)
                        throw Error('Unsupported elliptic curve');
                  if (keyPair.publicKey.constructor.name !== 'Buffer' || keyPair.privateKey.constructor.name !== 'Buffer')
                        throw Error('Only supports raw keys in Buffer');

                  // To ensure the oid encoding happens once for all
                  if (curve.constructor.name !== 'Buffer') {
                        curveToOidMaps[curveName] = curve = encodeOid(curve);
                  }

                  return {
                        privateKey: rawSkToPem(curve, keyPair.privateKey, keyPair.publicKey),
                        publicKey: rawPkToPem(curve, keyPair.publicKey)
                  }
            }
      }
})();

module.exports = ecKeyUtils;
