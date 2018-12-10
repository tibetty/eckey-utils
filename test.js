const crypto = require('crypto'), ecKeyUtils = require('./index.js');
const curveNames = ['prime192v1', 'prime192v2', 'prime192v3', 'prime239v1', 'prime239v2', 'prime239v3', 'prime256v1', 'secp112r1', 'secp112r2', 'secp128r1', 'secp128r2', 'secp160k1', 'secp160r1', 'secp160r2', 'secp192k1', 'secp224k1', 'secp224r1', 'secp256k1', 'secp384r1', 'secp521r1', 'sect113r1', 'sect113r2', 'sect131r1', 'sect131r2', 'sect163k1', 'sect163r1', 'sect163r2', 'sect193r1', 'sect193r2', 'sect233k1', 'sect233r1', 'sect239k1', 'sect283k1', 'sect283r1', 'sect409k1', 'sect409r1', 'sect571k1', 'sect571r1', 'brainpoolP160r1', 'brainpoolP160t1', 'brainpoolP192r1', 'brainpoolP192t1', 'brainpoolP224r1', 'brainpoolP224t1', 'brainpoolP256r1', 'brainpoolP256t1', 'brainpoolP320r1', 'brainpoolP320t1', 'brainpoolP384r1', 'brainpoolP384t1', 'brainpoolP512r1', 'brainpoolP512t1', 'c2pnb163v1', 'c2pnb163v2', 'c2pnb163v3', 'c2pnb176v1', 'c2pnb208w1', 'c2pnb272w1', 'c2pnb304w1', 'c2pnb368w1', 'c2tnb191v1', 'c2tnb191v2', 'c2tnb191v3', 'c2tnb239v1', 'c2tnb239v2', 'c2tnb239v3', 'c2tnb359v1', 'c2tnb431r1', 'wap-wsg-idm-ecid-wtls1', 'wap-wsg-idm-ecid-wtls10', 'wap-wsg-idm-ecid-wtls11', 'wap-wsg-idm-ecid-wtls12', 'wap-wsg-idm-ecid-wtls3', 'wap-wsg-idm-ecid-wtls4', 'wap-wsg-idm-ecid-wtls5', 'wap-wsg-idm-ecid-wtls6', 'wap-wsg-idm-ecid-wtls7', 'wap-wsg-idm-ecid-wtls8', 'wap-wsg-idm-ecid-wtls9'];

for (let curveName of curveNames) {
      console.log(`------${curveName}------`);
      const ecdh = crypto.createECDH(curveName);
      ecdh.generateKeys();
      
      let privateKey = ecdh.getPrivateKey(),
            publicKey = ecdh.getPublicKey();

      let pem = ecKeyUtils.generatePem(curveName, {privateKey, publicKey});
      let sk = pem.privateKey;
      let keyInfo = ecKeyUtils.parsePem(sk);
      console.log('Equal Curve?', keyInfo.curveName === curveName);
      console.log('Equal PrivateKey?', (privateKey.compare(keyInfo.privateKey) === 0) && (keyInfo.privateKey.compare(privateKey) === 0));
      console.log('Equal PublicKey?', (publicKey.compare(keyInfo.publicKey) === 0) && (keyInfo.publicKey.compare(publicKey) === 0));

      pem = ecKeyUtils.generatePem({curveName, privateKey});
      sk = pem.privateKey;
      keyInfo = ecKeyUtils.parsePem(sk);
      console.log('Equal Curve?', keyInfo.curveName === curveName);
      console.log('Equal PrivateKey?', (privateKey.compare(keyInfo.privateKey) === 0) && (keyInfo.privateKey.compare(privateKey) === 0));
      
      pem = ecKeyUtils.generatePem({curveName, publicKey});
      pk = pem.publicKey;
      keyInfo = ecKeyUtils.parsePem(pk);
      console.log('Equal Curve?', keyInfo.curveName === curveName);
      console.log('Equal PublicKey?', (publicKey.compare(keyInfo.publicKey) === 0) && (keyInfo.publicKey.compare(publicKey) === 0));

      const sign = crypto.createSign('sha256');
      const message = Buffer.from('Hello, World!');
      sign.update(message);
      let sig = sign.sign(sk);

      const verify = crypto.createVerify('sha256');
      verify.update(message);
      console.log('Singature Passed Verification?', verify.verify(pk, sig));
}

for (let curveName of ['prime256v1', 'secp384r1', 'secp521r1']) {
      console.log(`------${curveName}------`);
      const ecdh = crypto.createECDH(curveName);
      ecdh.generateKeys();
            
      let privateKey = ecdh.getPrivateKey(),
            publicKey = ecdh.getPublicKey();

      let keys = ecKeyUtils.generateJwk(curveName, {privateKey, publicKey});
      let sk = keys.privateKey;
      let keyInfo = ecKeyUtils.parseJwk(sk);
      console.log('Equal Curve?', keyInfo.curveName === curveName);
      console.log('Equal PrivateKey?', (privateKey.compare(keyInfo.privateKey) === 0) && (keyInfo.privateKey.compare(privateKey) === 0));
      console.log('Equal PublicKey?', (publicKey.compare(keyInfo.publicKey) === 0) && (keyInfo.publicKey.compare(publicKey) === 0));

      keys = ecKeyUtils.generateJwk({curveName, publicKey});
      pk = keys.publicKey;
      keyInfo = ecKeyUtils.parseJwk(pk);
      console.log('Equal Curve?', keyInfo.curveName === curveName);
      console.log('Equal PublicKey?', (publicKey.compare(keyInfo.publicKey) === 0) && (keyInfo.publicKey.compare(publicKey) === 0));
}