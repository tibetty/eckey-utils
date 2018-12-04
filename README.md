# eckeyUtils

Node.js based EC key utilities to generate PEM keys (required by crypto.sign and crypto.verify) from the raw ones generated crypto.ECDH and to parse key info from given PEM content.

## Motivation

Namely the ECDH.generateKeys function should be used to generate EC keys for the key-exchange purpose, but actually the keys it generates are bare/raw ec private key (i.e., `*d*` in the cryptographic context) and ec public key (the relevant EC point, calculated from base point `*G*` and `*d*`), so supposedly there's no obstacle to use it in ECSDA scenario except that the crypto.Sign and crypto.Verify function doesn't support using raw key directly. This library will bridge this gap by converting raw keys to PEM keys.

On the other side, this library provide a symmetrical function to parses key info (private key PEM -> {privateKey, curveName, publicKey}, public key PEM -> {curveName, publicKey}) from given EC PEM contents, and such information can be used to initialize crypto.ECDH.

## CAUTION
Some people argue that use one key pair for both ECDH and ECDSA will compromise the security, so please try to avoid using one key-pair for both usages except that you know there's no negative byeffect.

## Usage

*Generate PEMs from raw keys*
```js
const crypto = require('crypto'), ecKeyUtils = require('eckey-utils');
const curveName = 'secp256k1';

const ecdh = crypto.createECDH(curveName);
ecdh.generateKeys();

const pemKeyPair = ecKeyUtils.generatePemKeys(curveName, {
	privateKey: ecdh.getPrivateKey(),
	publicKey: ecdh.getPublicKey()
});

const sign = crypto.createSign('sha256');
const message = Buffer.from('Hello, World!');
sign.update(message);
let sig = sign.sign(pemKeyPair.privateKey);

const verify = crypto.createVerify('sha256');
verify.update(message);
console.log(verify.verify(pemKeyPair.publicKey, sig));
```

*Parse Key Info from PEM*
```js
const ecKeyUtils = require('eckey-utils');
console.log(ecKeyUtils.parseKeyInfo(`-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBL1+Q5pDjC9ijZg/XCBhaJrV8pM+v/XgcwC53sWRFK69paB9zzVAD
ZqzrgXOAghxqWx0QEG8RhvXowXzMOuLmHz2gBwYFK4EEACOhgYkDgYYABAAlLIp1
uSSj9wjrpr4+9UitBXtEwB5AAS/PHyK/FLvM0Ybz0PDeg8RTqKXJziwz0i0AjvWp
FQSyuJe5PXesKhRzXQDqJQTijoekz5mWOdYLRnKln0B87JrXbpx+R0slrEJzPeHo
7fv+DaM09Dfvy30CLHhzaGqRpesz+rvPVKYCyun8EQ==`);
console.log(ecKeyUtils.parseKeyInfo(`-----BEGIN PUBLIC KEY-----
MD4wEAYHKoZIzj0CAQYFZysBBAkDKgAEgiGotjsUDWG11VFfkBsSoscOvrH27hjw
6bHXZwpyLjXW19Th2MRYGg==
-----END PUBLIC KEY-----`));
```

## Dependencies
Node.js version later than 5.x

## License
Written in 2018 by tibetty <xihua.duan@gmail.com>