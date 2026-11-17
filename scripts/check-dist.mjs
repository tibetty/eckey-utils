/**
 * Guard the built package's import surface.
 *
 * The 0.7 line exposed one CommonJS object with seven functions. 1.0 publishes
 * named exports plus that object as the default, so every import style has to
 * keep working: `require()`, `require().default`, `import { … }` and
 * `import ecKeyUtils from …`.
 */
import { createECDH } from 'node:crypto';
import { createRequire } from 'node:module';

const FUNCTIONS = [
  'generateDer',
  'generateJwk',
  'generatePem',
  'parseJwk',
  'parsePem',
  'parsePkDer',
  'parseSkDer',
];

const failures = [];
const check = (condition, message) => {
  if (!condition) {
    failures.push(message);
  }
};

const cjs = createRequire(import.meta.url)('../dist/index.cjs');
const esm = await import('../dist/index.js');

for (const name of FUNCTIONS) {
  check(typeof cjs[name] === 'function', `require('eckey-utils').${name} is a function`);
  check(typeof cjs.default?.[name] === 'function', `require('eckey-utils').default.${name}`);
  check(typeof esm[name] === 'function', `import { ${name} } is a function`);
  check(typeof esm.default?.[name] === 'function', `import default .${name}`);
}

// The default export keeps the exact 0.7 shape: seven functions, nothing else.
check(
  Object.keys(cjs.default ?? {})
    .sort()
    .join() === [...FUNCTIONS].sort().join(),
  `default export exposes exactly ${FUNCTIONS.length} functions, got ${Object.keys(cjs.default ?? {}).join()}`
);

// Every entry point must agree, byte for byte, on real key material.
const ecdh = createECDH('prime256v1');
ecdh.generateKeys();
const { sk, pk } = { sk: ecdh.getPrivateKey(), pk: ecdh.getPublicKey() };
const digests = new Map();
for (const [label, api] of [
  ['require', cjs],
  ['require.default', cjs.default],
  ['import', esm],
  ['import.default', esm.default],
]) {
  const pair = api.generatePem('prime256v1', { sk, pk });
  digests.set(label, pair.privateKey);
}
check(new Set(digests.values()).size === 1, 'all entry points produce the same PEM');

if (failures.length > 0) {
  console.error('✖ package surface check failed:');
  for (const failure of failures) {
    console.error(`  - ${failure}`);
  }
  process.exit(1);
}
console.log(`✔ ${FUNCTIONS.length} functions reachable through require, default and named imports`);
