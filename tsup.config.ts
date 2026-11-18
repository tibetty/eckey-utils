import { defineConfig } from 'tsup';

export default defineConfig({
    entry: ['src/index.ts'],
    format: ['cjs', 'esm'],
    dts: true,
    sourcemap: true,
    clean: true,
    target: 'node22',
    outExtension: ({ format }) => ({ js: format === 'cjs' ? '.cjs' : '.js' }),
});
