import { defineConfig } from 'tsup';

export default defineConfig({
    entry: ['src/index.ts'],
    format: ['cjs', 'esm'],
    dts: true,
    sourcemap: true,
    clean: true,
    target: 'node18',
    outExtension: ({ format }) => ({ js: format === 'cjs' ? '.cjs' : '.js' }),
});
