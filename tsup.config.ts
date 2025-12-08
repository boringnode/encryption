import { defineConfig } from 'tsup'

export default defineConfig({
  entry: [
    './index.ts',
    './src/types/main.ts',
    './src/message_verifier.ts',
    './src/base64.ts',
    './factories/main.ts',
    './src/drivers/*.ts',
  ],
  outDir: './build',
  clean: true,
  format: 'esm',
  dts: true,
  sourcemap: true,
  target: 'esnext',
})
