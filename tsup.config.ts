import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['./index.ts', './src/types/*.ts', './src/drivers/*.ts'],
  outDir: './build',
  clean: true,
  format: 'esm',
  dts: true,
  sourcemap: true,
  target: 'esnext',
})
