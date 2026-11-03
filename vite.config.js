import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    lib: {
      entry: 'src/wallet-selector.js',
      name: 'AegisWalletBundle',
      fileName: () => 'wallet-bundle.js',
      formats: ['iife']
    },
    outDir: 'web',
    emptyOutDir: false,
    minify: true
  },
  define: {
    'process.env': {},
    global: 'window'
  }
});
