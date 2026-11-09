import { defineConfig } from 'vite';
import path from 'path';

const emptyChainStub = path.resolve(__dirname, 'src/empty-chain-stub.js');

export default defineConfig({
  resolve: {
    alias: [
      { find: 'chainsig.js', replacement: path.resolve(__dirname, 'node_modules/chainsig.js/browser/index.browser.js') },
      { find: /^viem(\/.*)?$/, replacement: emptyChainStub },
      { find: 'chain-registry', replacement: emptyChainStub },
      { find: /^@cosmjs\/.*/, replacement: emptyChainStub },
      { find: /^cosmjs-types\/.*/, replacement: emptyChainStub },
      { find: '@aptos-labs/ts-sdk', replacement: emptyChainStub },
      { find: /^@mysten\/.*/, replacement: emptyChainStub },
      { find: 'xrpl', replacement: emptyChainStub },
      { find: 'ripple-address-codec', replacement: emptyChainStub },
      { find: 'ripple-binary-codec', replacement: emptyChainStub }
    ]
  },
  build: {
    lib: {
      entry: path.resolve(__dirname, 'src/wallet-selector.js'),
      name: 'AegisWalletBundle',
      fileName: () => 'wallet-bundle.js',
      formats: ['iife']
    },
    outDir: path.resolve(__dirname, 'web'),
    emptyOutDir: false,
    minify: true
  },
  define: {
    'process.env.NODE_ENV': JSON.stringify('production'),
    'process.env': JSON.stringify({ NODE_ENV: 'production' }),
    'process.browser': true,
    'Buffer': 'window.Buffer',
    global: 'window'
  }
});
