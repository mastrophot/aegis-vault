import { Buffer } from 'node:buffer';

if (!globalThis.Buffer) {
  globalThis.Buffer = Buffer;
}

if (typeof globalThis.fetch === 'function' && !globalThis.__aegisFetchBound) {
  const nativeFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (input, init) => nativeFetch(input, init);
  globalThis.__aegisFetchBound = true;
}
