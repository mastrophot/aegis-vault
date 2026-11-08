import { Buffer as BufferPolyfill } from "buffer";

if (typeof window !== "undefined") {
  window.Buffer = window.Buffer || BufferPolyfill;
  window.process = window.process || { env: { NODE_ENV: "production" }, browser: true };
  window.global = window;
  window.JS_SHA256_NO_NODE_JS = true;
}
if (typeof globalThis !== "undefined") {
  globalThis.Buffer = globalThis.Buffer || BufferPolyfill;
  globalThis.process = globalThis.process || { env: { NODE_ENV: "production" }, browser: true };
  globalThis.JS_SHA256_NO_NODE_JS = true;
}
