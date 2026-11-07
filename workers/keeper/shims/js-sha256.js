//Eval-free SHA-256 shim for Cloudflare Workers (`nodejs_compat`)
const crypto = require('node:crypto');

function toBuf(input) {
  if (Buffer.isBuffer(input)) return input;
  if (input instanceof Uint8Array || Array.isArray(input)) return Buffer.from(input);
  if (input instanceof ArrayBuffer) return Buffer.from(new Uint8Array(input));
  return Buffer.from(String(input), 'utf8');
}

function sha256(message) {
  return crypto.createHash('sha256').update(toBuf(message)).digest('hex');
}

sha256.hex = sha256;
sha256.array = function (message) {
  return Array.from(crypto.createHash('sha256').update(toBuf(message)).digest());
};
sha256.digest = sha256.array;
sha256.arrayBuffer = function (message) {
  const buf = crypto.createHash('sha256').update(toBuf(message)).digest();
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
};
sha256.create = function () {
  const h = crypto.createHash('sha256');
  let digestBuf = null;
  const getBuf = () => {
    if (!digestBuf) digestBuf = h.digest();
    return digestBuf;
  };
  return {
    update(msg) {
      h.update(toBuf(msg));
      return this;
    },
    hex() {
      return getBuf().toString('hex');
    },
    toString() {
      return getBuf().toString('hex');
    },
    array() {
      return Array.from(getBuf());
    },
    digest() {
      return Array.from(getBuf());
    },
    arrayBuffer() {
      const b = getBuf();
      return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
    }
  };
};
sha256.sha256 = sha256;

module.exports = sha256;
