// Browser version of the starter's lib.js (same function names and behaviour)
const enc = new TextEncoder(), dec = new TextDecoder();
export const stringToBuffer = (s) => enc.encode(s);
export const bufferToString = (b) => dec.decode(b);
export function encodeBuffer(buf) {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = ""; for (const c of u) s += String.fromCharCode(c);
  return btoa(s);
}
export function decodeBuffer(str) {
  const s = atob(str), u = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
  return u;
}
export const getRandomBytes = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
