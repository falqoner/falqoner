/**
 * One realm for typed arrays in the jsdom tests (SAFE-02b).
 *
 * jsdom gives a test file its own `Uint8Array` and `ArrayBuffer`, while
 * `TextEncoder`, `Buffer` and WebAssembly in Node still make Node's. algosdk
 * checks `instanceof Uint8Array` when it encodes a transaction, and that
 * fails across the two - so a Falcon signature, whose scheme bytes come from
 * `TextEncoder`, could not be encoded. A browser has one realm, so the page
 * never meets this. Here Node's are used everywhere, as a browser would use
 * its own. In the Node environment this changes nothing.
 */
const nodeBytes = new TextEncoder().encode('');
const NodeUint8Array = Object.getPrototypeOf(nodeBytes).constructor as Uint8ArrayConstructor;
const NodeArrayBuffer = Object.getPrototypeOf(nodeBytes.buffer).constructor as ArrayBufferConstructor;
if (globalThis.Uint8Array !== NodeUint8Array) globalThis.Uint8Array = NodeUint8Array;
if (globalThis.ArrayBuffer !== NodeArrayBuffer) globalThis.ArrayBuffer = NodeArrayBuffer;
