// Encrypts private/content.html with a passcode and writes content.enc.js.
//
//   node build.mjs
//
// The passcode is read from a hidden prompt (or FLORIDA_PASSCODE for scripting).
// It is never written to disk. Only the encrypted output is meant to be committed.
import { webcrypto as crypto } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(fileURLToPath(import.meta.url));
const src = join(root, 'private', 'content.html');
const out = join(root, 'content.enc.js');
const ITERATIONS = 600_000;

const b64 = (buf) => Buffer.from(buf).toString('base64');

function promptHidden(label) {
  return new Promise((resolve) => {
    process.stdout.write(label);
    const stdin = process.stdin;
    let value = '';
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const onData = (ch) => {
      if (ch === '\r' || ch === '\n') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(value);
      } else if (ch === '\u0003') {
        process.exit(130);
      } else if (ch === '\u007f') {
        value = value.slice(0, -1);
      } else {
        value += ch;
      }
    };
    stdin.on('data', onData);
  });
}

if (!existsSync(src)) {
  console.error(`Missing ${src}. Put your private HTML there (it is gitignored).`);
  process.exit(1);
}

let pass = process.env.FLORIDA_PASSCODE;
if (!pass) {
  if (!process.stdin.isTTY) {
    console.error('No TTY and FLORIDA_PASSCODE not set.');
    process.exit(1);
  }
  pass = await promptHidden('Passcode: ');
  const again = await promptHidden('Repeat passcode: ');
  if (pass !== again) {
    console.error('Passcodes do not match.');
    process.exit(1);
  }
}
// Any length is accepted. Only very short passcodes get a (non-blocking) heads-up.
if (pass.length < 8) {
  console.warn(`Note: passcode is only ${pass.length} characters. The encrypted file is public, so very short passcodes are easy to guess offline.`);
}

const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
  material,
  { name: 'AES-GCM', length: 256 },
  false,
  ['encrypt']
);
const plaintext = new TextEncoder().encode(readFileSync(src, 'utf8'));
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);

const blob = { v: 1, iter: ITERATIONS, salt: b64(salt), iv: b64(iv), ct: b64(new Uint8Array(ct)) };
writeFileSync(out, `window.FLORIDA_ENC = ${JSON.stringify(blob)};\n`);
console.log(`Wrote ${out} (${plaintext.length} bytes of content encrypted).`);
