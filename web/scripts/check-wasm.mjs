// The browser verifier is a committed build artifact (web/public/wasm), so it can fall behind
// the trust core it was compiled from. Check that it accepts a current proof bundle; if this
// fails, rebuild it with `npm --prefix web run build:wasm` and commit the result.
//
// Usage: node web/scripts/check-wasm.mjs <bundle.json> [...]
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { initSync, verify_bundle } from '../public/wasm/ledger_wasm.js';

const wasm = fileURLToPath(new URL('../public/wasm/ledger_wasm_bg.wasm', import.meta.url));
initSync({ module: readFileSync(wasm) });

if (process.argv.length < 3) {
  console.error('usage: check-wasm.mjs <bundle.json> [...]');
  process.exit(2);
}

let failed = 0;
for (const path of process.argv.slice(2)) {
  const message = verify_bundle(readFileSync(path, 'utf8'));
  console.log(`${path}: ${message}`);
  if (!message.startsWith('VALID')) failed++;
}
process.exit(failed ? 1 : 0);
