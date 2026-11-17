#!/usr/bin/env node
/**
 * Pack the package, install it the way an integrator would, and use it.
 *
 * The suite runs against the source tree, where Node strips the types out of a
 * .ts file. It cannot see the failure that matters most at publish time: Node
 * refuses to strip types for anything under node_modules, so a package whose
 * exports point at its .ts sources throws
 * ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING on the consumer's first import.
 * Every test can pass while the published package cannot be loaded at all.
 *
 * There is a second thing only an install can check here. This package calls
 * intent-envelope's evaluate() at the centre of its decision path, and the
 * tests resolve that from this repo's node_modules. An installed copy resolves
 * it from the consumer's tree, against whatever version the range allows. If
 * the dependency is missing from package.json, or the range no longer matches a
 * published version, that breaks on install and nowhere earlier.
 *
 * Run: npm run smoke
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const PKG = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(readFileSync(join(PKG, 'package.json'), 'utf8'));

function exec(cmd, args, cwd, shell = false) {
  return execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], shell });
}

/**
 * On Windows `npm` is a .cmd shim, and since the fix for CVE-2024-27980 Node
 * refuses to spawn .cmd files without a shell. Going through npm's own entry
 * point with this Node binary avoids the shim.
 */
function npm(args, cwd) {
  if (process.env.npm_execpath) return exec(process.execPath, [process.env.npm_execpath, ...args], cwd);
  if (process.platform === 'win32') {
    return exec('npm.cmd', args.map(a => (/[\s"]/.test(a) ? `"${a}"` : a)), cwd, true);
  }
  return exec('npm', args, cwd);
}

const scratch = mkdtempSync(join(tmpdir(), 'sc-smoke-'));
let failed = false;
const check = (label, ok, detail = '') => {
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'}  ${label}\n`);
  if (!ok) { failed = true; if (detail) process.stdout.write(`        ${detail}\n`); }
};

try {
  process.stdout.write('packing...\n');
  const packed = npm(['pack', '--silent', '--pack-destination', scratch], PKG).trim().split('\n').pop();

  process.stdout.write(`installing ${packed} into a scratch directory...\n`);
  writeFileSync(join(scratch, 'package.json'), JSON.stringify({ name: 'smoke', private: true, type: 'module' }));
  npm(['install', '--silent', '--no-audit', '--no-fund', join(scratch, packed)], scratch);

  process.stdout.write('\nthe installed copy:\n');

  // Import the entry point and use it. Importing alone proves the module graph
  // loads, including intent-envelope; calling through proves it is not merely
  // parsed. digestOf and canonical are pure, so this needs no fixtures.
  const probe = join(scratch, 'probe.mjs');
  writeFileSync(probe, `
import * as api from '${manifest.name}';
const need = ['Supervisor', 'resolveFacts', 'EnvelopeStore', 'buildRecord', 'canonical',
              'digestOf', 'sign', 'verify', 'createSupervisorServer', 'VERSION'];
const missing = need.filter(n => !(n in api));
if (missing.length) { console.error('MISSING ' + missing.join(',')); process.exit(1); }

// canonical must be stable regardless of key order, which is what every
// signature over a record depends on.
const a = api.canonical({ b: 1, a: 2 });
const b = api.canonical({ a: 2, b: 1 });
if (a !== b) { console.error('CANONICAL-UNSTABLE'); process.exit(1); }
if (api.digestOf({ x: 1 }) !== api.digestOf({ x: 1 })) { console.error('DIGEST-UNSTABLE'); process.exit(1); }

// The envelope store has no write path at all, by design. Worth confirming the
// published copy kept that rather than only the one in this repo.
const store = new api.EnvelopeStore([]);
const writes = ['put', 'set', 'add', 'write', 'upsert', 'delete'].filter(m => typeof store[m] === 'function');
if (writes.length) { console.error('WRITE-PATH ' + writes.join(',')); process.exit(1); }

console.log('VERSION=' + api.VERSION);
`);
  let out = '';
  try {
    out = exec(process.execPath, [probe], scratch).trim();
    check('the package imports and resolves intent-envelope', true);
  } catch (e) {
    check('the package imports and resolves intent-envelope', false,
      `${e.stdout ?? ''}${e.stderr ?? ''}`.slice(0, 500));
  }
  if (out) {
    check('canonical JSON and digests are stable in the installed copy', !out.includes('UNSTABLE'));
    check('the envelope store still has no write path', !out.includes('WRITE-PATH'));
    const version = out.match(/VERSION=(.+)/)?.[1];
    check(`the exported VERSION matches package.json (${version} vs ${manifest.version})`,
      version === manifest.version,
      'VERSION is hand-written in src/index.ts and has drifted from the manifest');
  }

  check('the type declarations are in the tarball',
    npm(['pack', '--silent', '--dry-run', '--json'], PKG).includes('dist/index.d.ts'));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

process.stdout.write(failed ? '\nthe packaged install is broken\n' : '\nthe packaged install works\n');
process.exit(failed ? 1 : 0);
