#!/usr/bin/env node
// Version single-source-of-truth propagator for the connectMWP monorepo.
//
// THE canonical version lives in ONE place: the repo-root `VERSION` file.
// npm requires the literal in each package.json and WordPress requires it in
// the plugin header, so the value cannot be read from one place at runtime —
// instead this script PROPAGATES the canonical value into every required
// literal, and `--check` GATES against drift so mismatched versions can never
// be committed (wired into the git pre-commit hook + the OPERATIONS release
// flow). Humans only ever edit `VERSION`.
//
// Usage:
//   node scripts/sync-version.mjs            # write canonical VERSION into all targets
//   node scripts/sync-version.mjs --check    # verify all targets match; exit 1 on drift
//
// Targets:
//   - connectmwp-mcp/package.json      (.version)
//   - connectmwp-server/package.json   (.version)
//   - connectmwp-agent/connectmwp-agent.php   (plugin header `Version:` line)
// The plugin no longer carries a second `const VERSION` literal — its UI reads
// the header at runtime via get_file_data(); the header is the plugin's only
// version source.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SEMVER = /^\d+\.\d+\.\d+$/;

const PKG_TARGETS = [
  'connectmwp-mcp/package.json',
  'connectmwp-server/package.json',
];
const PHP_TARGET = 'connectmwp-agent/connectmwp-agent.php';
// Matches the plugin docblock header line, e.g. " * Version: 2.0.24"
const PHP_HEADER_RE = /^(\s*\*\s*Version:\s*)(.+?)(\s*)$/m;

function fail(msg) {
  console.error(`[sync-version] ERROR: ${msg}`);
  process.exit(2);
}

function readCanonical() {
  let raw;
  try {
    raw = readFileSync(join(ROOT, 'VERSION'), 'utf8');
  } catch (e) {
    fail(`cannot read canonical VERSION file at repo root: ${e.message}`);
  }
  const version = raw.trim();
  if (!SEMVER.test(version)) {
    fail(`VERSION file must contain a single semver line (X.Y.Z); got: ${JSON.stringify(version)}`);
  }
  return version;
}

// Returns the version literal currently in a package.json target.
function readPkgVersion(rel) {
  const abs = join(ROOT, rel);
  let json;
  try {
    json = JSON.parse(readFileSync(abs, 'utf8'));
  } catch (e) {
    fail(`cannot parse ${rel}: ${e.message}`);
  }
  return json.version;
}

function writePkgVersion(rel, version) {
  const abs = join(ROOT, rel);
  const text = readFileSync(abs, 'utf8');
  const json = JSON.parse(text);
  if (json.version === version) return false;
  json.version = version;
  // Preserve 2-space indent + trailing newline (matches existing files).
  writeFileSync(abs, JSON.stringify(json, null, 2) + '\n');
  return true;
}

function readPhpVersion() {
  const abs = join(ROOT, PHP_TARGET);
  let text;
  try {
    text = readFileSync(abs, 'utf8');
  } catch (e) {
    fail(`cannot read ${PHP_TARGET}: ${e.message}`);
  }
  const m = text.match(PHP_HEADER_RE);
  if (!m) fail(`could not find a "Version:" header line in ${PHP_TARGET}`);
  return m[2].trim();
}

function writePhpVersion(version) {
  const abs = join(ROOT, PHP_TARGET);
  const text = readFileSync(abs, 'utf8');
  const m = text.match(PHP_HEADER_RE);
  if (!m) fail(`could not find a "Version:" header line in ${PHP_TARGET}`);
  if (m[2].trim() === version) return false;
  const next = text.replace(PHP_HEADER_RE, `$1${version}$3`);
  writeFileSync(abs, next);
  return true;
}

function currentTargets() {
  return [
    ...PKG_TARGETS.map((rel) => ({ file: rel, found: readPkgVersion(rel) })),
    { file: PHP_TARGET, found: readPhpVersion() },
  ];
}

const check = process.argv.includes('--check');
const version = readCanonical();

if (check) {
  const targets = currentTargets();
  const drifted = targets.filter((t) => t.found !== version);
  console.log(`[sync-version] canonical VERSION = ${version}`);
  for (const t of targets) {
    console.log(`  ${t.found === version ? 'OK  ' : 'DRIFT'}  ${t.file} = ${t.found}`);
  }
  if (drifted.length) {
    console.error(
      `[sync-version] DRIFT: ${drifted.length} target(s) != ${version}. ` +
      `Run \`node scripts/sync-version.mjs\` to fix.`
    );
    process.exit(1);
  }
  console.log('[sync-version] all targets match canonical VERSION.');
  process.exit(0);
}

// Write mode
let changed = 0;
for (const rel of PKG_TARGETS) {
  if (writePkgVersion(rel, version)) {
    console.log(`[sync-version] updated ${rel} -> ${version}`);
    changed++;
  }
}
if (writePhpVersion(version)) {
  console.log(`[sync-version] updated ${PHP_TARGET} header -> ${version}`);
  changed++;
}
console.log(
  changed
    ? `[sync-version] propagated ${version} to ${changed} file(s).`
    : `[sync-version] all targets already at ${version}; nothing to do.`
);
