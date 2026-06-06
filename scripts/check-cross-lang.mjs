#!/usr/bin/env node
// Cross-language SSOT drift gate for the connectMWP monorepo (T094).
//
// Several values/contracts are duplicated across PHP (plugin) and JS (MCP
// client) with NO compile-time link, so they drift silently (CLAUDE.md documents
// the discipline; this script ENFORCES it — same spirit as sync-version.mjs
// --check). Run in CI / pre-commit. Exit 0 = aligned, 1 = drift, 2 = parse error.
//
// Checks:
//   1. MEDIA_MAX_BYTES — the 10 MB upload cap. A split-brain cap means uploads
//      pass the client pre-check but hard-fail at the plugin (or vice versa).
//        client: connectmwp-mcp/lib/constants.js  (export const MEDIA_MAX_BYTES)
//        plugin: connectmwp-agent/connectmwp-agent.php (const MEDIA_MAX_BYTES)
//   2. MCP tool NAME set — the tool surface ChatGPT sees (PHP mcp_tool_definitions)
//      must match what stdio clients see (Node ListTools), EXCEPT the one
//      deliberate asymmetry: connectmwp_upload_media is multipart-only and is
//      intentionally OMITTED from the PHP definitions (ChatGPT cannot upload).
//
// NOTE: field-level inputSchema parity is not yet checked (PHP/JS shapes are
// awkward to diff reliably). Name-set + cap parity catch the common drift
// (added/renamed tool, changed cap). Extend here if a field-drift bug appears.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const JS_CONSTANTS = 'connectmwp-mcp/lib/constants.js';
const JS_INDEX     = 'connectmwp-mcp/index.js';
const PHP_PLUGIN   = 'connectmwp-agent/connectmwp-agent.php';

// Tools present in the Node surface but intentionally absent from the PHP
// (ChatGPT/remote) surface. Keep this list tight and justified.
const PHP_OMITTED_BY_DESIGN = new Set(['connectmwp_upload_media']);

let failed = false;
const problems = [];

function read(rel) {
  try {
    return readFileSync(join(ROOT, rel), 'utf8');
  } catch (e) {
    console.error(`[check-cross-lang] ERROR: cannot read ${rel}: ${e.message}`);
    process.exit(2);
  }
}

// Evaluate a SAFE integer arithmetic expression (digits, * / + - ( ) and spaces
// only). Used to compare `10 * 1024 * 1024` written in either language.
function safeEvalIntExpr(expr, where) {
  const cleaned = expr.trim();
  if (!/^[0-9*/+\-() ]+$/.test(cleaned)) {
    console.error(`[check-cross-lang] ERROR: refusing to evaluate non-arithmetic MEDIA_MAX_BYTES expr in ${where}: ${JSON.stringify(cleaned)}`);
    process.exit(2);
  }
  // eslint-disable-next-line no-new-func
  return Function(`"use strict"; return (${cleaned});`)();
}

// ---- Check 1: MEDIA_MAX_BYTES parity ------------------------------------
function mediaMaxBytes(rel, re) {
  const text = read(rel);
  const m = text.match(re);
  if (!m) {
    console.error(`[check-cross-lang] ERROR: could not find MEDIA_MAX_BYTES in ${rel}`);
    process.exit(2);
  }
  return safeEvalIntExpr(m[1], rel);
}
const jsCap  = mediaMaxBytes(JS_CONSTANTS, /export const MEDIA_MAX_BYTES\s*=\s*([^;]+);/);
const phpCap = mediaMaxBytes(PHP_PLUGIN, /\bconst MEDIA_MAX_BYTES\s*=\s*([^;]+);/);
if (jsCap !== phpCap) {
  failed = true;
  problems.push(`MEDIA_MAX_BYTES drift: client=${jsCap} (${JS_CONSTANTS}) != plugin=${phpCap} (${PHP_PLUGIN})`);
}

// ---- Check 2: MCP tool name-set parity ----------------------------------
function toolNames(rel, re) {
  const text = read(rel);
  const names = new Set();
  let m;
  while ((m = re.exec(text)) !== null) names.add(m[1]);
  return names;
}
const jsNames  = toolNames(JS_INDEX, /name:\s*['"](connectmwp_[a-z_]+)['"]/g);
const phpNames = toolNames(PHP_PLUGIN, /'name'\s*=>\s*'(connectmwp_[a-z_]+)'/g);

if (jsNames.size === 0 || phpNames.size === 0) {
  console.error(`[check-cross-lang] ERROR: parsed 0 tool names (js=${jsNames.size}, php=${phpNames.size}) — regex likely stale`);
  process.exit(2);
}

// Expected PHP set = JS set minus the by-design omissions.
const expectedPhp = new Set([...jsNames].filter((n) => !PHP_OMITTED_BY_DESIGN.has(n)));
const missingFromPhp = [...expectedPhp].filter((n) => !phpNames.has(n));
const extraInPhp     = [...phpNames].filter((n) => !expectedPhp.has(n));
// A tool that is omitted-by-design must NOT appear in PHP.
const omittedButPresent = [...PHP_OMITTED_BY_DESIGN].filter((n) => phpNames.has(n));

if (missingFromPhp.length) {
  failed = true;
  problems.push(`tools in Node but missing from PHP mcp_tool_definitions(): ${missingFromPhp.join(', ')}`);
}
if (extraInPhp.length) {
  failed = true;
  problems.push(`tools in PHP but not in Node index.js (or not allow-listed): ${extraInPhp.join(', ')}`);
}
if (omittedButPresent.length) {
  failed = true;
  problems.push(`tools marked omitted-by-design but PRESENT in PHP: ${omittedButPresent.join(', ')} (update PHP_OMITTED_BY_DESIGN or remove them)`);
}

// ---- Report -------------------------------------------------------------
console.log(`[check-cross-lang] MEDIA_MAX_BYTES: client=${jsCap} plugin=${phpCap} ${jsCap === phpCap ? 'OK' : 'DRIFT'}`);
console.log(`[check-cross-lang] tool names: node=${jsNames.size} php=${phpNames.size} (by-design Node-only: ${[...PHP_OMITTED_BY_DESIGN].join(', ') || 'none'}) ${failed ? 'DRIFT' : 'OK'}`);
if (failed) {
  console.error('[check-cross-lang] DRIFT DETECTED:');
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log('[check-cross-lang] all cross-language contracts aligned.');
process.exit(0);
