// Ed25519 signing primitives for connectMWP MCP.
//
// Extracted from inline duplicates in `callWordPress` (REST) and
// `callWordPressAjax` (AJAX) during P5 step (ii) — T144 step ii of the
// modularization sequence. The canonical-builder and signing function are
// the byte-identical-with-PHP-plugin contract — any drift here breaks every
// signed request. Run `bash _internal/verify/interop_test.sh` after any
// change to this file.
//
// The canonical signing string format (v2.0.19+):
//
//     timestamp + "\n" + nonce + "\n" + METHOD + "\n" + path + "\n" +
//     sha256_hex(sorted_query) + "\n" + sha256_hex(body_or_empty)
//
// The plugin reconstructs the same six-field shape in
// `verify_request_signature` (connectmwp-agent/connectmwp-agent.php) — see
// _internal/ARCHITECTURE.md §4.3 for the authoritative spec.

import fs from 'fs/promises';
import crypto from 'crypto';

/**
 * Join the canonical parts with `'\n'`. Wrapped in a named function so the
 * byte-format invariant has a single place to read.
 *
 * @param {string[]} parts — exactly 6 strings as of v2.0.19:
 *   [timestamp, nonce, method, requestPath, queryHash, bodyHash]
 */
export function buildCanonical(parts) {
  return parts.join('\n');
}

/**
 * Read the Ed25519 private key PEM at `privateKeyPath`, sign `canonical`, and
 * return the base64-encoded 64-byte detached signature that the plugin's
 * `sodium_crypto_sign_verify_detached` expects.
 *
 * On failure, routes the diagnostic through `deps.logDiag` (full path + err
 * detail to operator stderr) and throws a sanitized user-facing error via
 * `deps.sanitizeSigningError` (no filesystem paths). The dependency-inject
 * pattern avoids a circular import to lib/errors.js (which will exist after
 * the next P5 step extracts the error helpers); for v2.0.23 the helpers stay
 * in index.js and crypto.js receives them as deps.
 *
 * @param {string} canonical — the joined canonical string
 * @param {string} privateKeyPath — absolute path to the per-site PEM
 * @param {{site: string, scope: 'REST'|'AJAX', action?: string}} ctx — diag context
 * @param {{sanitizeSigningError: (err: Error) => string, logDiag: (msg: string) => void}} deps
 */
export async function signCanonical(canonical, privateKeyPath, ctx, deps) {
  const { sanitizeSigningError, logDiag } = deps;
  try {
    const pem = await fs.readFile(privateKeyPath, 'utf-8');
    const privateKey = crypto.createPrivateKey(pem);
    const sigBuffer = crypto.sign(null, Buffer.from(canonical, 'utf-8'), privateKey);
    return sigBuffer.toString('base64');
  } catch (err) {
    const actionPart = ctx.action ? ` action=${ctx.action}` : '';
    logDiag(`${ctx.scope} signing failed keyPath=${privateKeyPath} site=${ctx.site}${actionPart} code=${err?.code ?? '<none>'} message=${err?.message ?? '<none>'}`);
    throw new Error(sanitizeSigningError(err));
  }
}
