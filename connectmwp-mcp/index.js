#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import fs from 'fs/promises';
import { createReadStream, realpathSync } from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import http from 'http';
import https from 'https';
import { fileURLToPath } from 'url';
import {
  projectGetPosts,
  projectGetPost,
  projectMutatePost,
  projectDeletePost,
  projectUploadMedia,
  projectListTaxonomy,
  projectCreateTaxonomy,
} from './lib/projections.js';
import {
  MEDIA_MAX_BYTES,
  MEDIA_MAX_MB,
  ALLOWED_EXTENSIONS,
  FALLBACK_VERSION,
} from './lib/constants.js';
import { buildCanonical, signCanonical } from './lib/crypto.js';
import { isPrivateIp, validateImageUrl, validateImageMagicNumbers } from './lib/validators.js';

// Configuration file path
const CONFIG_PATH = path.join(os.homedir(), '.connectmwp.json');

// Single canonical message returned to the LLM client when a tool fails with an
// unrecognized error class. Operator detail goes to stderr via logDiag; the LLM
// only ever sees this generic string (T040). Defined once (no-hardcoding SSOT).
const GENERIC_TOOL_ERROR = 'Tool execution failed — see local connectMWP diagnostics (stderr).';

/**
 * Clean and normalize site URLs
 */
function normalizeSiteUrl(url) {
  if (!url) return '';
  let clean = url.trim().replace(/\/$/, '');
  if (!/^https?:\/\//i.test(clean)) {
    clean = 'https://' + clean;
  }
  
  if (/^http:\/\//i.test(clean)) {
    try {
      const hostname = new URL(clean).hostname;
      const isLocal = hostname === 'localhost' || 
                      hostname === '127.0.0.1' || 
                      hostname === '::1' || 
                      hostname.endsWith('.local') || 
                      hostname.endsWith('.test');
      if (!isLocal) {
        throw new Error('Plaintext HTTP connections are only allowed for local targets (localhost, .local, .test). HTTPS is required for remote sites.');
      }
    } catch (e) {
      if (e.message && e.message.includes('Plaintext HTTP')) {
        throw e;
      }
    }
  }
  return clean;
}

/**
 * Load settings from the local configuration file. Also opportunistically
 * tightens perms on both the config file (0600) and the private-key
 * directory (0700) to upgrade pre-v2.0.21 installs in place — silent on
 * already-tight installs, single stderr log line on each tightening.
 */
/**
 * SSOT classifier for config-read failures (T044). Distinguishes the three
 * cases that readConfig must treat differently (R8 — no silent failures, but
 * a missing file on first run is EXPECTED and must stay silent):
 *   'missing'    — ENOENT: file genuinely absent (first run). Silent, expected.
 *   'corrupt'    — SyntaxError from JSON.parse: file exists but is unparseable.
 *   'unreadable' — EACCES / EPERM / other I/O: file exists but cannot be read.
 * One classification feeds both the diag line and the human CLI notice (no
 * scattered instanceof / code checks).
 */
function classifyReadError(error) {
  if (error && error.code === 'ENOENT') return 'missing';
  if (error instanceof SyntaxError) return 'corrupt';
  return 'unreadable';
}

async function readConfig() {
  let data;
  try {
    data = await fs.readFile(CONFIG_PATH, 'utf-8');
    // Best-effort tightening on existing installs. Failure must not break
    // the read path — tightenPathPerms already swallows ENOENT and logs
    // other errors via [connectmwp:diag] without throwing.
    await tightenPathPerms(CONFIG_PATH, 0o600);
    await tightenPathPerms(path.join(os.homedir(), '.connectmwp'), 0o700);
  } catch (error) {
    // ENOENT (first run) is expected — stay silent. EACCES / other I/O is a
    // real failure — log to stderr before returning the safe empty fallback.
    const kind = classifyReadError(error); // 'missing' | 'unreadable'
    if (kind !== 'missing') {
      logDiag(`config-read-error kind=${kind} code=${error && error.code ? error.code : '<none>'} message=${error && error.message ? error.message : String(error)}`);
    }
    return { defaultSite: '', sites: {} };
  }
  try {
    const cfg = JSON.parse(data);
    if (!cfg.sites) cfg.sites = {};
    if (!cfg.defaultSite) cfg.defaultSite = '';
    return cfg;
  } catch (error) {
    // Corrupt JSON: the file is on disk but unparseable. Never silently hide
    // the user's paired sites as "no sites" — log AND tag the fallback so the
    // CLI command blocks can print an explicit human notice (noticeIfCorrupt).
    logDiag(`config-corrupt path=${CONFIG_PATH} message=${error && error.message ? error.message : String(error)}`);
    const fallback = { defaultSite: '', sites: {} };
    Object.defineProperty(fallback, '__corrupt', { value: true, enumerable: false });
    return fallback;
  }
}

/**
 * Print a clear, actionable stderr notice if the config was corrupt (T044).
 * SSOT for the message; CLI command blocks call this once after readConfig so
 * a corrupt file never masquerades as "no sites configured" without a trace.
 * stderr is safe for human notices (CLI terminal); never the LLM transcript.
 */
function noticeIfCorrupt(cfg) {
  if (cfg && cfg.__corrupt) {
    process.stderr.write('connectMWP: ~/.connectmwp.json is present but unreadable (invalid JSON). Your paired sites are NOT lost — fix or restore the file. See the [connectmwp:diag] line above for details.\n');
  }
}

/**
 * Save settings to the local configuration file. mode option only applies on
 * CREATE; the post-write chmod covers the overwrite-existing case so perms
 * are correct after every write regardless of prior state.
 */
async function writeConfig(config) {
  await fs.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2), { encoding: 'utf-8', mode: 0o600 });
  await tightenPathPerms(CONFIG_PATH, 0o600);
}

// ============================================================================
// ERROR HANDLING — sanitization + diagnostics
// ============================================================================
// AUDIT POLICY: any `throw new Error(...)` whose message would include a
// filesystem path, private-key bytes, or other internal state MUST funnel
// through sanitizeSigningError() (user-facing) + logDiag() (operator-facing).
// As of v2.0.19 the only Class-A throw sites are the two signing catches in
// callWordPress and callWordPressAjax. All other throws were audited and
// classified safe (Class B: user-supplied values; Class C: constant strings).
// See _internal/PLAN_T138_2026-05-28_21-26-39.md §4 for the full survey.

function sanitizeSigningError(err) {
  const code = err?.code;
  if (code === 'ENOENT') {
    return 'Failed to sign request — private key file not found. Re-pair the site with: npx -y connectmwp-mcp add-site --enroll "<site_url>,<pairing_code>" (generate the pairing code from WP Admin → Settings → connectMWP → Generate Pairing Code).';
  }
  if (code === 'EACCES' || code === 'EPERM') {
    return 'Failed to sign request — private key file not readable (permission denied). Verify the connectMWP key directory is owned by your user. If unrecoverable, re-pair with: npx -y connectmwp-mcp add-site --enroll "<site_url>,<pairing_code>".';
  }
  return 'Failed to sign request — private key could not be parsed. The keystore may be corrupted. Re-pair with: npx -y connectmwp-mcp add-site --enroll "<site_url>,<pairing_code>".';
}

/**
 * SSOT mapper: convert any caught tool-dispatch error into a SAFE client-facing
 * string (T040). The catch-all's lone return site calls this; no inline message
 * logic lives anywhere else. Allowlist, first match wins:
 *   1. signing errors (`__signing`) delegate to sanitizeSigningError (keep the
 *      signing vocabulary owned by its existing SSOT — compose, don't duplicate).
 *   2. `Unknown tool:` passes through verbatim (names a tool, no sensitive
 *      content; preserves the useful default-case signal).
 *   3. everything else collapses to GENERIC_TOOL_ERROR — no raw message, stack,
 *      or fs path ever reaches the LLM transcript.
 */
function toClientErrorMessage(error) {
  if (error && error.__signing) return sanitizeSigningError(error);
  const m = error && typeof error.message === 'string' ? error.message : '';
  if (m.startsWith('Unknown tool:')) return m;
  return GENERIC_TOOL_ERROR;
}

function logDiag(msg) {
  // Stderr is structurally separate from MCP stdio's JSON-RPC stdout channel
  // (verified against @modelcontextprotocol/sdk StdioServerTransport — stdout
  // is JSON-RPC exclusive; stderr is captured by the client as an out-of-band
  // log stream, never parsed as protocol traffic). Safe to write here.
  try {
    process.stderr.write(`[connectmwp:diag] ${new Date().toISOString()} ${msg}\n`);
  } catch {
    // Best-effort; never throws back into the caller's path even if stderr is
    // unavailable (closed, redirected, EBADF).
  }
}

/**
 * Tighten POSIX perms on a file or directory to `expectedMode`, idempotently.
 * Silent no-op on Windows (NTFS doesn't honor POSIX mode bits; ACL-based
 * permissions are out of scope). Used to upgrade pre-v2.0.21 installs from
 * 0644/0755 to 0600/0700 on the next tool invocation.
 */
async function tightenPathPerms(targetPath, expectedMode) {
  if (process.platform === 'win32') return;
  try {
    const stat = await fs.stat(targetPath);
    const currentMode = stat.mode & 0o777;
    if (currentMode === expectedMode) return; // already tight; silent.
    await fs.chmod(targetPath, expectedMode);
    logDiag(`tightened perms on ${targetPath} from ${currentMode.toString(8)} to ${expectedMode.toString(8)}`);
  } catch (err) {
    // ENOENT = file doesn't exist yet (fresh install) — expected; silent.
    // EPERM / EACCES = user owns something we can't touch — log + continue.
    if (err && err.code !== 'ENOENT') {
      logDiag(`could not tighten perms on ${targetPath}: code=${err?.code ?? '<none>'} message=${err?.message ?? '<none>'}`);
    }
  }
}

// ============================================================================
// MEDIA HANDLING — streaming + DNS-rebinding-resistant fetch
// ============================================================================
// MEDIA_MAX_BYTES + MEDIA_MAX_MB + ALLOWED_EXTENSIONS now live in
// lib/constants.js (extracted in v2.0.23). Imported at top of file.

/**
 * Drain any iterable byte source (Node Readable OR Web ReadableStream) into a
 * Buffer, aborting the source the moment cumulative bytes exceed maxBytes.
 *
 * Closes the underlying resource (socket, fd) immediately on overflow rather
 * than waiting for GC — critical for the hostile-stream defense (T139).
 */
async function streamToCappedBuffer(stream, maxBytes) {
  const chunks = [];
  let total = 0;
  try {
    for await (const chunk of stream) {
      total += chunk.length;
      if (total > maxBytes) {
        // Tear down source eagerly so the underlying socket/fd is released
        // (don't wait for GC).
        if (typeof stream.destroy === 'function') {
          stream.destroy();
        } else if (typeof stream.cancel === 'function') {
          try { await stream.cancel(); } catch { /* best-effort */ }
        }
        throw new Error(`Image size exceeds the maximum limit of ${MEDIA_MAX_MB}MB.`);
      }
      chunks.push(chunk);
    }
  } catch (err) {
    // Ensure cleanup on any iteration error (network reset, FS errors, etc.).
    if (typeof stream.destroy === 'function') {
      try { stream.destroy(); } catch { /* best-effort */ }
    }
    throw err;
  }
  return Buffer.concat(chunks);
}

/**
 * Open an HTTP(S) request whose TCP connect target is pinned to the
 * pre-validated IP. SNI uses the URL's hostname (unchanged), so TLS cert
 * validation works naturally. Closes the DNS-rebinding window between
 * validation and connect that v2.0.19's bare `fetch(image_url)` left open.
 *
 * Returns a Node Readable IncomingMessage stream on success. Rejects on
 * redirect (status 3xx) — matches the v2.0.19 SSRF guard's redirect:'manual'
 * behavior. Rejects on 4xx/5xx with the generic failure message.
 */
async function pinnedHttpsGet(urlObj, validatedIp, family) {
  return new Promise((resolve, reject) => {
    const mod = urlObj.protocol === 'https:' ? https : http;
    const port = urlObj.port
      ? parseInt(urlObj.port, 10)
      : (urlObj.protocol === 'https:' ? 443 : 80);

    const req = mod.request({
      hostname: urlObj.hostname,
      port,
      path: (urlObj.pathname || '/') + (urlObj.search || ''),
      method: 'GET',
      // Pin DNS: lookup is called instead of the system resolver. The
      // pre-validated IP is the connect target regardless of what DNS would
      // say at this moment (defeats rebind between validation and connect).
      // Honors both dns.lookup shapes — single-address callback when opts.all
      // is falsy, array-callback when opts.all is true. Node's http.request
      // uses the single form, but some Node versions / agents request `all`.
      lookup: (_hostname, opts, cb) => {
        if (opts && opts.all) {
          cb(null, [{ address: validatedIp, family }]);
        } else {
          cb(null, validatedIp, family);
        }
      },
      // SNI: ensures TLS handshake presents the original hostname so the
      // server's certificate matches and cert validation succeeds.
      servername: urlObj.hostname,
      headers: {
        'User-Agent': 'connectmwp-mcp',
        'Accept': '*/*',
      },
    }, (res) => {
      const status = res.statusCode || 0;
      if (status >= 300 && status < 400) {
        res.resume();
        reject(new Error(`SSRF Block: Redirects are not allowed during image download (${status}).`));
        return;
      }
      if (status >= 400) {
        res.resume();
        reject(new Error(`Failed to download image from URL: ${urlObj.toString()}`));
        return;
      }
      resolve(res);
    });
    req.on('error', reject);
    req.setTimeout(30_000, () => {
      req.destroy(new Error('Image download timed out after 30s.'));
    });
    req.end();
  });
}

/**
 * Retrieve credentials for the selected target site
 */
async function getCredentials(requestedSite) {
  const config = await readConfig();
  
  let targetSite = '';
  if (requestedSite) {
    targetSite = normalizeSiteUrl(requestedSite);
  } else {
    targetSite = config.defaultSite;
  }
  
  if (!targetSite) {
    throw new Error('No WordPress site configured. Run "npx connectmwp-mcp add-site --enroll <enrollment_string>" in your terminal first.');
  }

  // Attempt direct lookup
  let siteConfig = config.sites && config.sites[targetSite];

  // Try matching domain names if the protocols/slashes differ slightly
  if (!siteConfig && requestedSite) {
    try {
      const requestedHost = new URL(normalizeSiteUrl(requestedSite)).hostname;
      const matchedKey = Object.keys(config.sites || {}).find(k => {
        try {
          return new URL(k).hostname === requestedHost;
        } catch {
          return false;
        }
      });
      if (matchedKey) {
        targetSite = matchedKey;
        siteConfig = config.sites[matchedKey];
      }
    } catch {
      // Fallback to raw check
    }
  }
  
  if (!siteConfig) {
    throw new Error(`WordPress site "${targetSite}" is not configured. Configure it first using "npx connectmwp-mcp add-site --enroll <enrollment_string>".`);
  }
  
  if (siteConfig.token) {
    throw new Error(`WordPress site "${targetSite}" is configured with a v1 token. Please re-enroll it using "npx connectmwp-mcp add-site --enroll <enrollment_string>".`);
  }
  
  return { 
    siteUrl: targetSite, 
    keyId: siteConfig.key_id, 
    privateKeyPath: siteConfig.private_key_path 
  };
}

/**
 * Render a friendly summary after a successful pairing. Uses the /whoami round-trip
 * response when available (proves end-to-end signing works), else falls back to the
 * /enroll response. Either way the shape is the same per the plugin's build_identity_payload.
 */
function printPairingSummary(identity, ctx) {
  const site = identity && identity.site ? identity.site : { title: ctx.siteUrl, url: ctx.siteUrl };
  const user = identity && identity.user ? identity.user : {};
  const caps = identity && identity.capabilities ? identity.capabilities : {};
  const label = (identity && identity.label) || ctx.labelUsed;

  // Friendly capability list (only the verbs the user actually has).
  const capLabels = [];
  if (caps.edit_posts) capLabels.push('read & draft posts');
  if (caps.publish_posts) capLabels.push('publish posts');
  if (caps.edit_others_posts) capLabels.push('edit other authors\' posts');
  if (caps.delete_posts) capLabels.push('delete posts');
  if (caps.upload_files) capLabels.push('upload media');
  if (caps.manage_categories) capLabels.push('manage categories & tags');

  const userDisplay = user.display_name || user.login || 'unknown';
  const userLogin = user.login ? ` (${user.login})` : '';
  const roles = Array.isArray(user.roles) && user.roles.length ? user.roles.join(', ') : 'no role';

  console.log('');
  console.log(`✓ Connected to "${site.title}" (${site.url})`);
  console.log(`✓ Acting as: ${userDisplay}${userLogin} — ${roles}`);
  if (capLabels.length) {
    console.log(`✓ Can: ${capLabels.join(', ')}`);
  } else {
    console.log(`✓ Can: (no content capabilities — pair from an Administrator or Editor account to enable tools)`);
  }
  console.log(`✓ Key ID: ${ctx.keyId}`);
  console.log(`✓ Label: ${label}`);
  if (ctx.isDefaultSite) {
    console.log(`✓ Set as default site.`);
  }
  if (!ctx.roundTripOk) {
    console.log('');
    console.log('⚠ Round-trip /whoami check did not return success. The key was stored on the site,');
    console.log('  but signing did not validate end-to-end. If subsequent tools fail, re-pair.');
  }
  console.log('');
  // ChatGPT uses a separate token-based connector — see the WP Admin "Connect ChatGPT" card.
  console.log('Test it in your AI client (Claude / Cursor / Antigravity):');
  console.log(`  "List the tags on ${new URL(ctx.siteUrl).hostname} using connectMWP"`);
  console.log('');
  console.log('Adding another AI client on this Mac? Register the same MCP server: `npx -y connectmwp-mcp`.');
  console.log('All AI clients on this user account share this pairing — no extra code needed.');
  console.log('(ChatGPT connects via a token from the WP Admin "Connect ChatGPT" card, not this command.)');
}

// ============================================================================
// CLI MANAGEMENT COMMANDS
// ============================================================================
const args = process.argv.slice(2);
const command = args[0];

if (command === 'add-site') {
  let site = '';
  let token = '';
  let enroll = '';
  let label = '';
  let isDefault = false;

  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--site' && args[i + 1]) {
      site = args[i + 1];
    } else if (args[i] === '--token' && args[i + 1]) {
      token = args[i + 1];
    } else if (args[i] === '--enroll' && args[i + 1]) {
      enroll = args[i + 1];
    } else if (args[i] === '--label' && args[i + 1]) {
      label = args[i + 1];
    } else if (args[i] === '--default') {
      isDefault = true;
    }
  }

  if (enroll) {
    // New enrollment flow
    const parts = enroll.includes(',') ? enroll.split(',') : enroll.split('|');
    if (parts.length < 2) {
      console.error('Error: Invalid enrollment string format. Must be "site_url,enrollment_code" or "site_url|enrollment_code".');
      process.exit(1);
    }
    const siteUrl = normalizeSiteUrl(parts[0]);
    const enrollCode = parts[1];

    console.log(`[INFO] Initiating Ed25519 pairing with WordPress site: ${siteUrl}`);
    
    // Generate Ed25519 keypair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });

    // Store private key securely
    const host = new URL(siteUrl).hostname;
    const privateKeyDir = path.join(os.homedir(), '.connectmwp');
    const privateKeyPath = path.join(privateKeyDir, `${host}.ed25519`);
    // Write the new key to a temp path first; only replace any existing key for
    // this site AFTER enrollment succeeds. Prevents a failed re-pair (e.g. an
    // expired pairing code) from destroying a working key.
    const tmpKeyPath = `${privateKeyPath}.tmp-${process.pid}`;

    try {
      // mode 0o700 on create; tightenPathPerms covers the existing-directory
      // case (mkdir's mode option is ignored when the directory exists).
      await fs.mkdir(privateKeyDir, { recursive: true, mode: 0o700 });
      await tightenPathPerms(privateKeyDir, 0o700);
      await fs.writeFile(tmpKeyPath, privateKeyPem, { encoding: 'utf-8', mode: 0o600 });
      await fs.chmod(tmpKeyPath, 0o600);
    } catch (err) {
      console.error(`[ERROR] Failed to save private key: ${err.message}`);
      process.exit(1);
    }

    // Export raw 32-byte public key (last 32 bytes of DER SPKI format) to base64
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const rawPublicKey = spkiDer.subarray(-32);
    const pubKeyBase64 = rawPublicKey.toString('base64');

    // Post public key to WordPress agent
    const enrollUrl = `${siteUrl}/wp-json/connectmwp/v1/enroll`;
    const payload = {
      public_key: pubKeyBase64,
      label: label || `Local client (${os.hostname()})`
    };

    try {
      const response = await fetch(enrollUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-ConnectMWP-Enroll-Code': enrollCode
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        let errMsg = `HTTP ${response.status}`;
        try {
          const errData = await response.json();
          errMsg = errData.error || errData.message || errMsg;
        } catch {}
        throw new Error(errMsg);
      }

      const resData = await response.json();
      if (!resData.success || !resData.key_id) {
        throw new Error('Plugin enrollment response did not return a key ID.');
      }

      // Enrollment confirmed — only now move the new key into place, replacing
      // any prior key for this site.
      await fs.rename(tmpKeyPath, privateKeyPath);

      const config = await readConfig();
      noticeIfCorrupt(config);
      config.sites = config.sites || {};
      config.sites[siteUrl] = {
        key_id: resData.key_id,
        private_key_path: privateKeyPath,
        label: label || host,
        updated: new Date().toISOString()
      };

      if (isDefault || !config.defaultSite) {
        config.defaultSite = siteUrl;
      }

      await writeConfig(config);

      // Round-trip test using the newly-stored key — proves end-to-end signing
      // works against the site (not just that enrollment stored the key).
      let identity = resData;
      let roundTripOk = true;
      process.stdout.write('[INFO] Verifying signed round-trip… ');
      try {
        const whoami = await callWordPress(siteUrl, resData.key_id, privateKeyPath, 'whoami', 'GET');
        if (whoami && whoami.success) {
          identity = whoami;
          process.stdout.write('ok\n');
        } else {
          roundTripOk = false;
          process.stdout.write('warn — using enroll response\n');
        }
      } catch (err) {
        roundTripOk = false;
        process.stdout.write(`warn (${err.message}) — using enroll response\n`);
      }

      printPairingSummary(identity, {
        keyId: resData.key_id,
        siteUrl,
        labelUsed: label || host,
        isDefaultSite: config.defaultSite === siteUrl,
        roundTripOk
      });
      process.exit(0);
    } catch (error) {
      console.error(`[ERROR] Pairing failed: ${error.message}`);
      // Clean up only the NEW temp key; never delete an existing working key.
      try {
        await fs.unlink(tmpKeyPath);
      } catch {}
      process.exit(1);
    }
  } else if (site && token) {
    console.error('Error: Token-based authentication is deprecated in v2.');
    console.error('Usage: connectmwp-mcp add-site --enroll "<site_url>|<enrollment_code>" [--default] [--label <label>]');
    process.exit(1);
  } else {
    console.error('Error: --enroll parameter is required.');
    console.error('Usage: connectmwp-mcp add-site --enroll "<site_url>|<enrollment_code>" [--default] [--label <label>]');
    process.exit(1);
  }
}

if (command === 'list-sites') {
  const config = await readConfig();
  noticeIfCorrupt(config);
  const sitesList = Object.keys(config.sites || {});

  if (sitesList.length === 0) {
    console.log('No WordPress sites configured in ~/.connectmwp.json yet.');
    console.log('Configure a site using: connectmwp-mcp add-site --site <url> --token <token>');
    process.exit(0);
  }

  console.log('\nConfigured connectMWP WordPress Sites:');
  console.log('===========================================================================');
  for (const site of sitesList) {
    const isDefault = config.defaultSite === site ? ' [DEFAULT]' : '';
    console.log(`- ${site}${isDefault}`);
  }
  console.log('===========================================================================\n');
  process.exit(0);
}

if (command === 'remove-site') {
  let site = '';
  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--site' && args[i + 1]) {
      site = args[i + 1];
    }
  }

  if (!site) {
    console.error('Error: --site parameter is required.');
    console.error('Usage: connectmwp-mcp remove-site --site <site_url>');
    process.exit(1);
  }

  const normalizedSite = normalizeSiteUrl(site);
  const config = await readConfig();
  noticeIfCorrupt(config);

  if (config.sites && config.sites[normalizedSite]) {
    delete config.sites[normalizedSite];
    if (config.defaultSite === normalizedSite) {
      config.defaultSite = Object.keys(config.sites)[0] || '';
    }
    await writeConfig(config);
    console.log(`[SUCCESS] Removed site ${normalizedSite} from config.`);
  } else {
    console.error(`[ERROR] Site ${normalizedSite} not found in configuration.`);
    process.exit(1);
  }
  process.exit(0);
}

if (command === 'set-default') {
  let site = '';
  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--site' && args[i + 1]) {
      site = args[i + 1];
    }
  }

  if (!site) {
    console.error('Error: --site parameter is required.');
    console.error('Usage: connectmwp-mcp set-default --site <site_url>');
    process.exit(1);
  }

  const normalizedSite = normalizeSiteUrl(site);
  const config = await readConfig();
  noticeIfCorrupt(config);

  if (config.sites && config.sites[normalizedSite]) {
    config.defaultSite = normalizedSite;
    await writeConfig(config);
    console.log(`[SUCCESS] Set ${normalizedSite} as default target site.`);
  } else {
    console.error(`[ERROR] Site ${normalizedSite} is not configured. Add it first.`);
    process.exit(1);
  }
  process.exit(0);
}

/**
 * Make a secure call to the WordPress Plugin REST API
 */
async function callWordPress(siteUrl, keyId, privateKeyPath, endpoint, method = 'GET', data = null, isUpload = false, fileHash = null) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  // Per-request nonce closes the replay window. Even byte-identical requests
  // (same body, same one-second-window timestamp) produce different signatures
  // because the nonce participates in the canonical. Plugin-side reconstruction
  // expects this field at the SAME canonical position (second, after timestamp).
  const nonce = crypto.randomUUID();
  const [endpointPath, endpointQuery] = endpoint.split('?');

  // Build canonical request path for REST
  const requestPath = `/connectmwp/v1/${endpointPath}`;

  // Query parameters hashing
  let sortedQuery = '';
  if (endpointQuery) {
    const queryParams = new URLSearchParams(endpointQuery);
    const keys = [...queryParams.keys()].sort();
    const sortedParams = [];
    for (const key of keys) {
      const values = queryParams.getAll(key).sort();
      for (const val of values) {
        const encodedKey = encodeURIComponent(key)
          .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
        const encodedVal = encodeURIComponent(val)
          .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
        sortedParams.push(`${encodedKey}=${encodedVal}`);
      }
    }
    sortedQuery = sortedParams.join('&');
  }
  const queryHash = crypto.createHash('sha256').update(sortedQuery).digest('hex');

  // Body hashing
  let rawBody = '';
  if (data && method !== 'GET' && method !== 'HEAD') {
    if (isUpload) {
      rawBody = '';
    } else {
      rawBody = JSON.stringify(data);
    }
  }
  const bodyHash = isUpload && fileHash ? fileHash : crypto.createHash('sha256').update(rawBody).digest('hex');

  // Build + sign the canonical via the extracted lib/crypto primitives. Field
  // order MUST stay aligned with the plugin's reconstruction in
  // verify_request_signature (connectmwp-agent.php § 4.3). Drift of a single
  // byte breaks every request — see _internal/verify/interop_test.sh.
  const canonical = buildCanonical([
    timestamp,
    nonce,
    method.toUpperCase(),
    requestPath,
    queryHash,
    bodyHash,
  ]);

  const signature = await signCanonical(
    canonical,
    privateKeyPath,
    { site: siteUrl, scope: 'REST' },
    { sanitizeSigningError, logDiag },
  );

  const url = `${siteUrl}/wp-json/connectmwp/v1/${endpoint}`;

  const headers = {
    'X-ConnectMWP-Key': keyId,
    'X-ConnectMWP-Timestamp': timestamp,
    'X-ConnectMWP-Nonce': nonce,
    'X-ConnectMWP-Signature': signature
  };
  if (isUpload && fileHash) {
    headers['X-ConnectMWP-Body-Hash'] = fileHash;
  }

  let body = null;
  if (data && method !== 'GET' && method !== 'HEAD') {
    if (isUpload) {
      body = data; // FormData
    } else {
      headers['Content-Type'] = 'application/json';
      body = rawBody;
    }
  }

  try {
    const response = await fetch(url, { method, headers, body });

    // If REST API is not found or fails with auth/security block, try Admin-AJAX fallback
    if (response.status === 401 || response.status === 404 || response.status === 403) {
      return await callWordPressAjax(siteUrl, keyId, privateKeyPath, endpoint, method, data, isUpload, fileHash);
    }

    const resData = await response.json();
    return resData;
  } catch (error) {
    console.error(`connectMWP: REST call failed (${error.message}). Attempting Admin-AJAX fallback...`);
    return await callWordPressAjax(siteUrl, keyId, privateKeyPath, endpoint, method, data, isUpload, fileHash);
  }
}

/**
 * Fallback handler: Routes requests through admin-ajax.php
 */
async function callWordPressAjax(siteUrl, keyId, privateKeyPath, endpoint, method, data, isUpload, fileHash = null) {
  const ajaxUrl = `${siteUrl}/wp-admin/admin-ajax.php`;

  // Endpoint may carry a query string (e.g. "posts?limit=50&fields=..."); split
  // it off so the action mapping matches and the query params can be forwarded.
  const [endpointPath, endpointQuery] = endpoint.split('?');

  // Translate REST route to AJAX action
  let action = '';
  if (endpointPath === 'posts') {
    action = method === 'GET' ? 'get_posts' : 'create_post';
  } else if (endpointPath.startsWith('posts/')) {
    if (method === 'DELETE') {
      action = 'delete_post';
    } else if (method === 'GET') {
      action = 'get_post';
    } else {
      action = 'update_post';
    }
  } else if (endpointPath === 'media') {
    action = 'upload_media';
  } else if (endpointPath === 'tags') {
    action = 'get_tags';
  } else if (endpointPath === 'categories') {
    action = 'get_categories';
  } else if (endpointPath === 'whoami') {
    action = 'whoami';
  }

  let body;
  let headers = {};

  if (isUpload) {
    body = data;
    body.append('action', 'connectmwp_api');
    body.append('connectmwp_action', action);
  } else {
    const params = new URLSearchParams();
    params.append('action', 'connectmwp_api');
    params.append('connectmwp_action', action);

    if (action === 'update_post' || action === 'delete_post' || action === 'get_post') {
      const postId = endpointPath.split('/')[1];
      params.append('post_id', postId);
    }

    // Forward any GET query-string params (e.g. limit, fields) into the AJAX body.
    if (endpointQuery) {
      for (const [key, value] of new URLSearchParams(endpointQuery).entries()) {
        params.append(key, value);
      }
    }

    if (data) {
      for (const [key, value] of Object.entries(data)) {
        if (typeof value === 'object') {
          params.append(key, JSON.stringify(value));
        } else {
          params.append(key, value);
        }
      }
    }
    body = params.toString();
  }

  // Calculate signature for AJAX fallback
  const timestamp = Math.floor(Date.now() / 1000).toString();
  // Same per-request nonce contract as the REST path — see callWordPress.
  const nonce = crypto.randomUUID();
  const requestPath = `/connectmwp/v1/${action}`;
  const queryHash = crypto.createHash('sha256').update('').digest('hex'); // no query parameters in AJAX URL

  // Body hash
  let bodyHash = '';
  if (isUpload) {
    bodyHash = fileHash || crypto.createHash('sha256').update('').digest('hex');
  } else {
    bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  }

  // Canonical shape identical to REST path (timestamp, nonce, method, path,
  // queryHash, bodyHash). Plugin reconstructs the same shape regardless of
  // REST vs AJAX entry point.
  const canonical = buildCanonical([
    timestamp,
    nonce,
    'POST', // AJAX is always POST
    requestPath,
    queryHash,
    bodyHash,
  ]);

  const signature = await signCanonical(
    canonical,
    privateKeyPath,
    { site: siteUrl, scope: 'AJAX', action },
    { sanitizeSigningError, logDiag },
  );

  headers['X-ConnectMWP-Key'] = keyId;
  headers['X-ConnectMWP-Timestamp'] = timestamp;
  headers['X-ConnectMWP-Nonce'] = nonce;
  headers['X-ConnectMWP-Signature'] = signature;
  if (isUpload && fileHash) {
    headers['X-ConnectMWP-Body-Hash'] = fileHash;
  }

  if (!isUpload) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
  }

  const response = await fetch(ajaxUrl, { method: 'POST', headers, body });
  return await response.json();
}

// ============================================================================
// MCP SERVER INITIALIZATION
// ============================================================================

// Load package version dynamically (Architectural Review Fix)
let version = FALLBACK_VERSION;
try {
  const pkgPath = new URL('./package.json', import.meta.url);
  const pkgContent = await fs.readFile(pkgPath, 'utf-8');
  const pkg = JSON.parse(pkgContent);
  if (pkg.version) {
    version = pkg.version;
  }
} catch (err) {
  // A package.json beside the script is always expected — there is no
  // legitimate "first run silence" case here, so log unconditionally before
  // falling back to FALLBACK_VERSION (T044 / absorbs T033).
  logDiag(`version-load-error code=${err && err.code ? err.code : '<none>'} message=${err && err.message ? err.message : String(err)}`);
  // version stays at FALLBACK_VERSION
}

// Create the MCP Server instance
const server = new Server(
  {
    name: 'connectmwp-mcp',
    version: version,
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register Tool Schemas
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'connectmwp_get_posts',
        description: 'Retrieve titles, content, URLs, and IDs of existing posts from the WordPress site.',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            },
            limit: {
              type: 'integer',
              description: 'Maximum number of posts to retrieve (default 50)',
            },
            offset: {
              type: 'integer',
              description: 'Number of posts to offset (for pagination, default 0)',
            },
            fields: {
              type: 'string',
              description: 'Optional comma-separated list of fields to return (e.g. "id,title,content"). Defaults to excluding content to save bandwidth.'
            }
          },
        },
      },
      {
        name: 'connectmwp_create_post',
        description: 'Create a new post draft or publish directly on a WordPress site.',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            },
            title: {
              type: 'string',
              description: 'Title of the post',
            },
            content: {
              type: 'string',
              description: 'Content of the post in clean HTML or Gutenberg block markup',
            },
            status: {
              type: 'string',
              enum: ['draft', 'publish', 'trash'],
              description: 'Post status: draft (default for review), publish (direct), or trash (move to trash)',
            },
            categories: {
              type: 'array',
              items: { type: 'integer' },
              description: 'List of category IDs to assign',
            },
            tags: {
              type: 'array',
              items: { type: 'integer' },
              description: 'List of tag IDs to assign (e.g. 1-5 tags)',
            },
            featured_media: {
              type: 'integer',
              description: 'ID of the uploaded media file to set as the Featured Image',
            },
          },
          required: ['title'],
        },
      },
      {
        name: 'connectmwp_update_post',
        description: 'Update an existing post (e.g., to insert SEO internal links).',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            },
            id: {
              type: 'integer',
              description: 'WordPress Post ID to update',
            },
            title: {
              type: 'string',
              description: 'New title',
            },
            content: {
              type: 'string',
              description: 'New content body',
            },
            status: {
              type: 'string',
              enum: ['draft', 'publish', 'trash'],
            },
            categories: {
              type: 'array',
              items: { type: 'integer' },
            },
            tags: {
              type: 'array',
              items: { type: 'integer' },
            },
            featured_media: {
              type: 'integer',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'connectmwp_upload_media',
        description: 'Upload a featured or inline image/graph to the WordPress media library.',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            },
            file_path: {
              type: 'string',
              description: 'Absolute path to the image file on your local machine',
            },
            image_url: {
              type: 'string',
              description: 'URL of the remote image to download and upload',
            },
            filename: {
              type: 'string',
              description: 'Optional name for the file (default image.png)',
            },
          },
        },
      },
      {
        name: 'connectmwp_list_tags',
        description: 'List all tags on the WordPress site to select the 1-5 most relevant ones.',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            },
            limit: {
              type: 'integer',
              description: 'Maximum number of tags to retrieve (default 50, max 200)',
            },
            offset: {
              type: 'integer',
              description: 'Number of tags to offset (default 0)',
            },
            search: {
              type: 'string',
              description: 'Optional search term to filter tags by name',
            }
          },
        },
      },
      {
        name: 'connectmwp_list_categories',
        description: 'List all categories on the WordPress site.',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            },
            limit: {
              type: 'integer',
              description: 'Maximum number of categories to retrieve (default 50, max 200)',
            },
            offset: {
              type: 'integer',
              description: 'Number of categories to offset (default 0)',
            },
            search: {
              type: 'string',
              description: 'Optional search term to filter categories by name',
            }
          },
        },
      },
      {
        name: 'connectmwp_get_post',
        description: 'Retrieve full details of a single post by ID (to analyze link opportunities).',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            },
            id: {
              type: 'integer',
              description: 'WordPress Post ID to retrieve'
            },
            fields: {
              type: 'string',
              description: 'Optional comma-separated list of fields to return (e.g. "id,title,content,url").'
            }
          },
          required: ['id']
        }
      },
      {
        name: 'connectmwp_create_category',
        description: 'Create a new category on the WordPress site.',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            },
            name: {
              type: 'string',
              description: 'Category name'
            },
            slug: {
              type: 'string',
              description: 'Optional URL-friendly slug for the category'
            },
            parent: {
              type: 'integer',
              description: 'Optional parent category ID'
            }
          },
          required: ['name']
        }
      },
      {
        name: 'connectmwp_create_tag',
        description: 'Create a new tag on the WordPress site.',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            },
            name: {
              type: 'string',
              description: 'Tag name'
            },
            slug: {
              type: 'string',
              description: 'Optional URL-friendly slug for the tag'
            }
          },
          required: ['name']
        }
      },
      {
        name: 'connectmwp_delete_post',
        description: 'Trash or permanently delete a post by ID from the WordPress site.',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL of the target WordPress site (e.g. "2morrow.ai"). Uses the default site if omitted.'
            },
            id: {
              type: 'integer',
              description: 'WordPress Post ID to delete'
            },
            force: {
              type: 'boolean',
              description: 'Optional. If true, bypasses trash and permanently deletes the post. Default false.'
            }
          },
          required: ['id']
        }
      },
      {
        name: 'connectmwp_status',
        description: 'Show connectMWP version and connection status: the running local MCP client version, the paired sites, the default site, and — via a live signed round-trip — the connectMWP plugin version installed on the target WordPress site. Use to confirm which versions are running and that end-to-end signing works.',
        inputSchema: {
          type: 'object',
          properties: {
            site: {
              type: 'string',
              description: 'Optional domain or site URL to probe for the live plugin version (e.g. "2morrow.ai"). Uses the default site if omitted.'
            }
          }
        }
      }
    ],
  };
});

// Handle Tool Executions
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'connectmwp_get_posts': {
        const { site, limit = 50, offset = 0, fields } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);

        // GET params travel in the query string only — never as a request body.
        const queryParams = new URLSearchParams();
        queryParams.append('limit', limit.toString());
        queryParams.append('offset', offset.toString());
        if (fields) {
          queryParams.append('fields', fields);
        }

        const res = await callWordPress(siteUrl, keyId, privateKeyPath, `posts?${queryParams.toString()}`, 'GET', null);
        return { content: [{ type: 'text', text: JSON.stringify(projectGetPosts(res, limit, offset)) }] };
      }

      case 'connectmwp_create_post': {
        const { site, ...postParams } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);
        const res = await callWordPress(siteUrl, keyId, privateKeyPath, 'posts', 'POST', postParams);
        return { content: [{ type: 'text', text: JSON.stringify(projectMutatePost(res)) }] };
      }

      case 'connectmwp_update_post': {
        const { site, id, ...postParams } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);
        const res = await callWordPress(siteUrl, keyId, privateKeyPath, `posts/${id}`, 'POST', postParams);
        return { content: [{ type: 'text', text: JSON.stringify(projectMutatePost(res)) }] };
      }

      case 'connectmwp_delete_post': {
        const { site, id, force } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);
        const res = await callWordPress(siteUrl, keyId, privateKeyPath, `posts/${id}`, 'DELETE', { force });
        return { content: [{ type: 'text', text: JSON.stringify(projectDeletePost(res)) }] };
      }

      case 'connectmwp_upload_media': {
        const { site, file_path, image_url, filename } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);
        let fileBuffer;
        let nameToUse = filename || 'image.png';

        if (!file_path && !image_url) {
          throw new Error('Either file_path or image_url must be provided.');
        }

        if (image_url) {
          // SSRF validation now ALSO returns the safe IP, which we pin through
          // the subsequent fetch so a DNS-rebinding attacker can't redirect
          // the connect target between validation and connect (T140).
          const { url, validatedIp, family } = await validateImageUrl(image_url);

          // Native https.request with the pinned IP as the connect target.
          // SNI uses url.hostname unchanged so TLS cert validation succeeds.
          // Redirects are NOT followed (matches the v2.0.19 SSRF guard).
          const imgRes = await pinnedHttpsGet(url, validatedIp, family);

          // Content-Length fast path: catches honest oversized payloads
          // before we read a byte. Cheap; runs BEFORE the streaming cap.
          const contentLength = imgRes.headers['content-length'];
          if (contentLength && parseInt(contentLength, 10) > MEDIA_MAX_BYTES) {
            imgRes.destroy();
            throw new Error(`Image size exceeds the maximum limit of ${MEDIA_MAX_MB}MB.`);
          }

          // Streaming cap: defense against chunked-encoded or
          // header-omitting hostile streams. Aborts the connection mid-stream
          // the moment cumulative bytes exceed MEDIA_MAX_BYTES (T139).
          fileBuffer = await streamToCappedBuffer(imgRes, MEDIA_MAX_BYTES);

          validateImageMagicNumbers(fileBuffer);

          if (!filename) {
            const urlPath = url.pathname;
            const parsedName = path.basename(urlPath);
            if (parsedName && parsedName.includes('.')) nameToUse = parsedName;
          }
        } else {
          const ext = path.extname(file_path).toLowerCase();
          if (!ALLOWED_EXTENSIONS.includes(ext)) {
            throw new Error(`Invalid file extension: ${ext}. Only image files (${ALLOWED_EXTENSIONS.join(', ')}) are allowed.`);
          }

          // fs.stat fast-path: rejects obvious oversized files without
          // reading a single byte. Cheap; runs BEFORE the streaming cap.
          const stat = await fs.stat(file_path);
          if (stat.size > MEDIA_MAX_BYTES) {
            throw new Error(`File size exceeds the maximum limit of ${MEDIA_MAX_MB}MB.`);
          }

          // Streaming read with cap closes the post-open TOCTOU window
          // (negligible on a single-user dev machine, but the streaming
          // primitive is shared with the remote path so it's free) (T139).
          fileBuffer = await streamToCappedBuffer(createReadStream(file_path), MEDIA_MAX_BYTES);

          validateImageMagicNumbers(fileBuffer);

          if (!filename) nameToUse = path.basename(file_path);
        }

        // Calculate SHA-256 hash of the buffer for signature verification
        const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

        // Build FormData payload compatible with native fetch
        const formData = new FormData();
        const blob = new Blob([fileBuffer]);
        formData.append('file', blob, nameToUse);

        const res = await callWordPress(siteUrl, keyId, privateKeyPath, 'media', 'POST', formData, true, fileHash);
        return { content: [{ type: 'text', text: JSON.stringify(projectUploadMedia(res)) }] };
      }

      case 'connectmwp_list_tags': {
        const { site, limit = 50, offset = 0, search } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);
        const queryParams = new URLSearchParams();
        queryParams.append('limit', limit.toString());
        queryParams.append('offset', offset.toString());
        if (search) {
          queryParams.append('search', search);
        }
        const res = await callWordPress(siteUrl, keyId, privateKeyPath, `tags?${queryParams.toString()}`, 'GET');
        return { content: [{ type: 'text', text: JSON.stringify(projectListTaxonomy(res, 'tags', limit, offset)) }] };
      }

      case 'connectmwp_list_categories': {
        const { site, limit = 50, offset = 0, search } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);
        const queryParams = new URLSearchParams();
        queryParams.append('limit', limit.toString());
        queryParams.append('offset', offset.toString());
        if (search) {
          queryParams.append('search', search);
        }
        const res = await callWordPress(siteUrl, keyId, privateKeyPath, `categories?${queryParams.toString()}`, 'GET');
        return { content: [{ type: 'text', text: JSON.stringify(projectListTaxonomy(res, 'categories', limit, offset)) }] };
      }

      case 'connectmwp_get_post': {
        const { site, id, fields } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);

        const queryParams = new URLSearchParams();
        if (fields) {
          queryParams.append('fields', fields);
        }
        const endpoint = fields ? `posts/${id}?${queryParams.toString()}` : `posts/${id}`;

        const res = await callWordPress(siteUrl, keyId, privateKeyPath, endpoint, 'GET', null);
        return { content: [{ type: 'text', text: JSON.stringify(projectGetPost(res)) }] };
      }

      case 'connectmwp_create_category': {
        const { site, ...catParams } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);
        const res = await callWordPress(siteUrl, keyId, privateKeyPath, 'categories', 'POST', catParams);
        return { content: [{ type: 'text', text: JSON.stringify(projectCreateTaxonomy(res)) }] };
      }

      case 'connectmwp_create_tag': {
        const { site, ...tagParams } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);
        const res = await callWordPress(siteUrl, keyId, privateKeyPath, 'tags', 'POST', tagParams);
        return { content: [{ type: 'text', text: JSON.stringify(projectCreateTaxonomy(res)) }] };
      }

      case 'connectmwp_status': {
        const { site } = args;
        const config = await readConfig();
        const siteKeys = Object.keys(config.sites || {});
        const sites = siteKeys.map((url) => ({
          url,
          label: config.sites[url].label || null,
          key_id: config.sites[url].key_id || null,
          is_default: url === config.defaultSite,
        }));

        const status = {
          success: true,
          mcp_client_version: version,
          default_site: config.defaultSite || null,
          sites,
        };

        // No sites paired yet — report cleanly instead of erroring.
        if (siteKeys.length === 0) {
          status.note = 'No WordPress sites paired yet. Run "npx -y connectmwp-mcp add-site --enroll <enrollment_string>" to pair one.';
          return { content: [{ type: 'text', text: JSON.stringify(status) }] };
        }

        // Live signed round-trip to read the plugin version on the target site.
        // Network/signing failure degrades gracefully — local facts stay accurate.
        try {
          const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);
          const whoami = await callWordPress(siteUrl, keyId, privateKeyPath, 'whoami', 'GET');
          if (whoami && whoami.success) {
            status.checked_site = siteUrl;
            status.plugin_version = (whoami.site && whoami.site.plugin_version) || 'unknown';
            status.site_title = whoami.site ? whoami.site.title : null;
            status.user = whoami.user ? whoami.user.login : null;
            status.signed_roundtrip = 'ok';
            if (status.plugin_version === 'unknown') {
              status.note = 'Signing works, but the site is running a plugin build older than 2.0.37 that does not report its version. Update the connectMWP plugin on the site to surface it.';
            }
          } else {
            status.signed_roundtrip = 'failed';
            status.note = 'Signed round-trip did not succeed; plugin version unavailable. Client version and sites are still accurate.';
          }
        } catch (err) {
          logDiag(`status-whoami-error message=${err && err.message ? err.message : String(err)}`);
          status.signed_roundtrip = 'failed';
          status.note = 'Could not reach the site for a live plugin-version check; client version and sites are still accurate.';
        }

        return { content: [{ type: 'text', text: JSON.stringify(status) }] };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    // Operator channel FIRST: full detail (message + code + stack) to stderr,
    // structurally isolated from the JSON-RPC stdout stream (T040).
    const code = error && error.code ? ` code=${error.code}` : '';
    const detail = error && error.message ? error.message : String(error);
    const stack = error && error.stack ? ` | ${error.stack}` : '';
    logDiag(`tool-error tool=${name}${code} message=${detail}${stack}`);
    // LLM channel: ONLY the safe, mapped message — never raw error detail.
    return {
      isError: true,
      content: [{ type: 'text', text: JSON.stringify({ success: false, error: toClientErrorMessage(error) }) }],
    };
  }
});

// Run the MCP server
async function run() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('connectMWP MCP Server running on stdio');
}

// Internal helpers exported for unit tests / verification harnesses. Not part
// of the public MCP tool surface — importers should never depend on these
// (they are subject to P5 modularization into lib/*.js).
export {
  isPrivateIp,
  streamToCappedBuffer,
  sanitizeSigningError,
  toClientErrorMessage,
  GENERIC_TOOL_ERROR,
  classifyReadError,
  readConfig,
  logDiag,
  pinnedHttpsGet,
  validateImageUrl,
  validateImageMagicNumbers,
  tightenPathPerms,
  MEDIA_MAX_BYTES,
  ALLOWED_EXTENSIONS,
};

// Boot the MCP server only when invoked directly (e.g. `npx connectmwp-mcp`,
// or via the npm-installed `connectmwp-mcp` bin symlink). When imported (e.g.
// from a test harness), skip boot so the importer can exercise the exported
// helpers without spawning a stdio server. realpath handles the symlink
// case — npm's bin shim points at index.js via a symlink whose path differs
// from import.meta.url until both are resolved.
function isMainModule() {
  if (!process.argv[1]) return false;
  try {
    const argvReal = realpathSync(process.argv[1]);
    const fileReal = realpathSync(fileURLToPath(import.meta.url));
    return argvReal === fileReal;
  } catch {
    return false;
  }
}
if (isMainModule()) {
  run().catch((error) => {
    console.error('Fatal error running server:', error);
    process.exit(1);
  });
}
