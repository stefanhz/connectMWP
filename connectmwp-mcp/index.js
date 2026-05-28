#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import dns from 'dns/promises';
import crypto from 'crypto';

// Configuration file path
const CONFIG_PATH = path.join(os.homedir(), '.connectmwp.json');

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
 * Load settings from the local configuration file
 */
async function readConfig() {
  try {
    const data = await fs.readFile(CONFIG_PATH, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    return { defaultSite: '', sites: {} };
  }
}

/**
 * Save settings to the local configuration file
 */
async function writeConfig(config) {
  await fs.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf-8');
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
  console.log('Test it in your AI client (Claude / ChatGPT / Cursor / Antigravity):');
  console.log(`  "List the tags on ${new URL(ctx.siteUrl).hostname} using connectMWP"`);
  console.log('');
  console.log('Adding another AI client on this Mac? Register the same MCP server: `npx -y connectmwp-mcp`.');
  console.log('All AI clients on this user account share this pairing — no extra code needed.');
}

/**
 * Helper to check if an IP address is in a private, loopback, or link-local range (I-2)
 */
function isPrivateIp(ip) {
  // IPv4 Checks
  if (/^(127\.|10\.|169\.254\.|192\.168\.)/.test(ip)) {
    return true;
  }
  // 172.16.0.0/12
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) {
    return true;
  }
  // IPv6 Checks
  if (ip === '::1' || ip.startsWith('fe80:') || ip.startsWith('fc00:') || ip.startsWith('fd00:')) {
    return true;
  }
  return false;
}

/**
 * Validate image URL to prevent SSRF (I-2)
 */
async function validateImageUrl(imageUrl) {
  const url = new URL(imageUrl);
  if (url.protocol !== 'https:') {
    throw new Error('Only HTTPS image URLs are allowed for security.');
  }

  const hostname = url.hostname;
  let ips = [];

  try {
    // Attempt resolving hostname to IP addresses
    const addresses = await dns.resolve(hostname);
    ips = addresses;
  } catch (error) {
    try {
      // Fallback for direct IP hostnames or DNS lookup
      const lookupResult = await dns.lookup(hostname);
      ips = [lookupResult.address];
    } catch {
      throw new Error(`Could not resolve hostname: ${hostname}`);
    }
  }

  for (const ip of ips) {
    if (isPrivateIp(ip)) {
      throw new Error(`Access to private IP range is blocked: ${ip}`);
    }
  }
}

/**
 * Validate image magic numbers to prevent arbitrary file read (I-2 Fix)
 */
function validateImageMagicNumbers(buffer) {
  if (buffer.length < 4) {
    throw new Error('File buffer is too small to be a valid image.');
  }
  
  // PNG
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
    return 'png';
  }
  // JPEG
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    return 'jpeg';
  }
  // GIF
  if (buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x38) {
    return 'gif';
  }
  // BMP
  if (buffer[0] === 0x42 && buffer[1] === 0x4D) {
    return 'bmp';
  }
  // WebP (RIFF....WEBP)
  if (buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46) {
    if (buffer.length >= 12 && buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50) {
      return 'webp';
    }
  }
  // TIFF
  if ((buffer[0] === 0x49 && buffer[1] === 0x49 && buffer[2] === 0x2A && buffer[3] === 0x00) ||
      (buffer[0] === 0x4D && buffer[1] === 0x4D && buffer[2] === 0x00 && buffer[3] === 0x2A)) {
    return 'tiff';
  }
  // SVG / XML (check if starts with <?xml or <svg, case insensitive or containing <svg)
  const head = buffer.slice(0, Math.min(buffer.length, 512)).toString('utf-8').trim();
  if (/^<svg/i.test(head) || /^<\?xml/i.test(head) && head.includes('<svg')) {
    return 'svg';
  }
  
  throw new Error('File magic number verification failed. Only valid image files (PNG, JPEG, GIF, WebP, SVG, BMP, TIFF) are allowed.');
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
      await fs.mkdir(privateKeyDir, { recursive: true });
      await fs.writeFile(tmpKeyPath, privateKeyPem, 'utf-8');
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

  // Rebuild canonical string
  const canonical = [
    timestamp,
    method.toUpperCase(),
    requestPath,
    queryHash,
    bodyHash
  ].join('\n');

  // Sign canonical string
  let signature;
  try {
    const pem = await fs.readFile(privateKeyPath, 'utf-8');
    const privateKey = crypto.createPrivateKey(pem);
    const sigBuffer = crypto.sign(null, Buffer.from(canonical, 'utf-8'), privateKey);
    signature = sigBuffer.toString('base64');
  } catch (err) {
    throw new Error(`Failed to sign request using private key at ${privateKeyPath}: ${err.message}`);
  }

  const url = `${siteUrl}/wp-json/connectmwp/v1/${endpoint}`;
  
  const headers = {
    'X-ConnectMWP-Key': keyId,
    'X-ConnectMWP-Timestamp': timestamp,
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
  const requestPath = `/connectmwp/v1/${action}`;
  const queryHash = crypto.createHash('sha256').update('').digest('hex'); // no query parameters in AJAX URL

  // Body hash
  let bodyHash = '';
  if (isUpload) {
    bodyHash = fileHash || crypto.createHash('sha256').update('').digest('hex');
  } else {
    bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  }

  const canonical = [
    timestamp,
    'POST', // AJAX is always POST
    requestPath,
    queryHash,
    bodyHash
  ].join('\n');

  let signature;
  try {
    const pem = await fs.readFile(privateKeyPath, 'utf-8');
    const privateKey = crypto.createPrivateKey(pem);
    const sigBuffer = crypto.sign(null, Buffer.from(canonical, 'utf-8'), privateKey);
    signature = sigBuffer.toString('base64');
  } catch (err) {
    throw new Error(`Failed to sign AJAX request using private key at ${privateKeyPath}: ${err.message}`);
  }

  headers['X-ConnectMWP-Key'] = keyId;
  headers['X-ConnectMWP-Timestamp'] = timestamp;
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
let version = '1.2.4';
try {
  const pkgPath = new URL('./package.json', import.meta.url);
  const pkgContent = await fs.readFile(pkgPath, 'utf-8');
  const pkg = JSON.parse(pkgContent);
  if (pkg.version) {
    version = pkg.version;
  }
} catch (err) {
  // Fallback to static version if package.json cannot be read at runtime
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
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'connectmwp_create_post': {
        const { site, ...postParams } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);
        const res = await callWordPress(siteUrl, keyId, privateKeyPath, 'posts', 'POST', postParams);
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'connectmwp_update_post': {
        const { site, id, ...postParams } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);
        const res = await callWordPress(siteUrl, keyId, privateKeyPath, `posts/${id}`, 'POST', postParams);
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'connectmwp_delete_post': {
        const { site, id, force } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);
        const res = await callWordPress(siteUrl, keyId, privateKeyPath, `posts/${id}`, 'DELETE', { force });
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
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
          // SSRF Validation (I-2 Fix)
          await validateImageUrl(image_url);

          // Fetch image from URL, manually handling redirects to prevent SSRF bypass
          const imgRes = await fetch(image_url, { redirect: 'manual' });
          if (imgRes.status >= 300 && imgRes.status < 400) {
            throw new Error(`SSRF Block: Redirects are not allowed during image download (${imgRes.status}).`);
          }
          if (!imgRes.ok) throw new Error(`Failed to download image from URL: ${image_url}`);

          // Size limit check on Content-Length header if present
          const contentLength = imgRes.headers.get('content-length');
          if (contentLength && parseInt(contentLength, 10) > 10 * 1024 * 1024) {
            throw new Error('Image size exceeds the maximum limit of 10MB.');
          }

          fileBuffer = Buffer.from(await imgRes.arrayBuffer());
          
          // Verify final buffer size
          if (fileBuffer.byteLength > 10 * 1024 * 1024) {
            throw new Error('Image size exceeds the maximum limit of 10MB.');
          }

          // Verify magic numbers
          validateImageMagicNumbers(fileBuffer);

          if (!filename) {
            const urlPath = new URL(image_url).pathname;
            const parsedName = path.basename(urlPath);
            if (parsedName && parsedName.includes('.')) nameToUse = parsedName;
          }
        } else {
          // File extension allowlist validation (I-2 Fix)
          const ALLOWED_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.tiff'];
          const ext = path.extname(file_path).toLowerCase();
          if (!ALLOWED_EXTENSIONS.includes(ext)) {
            throw new Error(`Invalid file extension: ${ext}. Only image files (${ALLOWED_EXTENSIONS.join(', ')}) are allowed.`);
          }

          // Read local file
          fileBuffer = await fs.readFile(file_path);
          
          // Verify buffer size
          if (fileBuffer.byteLength > 10 * 1024 * 1024) {
            throw new Error('File size exceeds the maximum limit of 10MB.');
          }

          // Verify magic numbers
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
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
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
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
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
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
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
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'connectmwp_create_category': {
        const { site, ...catParams } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);
        const res = await callWordPress(siteUrl, keyId, privateKeyPath, 'categories', 'POST', catParams);
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      case 'connectmwp_create_tag': {
        const { site, ...tagParams } = args;
        const { siteUrl, keyId, privateKeyPath } = await getCredentials(site);
        const res = await callWordPress(siteUrl, keyId, privateKeyPath, 'tags', 'POST', tagParams);
        return { content: [{ type: 'text', text: JSON.stringify(res) }] };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      isError: true,
      content: [{ type: 'text', text: JSON.stringify({ success: false, error: error.message }) }],
    };
  }
});

// Run the MCP server
async function run() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('connectMWP MCP Server running on stdio');
}

run().catch((error) => {
  console.error('Fatal error running server:', error);
  process.exit(1);
});
