// Request-input validation layer for the connectMWP MCP client.
//
// Extracted from inline definitions in index.js during P5 step (iii) —
// T144 step iii of the modularization sequence. These three functions are the
// MCP client's input-validation surface for the `upload_media` tool:
//
//   - isPrivateIp            — SSRF guard; classifies an IP as private /
//                              loopback / link-local across IPv4, IPv6, and
//                              IPv4-mapped-IPv6 forms (T140 hardening).
//   - validateImageUrl       — HTTPS-only check + DNS resolution + private-IP
//                              rejection; resolves and pins the safe IP that
//                              `pinnedHttpsGet` (still in index.js for now —
//                              step vi `lib/wp-client.js` territory) reuses at
//                              connect time to defeat DNS rebinding (T140).
//   - validateImageMagicNumbers — magic-number sniff that rejects non-image
//                              payloads (arbitrary-file-read guard, I-2 Fix).
//
// Pure code move; bodies are byte-for-byte identical to the v2.0.23 originals.
// No default export — import the named functions. The p2 verification harness
// (`_internal/verify/p2_test.sh`) exercises isPrivateIp / validateImageUrl.

import dns from 'dns/promises';

/**
 * Helper to check if an IP address is in a private, loopback, or link-local
 * range. Handles both IPv4, IPv6, AND IPv4-mapped IPv6 forms (e.g.
 * `::ffff:127.0.0.1`) so an attacker can't smuggle a loopback target by
 * dual-stack representation (T140 hardening).
 */
export function isPrivateIp(ip) {
  const addr = String(ip).trim().toLowerCase();

  // IPv4-mapped IPv6, DOTTED form (`::ffff:1.2.3.4`) — strip prefix, recurse on
  // the embedded IPv4. Common attacker bypass; rejected explicitly.
  const mappedDotted = addr.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mappedDotted) {
    return isPrivateIp(mappedDotted[1]);
  }
  // IPv4-mapped IPv6, HEX-GROUPED form (`::ffff:7f00:1` = 127.0.0.1). getaddrinfo
  // rarely emits this, but a hostile resolver could return it to slip the dotted
  // check above — reconstruct the embedded IPv4 from the two 16-bit groups and
  // recurse so the mapped private target is still caught (T092).
  const mappedHex = addr.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mappedHex) {
    const hi = parseInt(mappedHex[1], 16);
    const lo = parseInt(mappedHex[2], 16);
    const v4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
    return isPrivateIp(v4);
  }

  // IPv4 checks
  if (/^(127\.|10\.|169\.254\.|192\.168\.)/.test(addr)) {
    return true;
  }
  // 172.16.0.0/12
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(addr)) {
    return true;
  }
  // 100.64.0.0/10 — carrier-grade NAT (RFC 6598); also Tailscale's range. A
  // request that resolves here can reach a tailnet / CGNAT-internal host (T092).
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(addr)) {
    return true;
  }
  // 198.18.0.0/15 — benchmarking range (RFC 2544); never a legitimate fetch.
  if (/^198\.1[89]\./.test(addr)) {
    return true;
  }
  // 0.0.0.0/8 — "this host" address; not usable as a remote target but
  // sometimes resolves on misconfigured services. Block defensively.
  if (/^0\./.test(addr)) {
    return true;
  }

  // IPv6: normalize a fully-EXPANDED all-zero-but-last form
  // (`0:0:0:0:0:0:0:1` / `0:0:0:0:0:0:0:0`) so an un-compressed loopback /
  // unspecified can't bypass the exact-match checks below (T092).
  const groups = addr.split(':');
  if (groups.length === 8 && groups.slice(0, 7).every((g) => /^0+$/.test(g))) {
    if (/^0*1$/.test(groups[7])) return true; // ::1 loopback
    if (/^0+$/.test(groups[7])) return true;  // :: unspecified
  }
  // ::1 = loopback, :: = unspecified, fe80::/10 = link-local (fe80–febf),
  // fc00::/7 = unique-local (fc/fd prefixes).
  if (addr === '::1' || addr === '::' || /^fe[89ab]/.test(addr)
      || addr.startsWith('fc') || addr.startsWith('fd')) {
    return true;
  }

  return false;
}

/**
 * Validate image URL to prevent SSRF. Returns the parsed URL, the pre-resolved
 * safe IP, and the IP family — used by `pinnedHttpsGet` to skip DNS at connect
 * time so a rebinding attacker can't redirect the fetch between validation
 * and connect (T140 hardening).
 */
export async function validateImageUrl(imageUrl) {
  const url = new URL(imageUrl);
  if (url.protocol !== 'https:') {
    throw new Error('Only HTTPS image URLs are allowed for security.');
  }

  const hostname = url.hostname;
  let resolved = [];

  // Prefer dns.lookup (returns {address, family}) so we get the family
  // we'll need to pass to https.request's lookup callback. dns.resolve
  // doesn't return family.
  try {
    const result = await dns.lookup(hostname, { all: true });
    resolved = result.map(r => ({ address: r.address, family: r.family }));
  } catch {
    throw new Error(`Could not resolve hostname: ${hostname}`);
  }

  if (resolved.length === 0) {
    throw new Error(`Could not resolve hostname: ${hostname}`);
  }

  for (const r of resolved) {
    if (isPrivateIp(r.address)) {
      throw new Error(`Access to private IP range is blocked: ${r.address}`);
    }
  }

  // Pin the first safe IP for the subsequent fetch. Family must match the IP
  // (4 for IPv4, 6 for IPv6) — passed unchanged into `lookup` callback.
  const first = resolved[0];
  return { url, validatedIp: first.address, family: first.family };
}

/**
 * Validate image magic numbers to prevent arbitrary file read (I-2 Fix)
 */
export function validateImageMagicNumbers(buffer) {
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
  // SVG is DELIBERATELY NOT accepted (T091). SVG is XML, not a raster image, and
  // is a well-known stored-XSS carrier: an SVG with embedded <script>/event
  // handlers uploaded to the WP media library and served as image/svg+xml runs
  // in the site origin when its attachment URL is opened. A prompt-injected LLM
  // could supply such a file via upload_media. Raster formats cover the real use
  // case; if SVG is ever needed it must be sanitized server-side before storage.
  throw new Error('File magic number verification failed. Only valid raster image files (PNG, JPEG, GIF, WebP, BMP, TIFF) are allowed.');
}
