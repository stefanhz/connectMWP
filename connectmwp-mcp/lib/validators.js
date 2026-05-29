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
  // IPv4-mapped IPv6 form (`::ffff:1.2.3.4`) — strip prefix, recurse on the
  // embedded IPv4 address. Common attacker bypass; rejected explicitly.
  const mappedMatch = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mappedMatch) {
    return isPrivateIp(mappedMatch[1]);
  }

  // IPv4 checks
  if (/^(127\.|10\.|169\.254\.|192\.168\.)/.test(ip)) {
    return true;
  }
  // 172.16.0.0/12
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) {
    return true;
  }
  // 0.0.0.0/8 — "this host" address; not usable as a remote target but
  // sometimes resolves on misconfigured services. Block defensively.
  if (/^0\./.test(ip)) {
    return true;
  }

  // IPv6 checks
  // ::1 = loopback
  // ::  = unspecified
  // fe80::/10 = link-local
  // fc00::/7 = unique-local (covers fc and fd prefixes)
  if (ip === '::1' || ip === '::' || ip.toLowerCase().startsWith('fe80:')
      || ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) {
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
  // SVG / XML (check if starts with <?xml or <svg, case insensitive or containing <svg)
  const head = buffer.slice(0, Math.min(buffer.length, 512)).toString('utf-8').trim();
  if (/^<svg/i.test(head) || /^<\?xml/i.test(head) && head.includes('<svg')) {
    return 'svg';
  }

  throw new Error('File magic number verification failed. Only valid image files (PNG, JPEG, GIF, WebP, SVG, BMP, TIFF) are allowed.');
}
