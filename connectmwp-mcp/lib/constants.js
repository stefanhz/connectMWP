// Single source of truth for connectMWP MCP constants.
//
// Extracted from inline literals during P5 step (i) — T147 (centralize hardcoded
// constants). Future P5 / P6 work moves additional configurables here.
//
// NEVER hardcode these values elsewhere; always import.

// Media-upload cap (T139). Applies to both remote (chunked stream) and
// local-file (fs.stat fast-path + createReadStream) upload paths.
export const MEDIA_MAX_BYTES = 10 * 1024 * 1024;
export const MEDIA_MAX_MB = MEDIA_MAX_BYTES / 1024 / 1024;

// File-extension allowlist for local-file uploads (T140 hardening — paired
// with the magic-number check; defense in depth against renamed binaries).
export const ALLOWED_EXTENSIONS = [
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.tiff',
];

// Fallback version reported when package.json cannot be read at runtime
// (audit ARCH §3 — Hardcoded Fallbacks & Metadata). Held at the last
// stable 1.x → 2.x bridge tag so a runtime parse failure surfaces clearly
// as "an old version is running" rather than a wildly wrong number.
export const FALLBACK_VERSION = '2.3.9';
