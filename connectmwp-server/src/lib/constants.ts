/**
 * Shared, single-source-of-truth constants for the connectMWP marketing site.
 *
 * Scope note: this is the SSOT *within the central server (TypeScript) only*.
 * The WordPress plugin (PHP) and the MCP client cannot import this module, so
 * they maintain their own copies of the package name / pairing command. When the
 * canonical invocation form changes, update those surfaces too (see project
 * CLAUDE.md). Do NOT attempt to import this into the plugin.
 */

/** npm package name of the local MCP client. Single source of truth (server-side). */
export const MCP_PACKAGE = 'connectmwp-mcp';

/**
 * Canonical pairing command shown on the landing page.
 *
 * Uses the bare `npx -y <pkg>` form (no `@latest`) to match the plugin's
 * rendered pairing screen and the documented canonical invocation. `npx -y`
 * already resolves the latest published version when the package isn't cached,
 * so `@latest` adds nothing functionally while diverging the three surfaces.
 */
export const PAIRING_COMMAND = `npx -y ${MCP_PACKAGE} add-site --enroll "<your_site_url>,<pairing_code>"`;
