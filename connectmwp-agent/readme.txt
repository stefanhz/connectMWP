=== connectMWP ===
Contributors: (your-wordpress-org-username)
Tags: mcp, rest-api, ai, publishing, automation
Requires at least: 6.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 2.3.9
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Securely let your own AI client (Claude, Cursor) publish to this WordPress site over a signed, session-less connection. No login, no central server.

== Description ==

connectMWP turns your WordPress site into a secure endpoint that a local AI client on **your own machine** can publish to — drafting posts, uploading media, and managing tags and categories — without ever creating a WordPress login session.

Authentication uses per-request **Ed25519 cryptographic signatures**, not passwords or login cookies. Because no login session is ever established, the plugin works alongside 2FA and security plugins that police login state — there is no login state to police.

**The defining design choice: no central server sits in the path.** Your AI client talks straight to this site over HTTPS. connectmwp.com exists only to host this plugin's download and documentation — your content and your keys never pass through it.

= What it does =

* Exposes safe REST API and Admin-AJAX endpoints for posts, media, tags, and categories.
* Verifies every request with a detached Ed25519 signature over a deterministic canonical string (timestamp + nonce + method + path + query hash + body hash).
* Enforces a ±300-second timestamp window and per-request nonce replay protection.
* Runs WordPress capability checks (edit_posts / publish_posts / upload_files / manage_categories) against the bound user — no privilege is granted beyond what that user already has.
* Pairs with your local client through a one-time, single-use enrollment code generated in your WordPress admin. Your private key never leaves your machine; only the public key is ever transmitted.

= Who it is for =

Site owners who want to use a local AI assistant to draft and manage content on their own self-hosted WordPress site, while keeping credentials and content off any third-party server.

== External services ==

This plugin does **not** send your site's data to any external server. It is a *receiver*: a local client application running on your own computer initiates authenticated requests to this site.

To set up the connection you install the companion open-source client from the public npm registry (`connectmwp-mcp`) and run a one-time pairing command. The client is configured by you, runs on your machine, and connects directly to this site. The plugin makes no outbound HTTP calls of its own.

Project home and documentation: https://connectmwp.com
Source code (all components, GPL): https://github.com/stefanhz/connectMWP

No analytics, tracking, or telemetry is collected by this plugin.

== Installation ==

1. Upload the plugin to `/wp-content/plugins/` (or install it from the WordPress Plugins screen) and activate it.
2. Go to **Settings → connectMWP** and click **Generate Pairing Code**.
3. On your own computer, run the displayed command, e.g.
   `npx -y connectmwp-mcp add-site --enroll "https://your-site.com,<pairing_code>"`
4. The client generates a key pair locally, sends only the public key to your site, and stores the private key on your machine (mode 0600).
5. Configure your AI client (Claude Desktop/Code, Cursor) to launch `npx -y connectmwp-mcp` as an MCP server.

== Frequently Asked Questions ==

= Does this create a login on my site? =
No. There is no login session at any point. Each request is authorized by a one-time cryptographic signature and then checked against WordPress capabilities for the paired user.

= Does my content or password go through connectmwp.com? =
No. Your AI client talks directly to your site. connectmwp.com only hosts the plugin download and documentation.

= What happens if I lose or rotate my key? =
Generate a new pairing code in Settings → connectMWP and re-pair. A failed re-pair leaves any existing working key untouched.

= Does it work with security plugins and 2FA? =
Yes. Those tools police login state, and this plugin never establishes one.

== Changelog ==

= 2.0.36 =
* Distribution: the plugin is now packaged as `connectmwp.zip` and installs to a `connectmwp/` folder (matching the directory slug). No code or behavior change.

= 2.0.35 =
* Renamed the plugin from "connectMWP Agent" to "connectMWP" (text domain `connectmwp`). Display/identity only — no behavioral or auth-path change.

= 2.0.34 =
* WordPress.org listing assets: replaced the security-style shield icon with a chain-link connector icon and a matching banner, and filled in the source-repository and privacy-contact details. No code-path change.

= 2.0.33 =
* WordPress.org submission-prep: completed plugin header (Requires/License URI/Text Domain), corrected the description to the session-less Ed25519 model, added this readme and a GPLv2 license file. No behavioral change.

= 2.0.32 =
* Single-sourced the 10MB media upload cap across client and server.
* Added post_type guards on post update/delete and a generic taxonomy-create error message.
* Atomic single-use enrollment-code claim to close a concurrent double-consume window.
* Various admin-UI accessibility and observability improvements.

(Earlier history is maintained in the project CHANGELOG.)

== Upgrade Notice ==

= 2.0.36 =
Packaging only — plugin folder is now `connectmwp`. No functional change.

= 2.0.35 =
Plugin name shortened to "connectMWP". No functional change.

= 2.0.33 =
Packaging/metadata update for WordPress.org listing. No functional change from 2.0.32.
