# Privacy Policy

Your privacy is extremely important to us. This policy explains how connectMWP handles data, security, and credentials.

## 1. 100% Decentralized Design
connectMWP is a decentralized connection bridge. All operations, posts, media uploads, and configuration syncs go directly from your local machine to your WordPress site over secure HTTPS. 

## 2. No Central Databases
We do not operate a stateful backend database, nor do we host user accounts or profile storage on our servers.
- The central site `connectmwp.com` serves only the public information pages and the plugin download. It is **not** involved in pairing, authentication, or publishing — your AI client connects straight to your own WordPress site over HTTPS.
- Your site keys, tokens, and credentials are never stored, sent, or processed by our servers.

## 3. Local Storage of Credentials
Your connection credentials are stored only in places you control:
1. On your own self-hosted WordPress site (in your user-profile metadata): for device pairing, only the client's **public** key; for ChatGPT (OAuth) and API-token connections, a **SHA-256 hash** of the token — never the raw secret.
2. On your own computer: for local AI clients, a configuration file (`~/.connectmwp.json`) plus a private key stored separately under `~/.connectmwp/`. The **private key never leaves your machine** — only the public key is ever transmitted, during pairing.

We have no access to any of these credentials. You have complete ownership and control, and can revoke any connection at any time directly in your WordPress settings page.

## 4. Contact
For any questions regarding this policy, contact us at [{{SUPPORT_EMAIL}}](mailto:{{SUPPORT_EMAIL}}).
