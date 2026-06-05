# Privacy Policy

_Last updated: 4 June 2026._

connectMWP is provided by Stefan Heinz (2morrow.ai). Protecting your privacy matters to us, and the product is deliberately designed to collect as little of your data as technically possible. This policy explains, in plain terms, what happens to your data when you use the connectMWP website, the WordPress plugin, and the local client.

## The short version
connectMWP is decentralized by design. When you connect an AI client to your WordPress site, the connection runs **directly** between your own machine (or AI client) and your own WordPress site. Your content, credentials, and keys do not pass through — and are not stored on — our servers. We do not operate user accounts, we do not keep a database of your sites, and we do not sell or rent any data, because we do not hold it.

## 1. Who is responsible
The connectMWP software and the website at connectmwp.com are operated by Stefan Heinz (2morrow.ai). For any privacy question, contact us at [{{SUPPORT_EMAIL}}](mailto:{{SUPPORT_EMAIL}}).

## 2. The website (connectmwp.com)
The website exists only to explain the product, host these legal pages, and serve the plugin download. Like virtually every website, our hosting provider automatically records standard technical request logs — such as IP address, browser type, referring page, and the date and time of each request — for security and to keep the service running. This is a standard, legitimate-interest use under data-protection law. We do not use these logs to identify or profile you.

We do **not** use advertising or analytics cookies, tracking pixels, or third-party trackers on connectmwp.com.

## 3. The connection between your AI client and your WordPress site
All operations — drafting posts, uploading media, syncing configuration — go **directly** from your local machine or AI client to your own WordPress site over HTTPS. The central site connectmwp.com is **never** part of pairing, authentication, or publishing.

We have no access to:
- the content you create or publish;
- your WordPress login or any site credentials;
- the keys or tokens that authorize the connection.

## 4. Where your credentials are stored
Your connection credentials are stored only in places **you** control:

- On your own self-hosted WordPress site (in your user-profile metadata): for device pairing, only the client's **public** key; for ChatGPT (OAuth) and API-token connections, a **SHA-256 hash** of the token — never the raw secret.
- On your own computer: for local AI clients, a configuration file (`~/.connectmwp.json`) plus a private key stored separately under `~/.connectmwp/`. The **private key never leaves your machine** — only the public key is ever transmitted, during pairing.

You can revoke any connection at any time from your WordPress settings page, which immediately blocks future access.

## 5. If you contact us
If you email us, we receive whatever you put in that message (your email address and its contents) and use it only to respond to you. We do not add you to any mailing list.

## 6. Your rights
Because we hold essentially no personal data about you, there is very little for us to disclose, correct, or delete — but you can always ask. Depending on where you live (for example, under the EU/UK GDPR or the California CCPA), you may have the right to request access to, correction of, or deletion of any personal data we hold; to object to or restrict our processing of it; and to lodge a complaint with your local data-protection authority. We do **not** sell or share personal information for advertising, and we never have. To exercise any of these rights, email us at [{{SUPPORT_EMAIL}}](mailto:{{SUPPORT_EMAIL}}).

## 7. Third-party links
Our website and documentation may link to third-party sites (for example Node.js, GitHub, or your AI provider). We do not control those sites and are not responsible for their privacy practices — please read their own policies.

## 8. Changes to this policy
We may update this policy from time to time; the "last updated" date above will change accordingly. Material changes will be reflected on this page.

## 9. Contact
For any question about this policy or the data we may hold, contact Stefan Heinz (2morrow.ai) at [{{SUPPORT_EMAIL}}](mailto:{{SUPPORT_EMAIL}}).
