# Privacy Policy

Your privacy is extremely important to us. This policy explains how wpConnect handles data, security, and credentials.

## 1. 100% Decentralized Design
wpConnect is a decentralized connection bridge. All operations, posts, media uploads, and configuration syncs go directly from your local machine to your WordPress site over secure HTTPS. 

## 2. No Central Databases
We do not operate a stateful backend database, nor do we host user accounts or profile storage on our servers. 
- The central site `connectmwp.com` acts strictly as a stateless router during the initial setup handshake.
- Your site tokens and credentials are never stored, sent, or processed by our servers.

## 3. Local Storage of Tokens
When you authorize a connection, the connection token is saved:
1. Under your user profile's metadata on your own self-hosted WordPress database (hashed using SHA-256).
2. Inside a local JSON configuration file on your own computer (`~/.wpconnect.json`).

We have no access to these tokens. You have complete ownership and control. You can revoke any connection at any time directly in your WordPress settings page.

## 4. Contact
For any questions regarding this policy, contact us at [support@connectmwp.com](mailto:support@connectmwp.com).
