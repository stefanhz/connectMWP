'use client';

import React, { useEffect, useState } from 'react';

export default function Callback() {
  const [token, setToken] = useState('');
  const [site, setSite] = useState('');
  const [copiedCli, setCopiedCli] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      // Check fragment (hash) first for secure modern flow (C-2 Fix)
      let tokenVal = '';
      let siteVal = '';
      
      if (window.location.hash) {
        const hashStr = window.location.hash.substring(1);
        const hashParams = new URLSearchParams(hashStr);
        tokenVal = hashParams.get('token') || '';
        siteVal = hashParams.get('site') || '';
      }
      
      // Fallback to query params if hash is empty (backward compatibility)
      if (!tokenVal || !siteVal) {
        const searchParams = new URLSearchParams(window.location.search);
        tokenVal = searchParams.get('token') || '';
        siteVal = searchParams.get('site') || '';
      }
      
      setTimeout(() => {
        setToken(tokenVal);
        setSite(siteVal);
      }, 0);
    }
  }, []);

  const cliCommand = `claude mcp add connectmwp npx -y connectmwp-mcp --site "${site}" --token "${token}"`;

  const jsonConfig = JSON.stringify({
    mcpServers: {
      connectmwp: {
        command: "npx",
        args: [
          "-y",
          "connectmwp-mcp",
          "--site",
          site,
          "--token",
          token
        ]
      }
    }
  }, null, 2);

  const handleCopyCli = () => {
    navigator.clipboard.writeText(cliCommand);
    setCopiedCli(true);
    setTimeout(() => setCopiedCli(false), 2000);
  };

  const handleCopyJson = () => {
    navigator.clipboard.writeText(jsonConfig);
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  if (!token || !site) {
    return (
      <div className="app-container" style={{ justifyContent: 'center' }}>
        <div style={{ textAlign: 'center', color: '#a1a1aa' }}>
          <p>Validating authentication tokens...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="app-container" style={{ justifyContent: 'center' }}>
      <div className="callback-card-container">
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div className="success-badge">
            ✓
          </div>
          <h1 style={{ fontSize: '28px', fontWeight: '800', margin: '0 0 8px 0' }}>
            Authorization Successful!
          </h1>
          <p style={{ color: '#a1a1aa', margin: '0', fontSize: '15px' }}>
            Your WordPress site at <a href={site} target="_blank" rel="noopener noreferrer" style={{ color: '#818cf8', textDecoration: 'none' }}>{site}</a> has authorized the connection.
          </p>
        </div>

        {/* Tab 1: Claude Code CLI */}
        <div className="option-group">
          <h2 className="option-title">
            Option 1: For Claude Code (CLI)
          </h2>
          <p className="option-desc">
            Run this command in your terminal to automatically add the MCP server to Claude Code:
          </p>
          <div className="code-block-container">
            {cliCommand}
            <button
              onClick={handleCopyCli}
              className={`copy-btn ${copiedCli ? 'copied' : ''}`}
            >
              {copiedCli ? 'Copied!' : 'Copy'}
            </button>
          </div>
        </div>

        {/* Tab 2: Custom JSON */}
        <div className="option-group" style={{ marginBottom: 0 }}>
          <h2 className="option-title">
            Option 2: For IDEs &amp; Platforms (Cursor, Claude Desktop, etc.)
          </h2>
          <p className="option-desc">
            Copy this JSON configuration block and paste it into your MCP configuration file (e.g., <code>claude_desktop_config.json</code>):
          </p>
          <div className="code-block-container json-mode">
            <button
              onClick={handleCopyJson}
              className={`copy-btn json-mode ${copiedJson ? 'copied' : ''}`}
            >
              {copiedJson ? 'Copied!' : 'Copy JSON'}
            </button>
            {jsonConfig}
          </div>
        </div>
      </div>

      <div className="footer-container" style={{ marginTop: '32px' }}>
        <p style={{ margin: '0 0 8px 0' }}>
          <strong>Security Note:</strong> This page ran completely in your browser.
        </p>
        <p style={{ margin: '0' }}>
          Your token was never sent to our servers. Keep it private.
        </p>
      </div>
    </div>
  );
}
