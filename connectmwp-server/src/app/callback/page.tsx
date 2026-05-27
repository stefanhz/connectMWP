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
      
      setToken(tokenVal);
      setSite(siteVal);
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
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        background: '#0d0d15',
        color: '#ffffff',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
      }}>
        <div style={{ textAlign: 'center', color: '#a1a1aa' }}>
          <p>Validating authentication tokens...</p>
        </div>
      </div>
    );
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'center',
      alignItems: 'center',
      background: 'radial-gradient(circle at top, #1e1e2f 0%, #0d0d15 100%)',
      color: '#ffffff',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      padding: '20px',
      boxSizing: 'border-box'
    }}>
      <div style={{
        maxWidth: '650px',
        width: '100%',
        background: 'rgba(255, 255, 255, 0.03)',
        backdropFilter: 'blur(16px)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '16px',
        padding: '40px',
        boxShadow: '0 20px 50px rgba(0,0,0,0.3)'
      }}>
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '64px',
            height: '64px',
            background: 'rgba(34, 197, 94, 0.1)',
            border: '2px solid rgb(34, 197, 94)',
            borderRadius: '50%',
            color: 'rgb(34, 197, 94)',
            fontSize: '32px',
            marginBottom: '16px'
          }}>
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
        <div style={{ marginBottom: '32px' }}>
          <h2 style={{ fontSize: '14px', fontWeight: '600', textTransform: 'uppercase', color: '#a1a1aa', letterSpacing: '1px', marginBottom: '12px' }}>
            Option 1: For Claude Code (CLI)
          </h2>
          <p style={{ fontSize: '13px', color: '#71717a', margin: '0 0 12px 0' }}>
            Run this command in your terminal to automatically add the MCP server to Claude Code:
          </p>
          <div style={{
            position: 'relative',
            background: 'rgba(0, 0, 0, 0.4)',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: '8px',
            padding: '16px',
            fontFamily: 'monospace',
            fontSize: '13px',
            wordBreak: 'break-all',
            paddingRight: '120px',
            lineHeight: '1.5'
          }}>
            {cliCommand}
            <button
              onClick={handleCopyCli}
              style={{
                position: 'absolute',
                top: '50%',
                right: '12px',
                transform: 'translateY(-50%)',
                background: copiedCli ? '#22c55e' : '#6366f1',
                border: 'none',
                color: '#ffffff',
                padding: '8px 14px',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '12px',
                fontWeight: '600',
                transition: 'background 0.2s'
              }}
            >
              {copiedCli ? 'Copied!' : 'Copy'}
            </button>
          </div>
        </div>

        {/* Tab 2: Custom JSON */}
        <div>
          <h2 style={{ fontSize: '14px', fontWeight: '600', textTransform: 'uppercase', color: '#a1a1aa', letterSpacing: '1px', marginBottom: '12px' }}>
            Option 2: For IDEs &amp; Platforms (Cursor, Claude Desktop, etc.)
          </h2>
          <p style={{ fontSize: '13px', color: '#71717a', margin: '0 0 12px 0' }}>
            Copy this JSON configuration block and paste it into your MCP configuration file (e.g., <code>claude_desktop_config.json</code>):
          </p>
          <div style={{
            position: 'relative',
            background: 'rgba(0, 0, 0, 0.4)',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: '8px',
            padding: '16px',
            fontFamily: 'monospace',
            fontSize: '13px',
            whiteSpace: 'pre-wrap',
            lineHeight: '1.5'
          }}>
            <button
              onClick={handleCopyJson}
              style={{
                position: 'absolute',
                top: '12px',
                right: '12px',
                background: copiedJson ? '#22c55e' : 'rgba(255,255,255,0.08)',
                border: 'none',
                color: '#ffffff',
                padding: '6px 12px',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '11px',
                fontWeight: '600',
                transition: 'background 0.2s'
              }}
            >
              {copiedJson ? 'Copied!' : 'Copy JSON'}
            </button>
            {jsonConfig}
          </div>
        </div>
      </div>

      <div style={{
        marginTop: '32px',
        fontSize: '13px',
        color: '#71717a',
        textAlign: 'center'
      }}>
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
