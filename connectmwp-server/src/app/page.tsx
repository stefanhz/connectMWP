'use client';

import React, { useState } from 'react';

export default function Home() {
  const [siteUrl, setSiteUrl] = useState('');
  const [error, setError] = useState('');

  const handleConnect = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!siteUrl) {
      setError('Please enter your WordPress site URL.');
      return;
    }

    try {
      // Validate and clean URL
      let cleanUrl = siteUrl.trim();
      if (!/^https?:\/\//i.test(cleanUrl)) {
        cleanUrl = 'https://' + cleanUrl;
      }
      
      const parsedUrl = new URL(cleanUrl);
      const origin = parsedUrl.origin;

      // Redirect to WordPress OAuth authorize endpoint
      const callbackUrl = `${window.location.origin}/callback`;
      const state = Math.random().toString(36).substring(2, 15);
      
      const authUrl = `${origin}/wp-admin/admin.php?page=wpconnect-auth&callback=${encodeURIComponent(callbackUrl)}&state=${state}`;
      
      window.location.href = authUrl;
    } catch (err) {
      setError('Please enter a valid URL (e.g., https://mywebsite.com).');
    }
  };

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
        maxWidth: '550px',
        width: '100%',
        background: 'rgba(255, 255, 255, 0.03)',
        backdropFilter: 'blur(16px)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '16px',
        padding: '40px',
        boxShadow: '0 20px 50px rgba(0,0,0,0.3)',
        textAlign: 'center'
      }}>
        <div style={{
          display: 'inline-flex',
          padding: '12px',
          background: 'linear-gradient(135deg, #6366f1 0%, #a855f7 100%)',
          borderRadius: '12px',
          marginBottom: '24px',
          fontWeight: 'bold',
          fontSize: '22px',
          boxShadow: '0 8px 20px rgba(99, 102, 241, 0.3)'
        }}>
          MWP
        </div>

        <h1 style={{
          fontSize: '32px',
          fontWeight: '800',
          marginBottom: '12px',
          letterSpacing: '-0.5px',
          background: 'linear-gradient(to right, #ffffff, #a3a3a3)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent'
        }}>
          Connect My WordPress
        </h1>

        <p style={{
          fontSize: '15px',
          lineHeight: '1.6',
          color: '#a1a1aa',
          marginBottom: '32px'
        }}>
          Bridge your local AI clients (Claude Cowork, Cursor, etc.) directly to your WordPress sites. Secure, 100% private, and serverless.
        </p>

        <form onSubmit={handleConnect} style={{ width: '100%' }}>
          <div style={{ marginBottom: '20px', textAlign: 'left' }}>
            <label htmlFor="siteUrl" style={{
              display: 'block',
              fontSize: '12px',
              fontWeight: '600',
              textTransform: 'uppercase',
              letterSpacing: '1px',
              color: '#a1a1aa',
              marginBottom: '8px'
            }}>
              WordPress Site URL
            </label>
            <input
              id="siteUrl"
              type="text"
              placeholder="e.g. https://mywebsite.com"
              value={siteUrl}
              onChange={(e) => setSiteUrl(e.target.value)}
              style={{
                width: '100%',
                padding: '14px 18px',
                background: 'rgba(0, 0, 0, 0.3)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: '8px',
                color: '#ffffff',
                fontSize: '15px',
                outline: 'none',
                transition: 'border-color 0.2s',
                boxSizing: 'border-box'
              }}
            />
            {error && (
              <p style={{
                color: '#f87171',
                fontSize: '13px',
                marginTop: '8px',
                display: 'flex',
                alignItems: 'center',
                gap: '4px'
              }}>
                {error}
              </p>
            )}
          </div>

          <button type="submit" style={{
            width: '100%',
            padding: '14px',
            background: 'linear-gradient(135deg, #6366f1 0%, #a855f7 100%)',
            border: 'none',
            borderRadius: '8px',
            color: '#ffffff',
            fontWeight: '600',
            fontSize: '15px',
            cursor: 'pointer',
            boxShadow: '0 4px 12px rgba(99, 102, 241, 0.2)',
            transition: 'opacity 0.2s'
          }}>
            Connect WordPress Site
          </button>
        </form>
      </div>

      <div style={{
        marginTop: '32px',
        fontSize: '13px',
        color: '#71717a',
        display: 'flex',
        gap: '24px'
      }}>
        <span>Free &amp; Open Source</span>
        <span>•</span>
        <span>100% Direct Connection</span>
        <span>•</span>
        <span>Zero Data Stored</span>
      </div>
    </div>
  );
}
