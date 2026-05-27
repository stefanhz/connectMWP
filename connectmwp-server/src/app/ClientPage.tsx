'use client';

import React, { useState } from 'react';
import Link from 'next/link';

interface ClientPageProps {
  faqs: {
    q: string;
    a: string;
  }[];
}

export default function ClientPage({ faqs }: ClientPageProps) {
  const [siteUrl, setSiteUrl] = useState('');
  const [error, setError] = useState('');
  const [openFaq, setOpenFaq] = useState<number | null>(null);

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
      
      const authUrl = `${origin}/wp-admin/admin.php?page=connectmwp-auth&callback=${encodeURIComponent(callbackUrl)}&state=${state}`;
      
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
      justifyContent: 'flex-start',
      alignItems: 'center',
      background: 'radial-gradient(circle at top, #1e1e2f 0%, #0d0d15 100%)',
      color: '#ffffff',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      padding: '80px 20px 40px 20px',
      boxSizing: 'border-box'
    }}>
      {/* Main Container Card */}
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

        {/* Development Warning Notice */}
        <div>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 16px',
            background: 'rgba(245, 158, 11, 0.08)',
            border: '1px solid rgba(245, 158, 11, 0.25)',
            borderRadius: '30px',
            fontSize: '12.5px',
            color: '#fbbf24',
            marginBottom: '24px',
            fontWeight: '500',
            lineHeight: '1.4',
            textAlign: 'left'
          }}>
            <span>⚠️</span> Active Development — Use at your own risk
          </div>
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

      {/* FAQ Accordion Card */}
      <div style={{
        maxWidth: '550px',
        width: '100%',
        marginTop: '40px',
        background: 'rgba(255, 255, 255, 0.02)',
        border: '1px solid rgba(255, 255, 255, 0.06)',
        borderRadius: '16px',
        padding: '35px',
        boxSizing: 'border-box',
        boxShadow: '0 10px 30px rgba(0,0,0,0.15)'
      }}>
        <h2 style={{
          fontSize: '18px',
          fontWeight: '700',
          color: '#ffffff',
          marginTop: 0,
          marginBottom: '20px',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          paddingBottom: '12px'
        }}>
          Frequently Asked Questions
        </h2>
        {faqs.map((item, index) => (
          <div key={index} style={{
            borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
            paddingBottom: '12px',
            marginBottom: '12px'
          }}>
            <button
              onClick={() => setOpenFaq(openFaq === index ? null : index)}
              style={{
                width: '100%',
                background: 'none',
                border: 'none',
                color: '#ffffff',
                fontSize: '14px',
                fontWeight: '600',
                textAlign: 'left',
                cursor: 'pointer',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '6px 0',
                outline: 'none'
              }}
            >
              <span>{item.q}</span>
              <span style={{
                color: '#818cf8',
                transform: openFaq === index ? 'rotate(180deg)' : 'rotate(0deg)',
                transition: 'transform 0.2s',
                fontSize: '10px'
              }}>
                ▼
              </span>
            </button>
            {openFaq === index && (
              <div
                style={{
                  fontSize: '13.5px',
                  lineHeight: '1.6',
                  color: '#a1a1aa',
                  margin: '8px 0 0 0',
                  animation: 'fadeIn 0.2s ease-out',
                  textAlign: 'left'
                }}
                dangerouslySetInnerHTML={{ __html: item.a }}
              />
            )}
          </div>
        ))}
      </div>

      {/* Footer Links & Info */}
      <footer style={{
        marginTop: '50px',
        fontSize: '13px',
        color: '#71717a',
        textAlign: 'center',
        lineHeight: '1.8'
      }}>
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          gap: '15px',
          marginBottom: '12px',
          flexWrap: 'wrap'
        }}>
          <Link href="/legal/about" style={{ color: '#a1a1aa', textDecoration: 'none' }}>About</Link>
          <span>•</span>
          <Link href="/legal/privacy" style={{ color: '#a1a1aa', textDecoration: 'none' }}>Privacy Policy</Link>
          <span>•</span>
          <Link href="/legal/terms" style={{ color: '#a1a1aa', textDecoration: 'none' }}>Terms of Service</Link>
          <span>•</span>
          <a href="mailto:support@connectmwp.com" style={{ color: '#a1a1aa', textDecoration: 'none' }}>Support</a>
          <span>•</span>
          <a href="https://buy.stripe.com/aFa8wQ0rH2PQ4Msama5kk0l" target="_blank" rel="noopener noreferrer" style={{ color: '#fbbf24', textDecoration: 'none', fontWeight: '600' }}>☕ Buy me a coffee</a>
        </div>
        <div style={{ marginBottom: '15px' }}>
          Brought to you by <a href="https://2morrow.ai" target="_blank" rel="noopener noreferrer" style={{ color: '#818cf8', textDecoration: 'none' }}>2morrow.ai</a>
        </div>
        <div style={{ fontSize: '11px', opacity: 0.6 }}>
          connectMWP Client v1.2.3
        </div>
      </footer>
    </div>
  );
}
