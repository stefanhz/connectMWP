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
  const [touched, setTouched] = useState(false);
  const [openFaq, setOpenFaq] = useState<number | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [adminPath, setAdminPath] = useState('/wp-admin');

  const isValidSiteUrl = (val: string): boolean => {
    const clean = val.trim();
    if (!clean) return false;
    
    // Explicitly reject email addresses
    if (clean.includes('@')) return false;

    let urlStr = clean;
    if (!/^https?:\/\//i.test(urlStr)) {
      urlStr = 'https://' + urlStr;
    }
    try {
      const url = new URL(urlStr);
      const hostname = url.hostname;
      
      // Prevent credentials URLs (e.g. stefan@sheinz.com parsed as user credentials)
      if (url.username || url.password) {
        return false;
      }

      if (!hostname.includes('.')) {
        return hostname === 'localhost';
      }
      return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(hostname) || hostname === 'localhost';
    } catch (e) {
      return false;
    }
  };

  const handleBlur = () => {
    setTouched(true);
    let val = siteUrl.trim();
    if (val && !/^https?:\/\//i.test(val) && !val.includes('@')) {
      setSiteUrl('https://' + val);
    }
  };

  const isValid = isValidSiteUrl(siteUrl);

  const displayError = (touched && siteUrl.trim() !== '' && !isValid)
    ? 'Please enter a valid website URL (e.g., mywebsite.com).'
    : error;

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);
    setError('');

    if (!isValid) {
      return;
    }

    setIsVerifying(true);

    try {
      // Validate and clean URL
      let cleanUrl = siteUrl.trim();
      let resolvedUrl = cleanUrl;

      try {
        const response = await fetch(`/api/verify-site?url=${encodeURIComponent(cleanUrl)}`);
        if (response.ok) {
          const data = await response.json();
          if (data.url) {
            resolvedUrl = data.url;
            setSiteUrl(resolvedUrl); // Dynamically update the input value so the user sees the verified protocol
          }
        }
      } catch (verifyErr) {
        console.warn('Protocol verification failed, falling back:', verifyErr);
      }

      // Final fallback if verification completely failed to add a protocol
      if (!/^https?:\/\//i.test(resolvedUrl)) {
        resolvedUrl = 'https://' + resolvedUrl;
        setSiteUrl(resolvedUrl);
      }
      
      const parsedUrl = new URL(resolvedUrl);
      const origin = parsedUrl.origin;

      // Clean and normalize custom admin path
      let cleanPath = adminPath.trim();
      if (!cleanPath.startsWith('/')) {
        cleanPath = '/' + cleanPath;
      }
      if (cleanPath.endsWith('/')) {
        cleanPath = cleanPath.slice(0, -1);
      }
      if (!cleanPath || cleanPath === '/') {
        cleanPath = '/wp-admin';
      }

      // Redirect to WordPress OAuth authorize endpoint
      const callbackUrl = `${window.location.origin}/callback`;
      const state = Math.random().toString(36).substring(2, 15);
      
      const authUrl = `${origin}${cleanPath}/admin.php?page=connectmwp-auth&callback=${encodeURIComponent(callbackUrl)}&state=${state}`;
      
      window.location.href = authUrl;
    } catch (err) {
      setError('Failed to connect. Please check the URL.');
      setIsVerifying(false);
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
          background: 'linear-gradient(135deg, #f97316 0%, #f59e0b 100%)',
          borderRadius: '12px',
          marginBottom: '24px',
          fontWeight: 'bold',
          fontSize: '22px',
          boxShadow: '0 8px 20px rgba(249, 115, 22, 0.3)'
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
          marginBottom: '20px'
        }}>
          Bridge your local AI clients (Claude Cowork, Cursor, etc.) directly to your WordPress sites. Secure, 100% private, and serverless.
        </p>

        <p style={{
          fontSize: '13.5px',
          color: '#fbbf24',
          marginBottom: '32px',
          padding: '12px',
          background: 'rgba(251, 191, 36, 0.05)',
          borderRadius: '8px',
          border: '1px dashed rgba(251, 191, 36, 0.2)',
          lineHeight: '1.5'
        }}>
          First time? Download the <a href="/connectmwp-agent.zip" download style={{ color: '#fbbf24', textDecoration: 'underline', fontWeight: '600' }}>WordPress Agent Plugin (ZIP)</a> and activate it on your site.
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
              onBlur={handleBlur}
              onChange={(e) => {
                setSiteUrl(e.target.value);
                if (e.target.value.trim() === '') {
                  setTouched(false);
                }
              }}
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
            {displayError && (
              <p style={{
                color: '#f87171',
                fontSize: '13px',
                marginTop: '8px',
                display: 'flex',
                alignItems: 'center',
                gap: '4px'
              }}>
                {displayError}
              </p>
            )}
            <p style={{
              fontSize: '12.5px',
              color: '#a1a1aa',
              marginTop: '10px',
              lineHeight: '1.4'
            }}>
              💡 <strong>Tip:</strong> Log in to your WordPress dashboard in this browser tab first to ensure a smooth redirection.
            </p>
          </div>

          {/* Advanced Settings Toggle & Panel */}
          <div style={{ marginBottom: '24px', textAlign: 'left' }}>
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              style={{
                background: 'none',
                border: 'none',
                color: '#a1a1aa',
                fontSize: '13px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '4px 0',
                outline: 'none',
                fontWeight: '500'
              }}
            >
              <span style={{
                fontSize: '9px',
                color: '#fbbf24',
                display: 'inline-block',
                transform: showAdvanced ? 'rotate(90deg)' : 'rotate(0deg)',
                transition: 'transform 0.2s'
              }}>
                ▶
              </span>
              Advanced Settings
            </button>

            {showAdvanced && (
              <div style={{
                marginTop: '12px',
                padding: '16px',
                background: 'rgba(255, 255, 255, 0.02)',
                border: '1px solid rgba(255, 255, 255, 0.05)',
                borderRadius: '8px',
                animation: 'fadeIn 0.2s ease-out'
              }}>
                <label htmlFor="adminPath" style={{
                  display: 'block',
                  fontSize: '11px',
                  fontWeight: '600',
                  textTransform: 'uppercase',
                  letterSpacing: '1px',
                  color: '#a1a1aa',
                  marginBottom: '6px'
                }}>
                  Custom Admin Path
                </label>
                <input
                  id="adminPath"
                  type="text"
                  placeholder="/wp-admin"
                  value={adminPath}
                  onChange={(e) => setAdminPath(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '10px 14px',
                    background: 'rgba(0, 0, 0, 0.3)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: '6px',
                    color: '#ffffff',
                    fontSize: '14px',
                    outline: 'none',
                    boxSizing: 'border-box'
                  }}
                />
                <p style={{
                  fontSize: '11.5px',
                  color: '#71717a',
                  marginTop: '6px',
                  lineHeight: '1.4',
                  marginBottom: 0
                }}>
                  Change this if you use security plugins (like WPS Hide Login) that rename the admin path.
                </p>
              </div>
            )}
          </div>

          <button 
            type="submit" 
            disabled={!isValid || isVerifying}
            style={{
              width: '100%',
              padding: '14px',
              background: (isValid && !isVerifying)
                ? 'linear-gradient(135deg, #f97316 0%, #f59e0b 100%)' 
                : 'linear-gradient(135deg, #4b5563 0%, #374151 100%)',
              border: 'none',
              borderRadius: '8px',
              color: (isValid && !isVerifying) ? '#ffffff' : '#9ca3af',
              fontWeight: '600',
              fontSize: '15px',
              cursor: (isValid && !isVerifying) ? 'pointer' : 'not-allowed',
              boxShadow: (isValid && !isVerifying) ? '0 4px 12px rgba(249, 115, 22, 0.2)' : 'none',
              opacity: (isValid && !isVerifying) ? 1 : 0.4,
              transition: 'all 0.2s ease'
            }}
          >
            {isVerifying ? 'Verifying site...' : 'Connect WordPress Site'}
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
                color: '#fbbf24',
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
          Brought to you by <a href="https://2morrow.ai" target="_blank" rel="noopener noreferrer" style={{ color: '#fbbf24', textDecoration: 'none' }}>2morrow.ai</a>
        </div>
        <div style={{ fontSize: '11px', opacity: 0.6 }}>
          connectMWP Client v1.2.3
        </div>
      </footer>
    </div>
  );
}
