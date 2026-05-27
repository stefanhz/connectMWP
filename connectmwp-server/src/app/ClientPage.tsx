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
  const [warning, setWarning] = useState('');
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
    setWarning('');

    if (!isValid) {
      return;
    }

    setIsVerifying(true);

    try {
      // Validate and clean URL
      let cleanUrl = siteUrl.trim();
      let resolvedUrl = cleanUrl;
      let isHardError = false;
      let warningMsg = '';

      try {
        const response = await fetch(`/api/verify-site?url=${encodeURIComponent(cleanUrl)}`);
        if (response.ok) {
          const data = await response.json();
          if (data.url) {
            resolvedUrl = data.url;
            setSiteUrl(resolvedUrl); // Dynamically update the input value so the user sees the verified protocol
          }
          if (data.status === 'WARNING') {
            if (data.warning === 'DNS_FAILURE') {
              isHardError = true;
              setError(data.message || 'DNS resolution failed.');
            } else {
              warningMsg = data.message + ' Attempting to connect anyway...';
              setWarning(warningMsg);
            }
          }
        }
      } catch (verifyErr) {
        console.warn('Protocol verification failed, falling back:', verifyErr);
      }

      if (isHardError) {
        setIsVerifying(false);
        return;
      }

      // If we have a soft warning, pause for 1.5s so the user can read the notice
      if (warningMsg) {
        await new Promise((resolve) => setTimeout(resolve, 1500));
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
    <div className="app-container">
      {/* Main Container Card */}
      <div className="card-container">
        <div className="logo-badge">
          MWP
        </div>

        {/* Development Warning Notice */}
        <div>
          <div className="dev-badge">
            <span>⚠️</span> Active Development — Use at your own risk
          </div>
        </div>

        <h1 className="card-title">
          Connect My WordPress
        </h1>

        <p className="card-desc">
          Bridge your local AI clients (Claude Cowork, Cursor, etc.) directly to your WordPress sites. Secure, 100% private, and serverless.
        </p>

        <p className="download-banner">
          First time? Download the <a href="/connectmwp-agent.zip" download>WordPress Agent Plugin (ZIP)</a> and activate it on your site.
        </p>

        <form onSubmit={handleConnect} style={{ width: '100%' }}>
          <div className="input-group">
            <label htmlFor="siteUrl" className="input-label">
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
              className="input-field"
            />
            {displayError && (
              <p className="error-text">
                {displayError}
              </p>
            )}
            {warning && (
              <p className="warning-text">
                ⚠️ {warning}
              </p>
            )}
            <p className="tip-text">
              💡 <strong>Tip:</strong> Log in to your WordPress dashboard in this browser tab first to ensure a smooth redirection.
            </p>
          </div>

          {/* Advanced Settings Toggle & Panel */}
          <div className="advanced-group">
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="advanced-toggle"
            >
              <span className={`advanced-arrow ${showAdvanced ? 'open' : ''}`}>
                ▶
              </span>
              Advanced Settings
            </button>

            {showAdvanced && (
              <div className="advanced-panel">
                <label htmlFor="adminPath" className="advanced-panel-label">
                  Custom Admin Path
                </label>
                <input
                  id="adminPath"
                  type="text"
                  placeholder="/wp-admin"
                  value={adminPath}
                  onChange={(e) => setAdminPath(e.target.value)}
                  className="advanced-panel-input"
                />
                <p className="advanced-panel-desc">
                  Change this if you use security plugins (like WPS Hide Login) that rename the admin path.
                </p>
              </div>
            )}
          </div>

          <button 
            type="submit" 
            disabled={!isValid || isVerifying}
            className="connect-btn"
          >
            {isVerifying ? 'Verifying site...' : 'Connect WordPress Site'}
          </button>
        </form>
      </div>

      {/* FAQ Accordion Card */}
      <div className="faq-container">
        <h2 className="faq-title">
          Frequently Asked Questions
        </h2>
        {faqs.map((item, index) => (
          <div key={index} className="faq-item">
            <button
              onClick={() => setOpenFaq(openFaq === index ? null : index)}
              className="faq-trigger"
            >
              <span>{item.q}</span>
              <span className={`faq-arrow ${openFaq === index ? 'open' : ''}`}>
                ▼
              </span>
            </button>
            {openFaq === index && (
              <div
                className="faq-content"
                dangerouslySetInnerHTML={{ __html: item.a }}
              />
            )}
          </div>
        ))}
      </div>

      {/* Footer Links & Info */}
      <footer className="footer-container">
        <div className="footer-links">
          <Link href="/legal/about" className="footer-link">About</Link>
          <span>•</span>
          <Link href="/legal/privacy" className="footer-link">Privacy Policy</Link>
          <span>•</span>
          <Link href="/legal/terms" className="footer-link">Terms of Service</Link>
          <span>•</span>
          <a href="mailto:support@connectmwp.com" className="footer-link">Support</a>
          <span>•</span>
          <a href="https://buy.stripe.com/aFa8wQ0rH2PQ4Msama5kk0l" target="_blank" rel="noopener noreferrer" className="footer-link coffee">☕ Buy me a coffee</a>
        </div>
        <div className="footer-credit">
          Brought to you by <a href="https://2morrow.ai" target="_blank" rel="noopener noreferrer">2morrow.ai</a>
        </div>
        <div className="footer-version">
          connectMWP Client v1.2.4
        </div>
      </footer>
    </div>
  );
}
