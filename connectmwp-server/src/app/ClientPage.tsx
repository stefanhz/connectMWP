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
  const [openFaq, setOpenFaq] = useState<number | null>(null);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const pairingCmd = 'npx -y connectmwp-mcp@latest add-site --enroll "<your_site_url>,<pairing_code>"';

  const handleCopyCmd = () => {
    navigator.clipboard.writeText(pairingCmd);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  return (
    <div className="app-container">
      {/* Main Container Card */}
      <div className="card-container" style={{ textAlign: 'left' }}>
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '8px' }}>
          <div className="logo-badge" style={{ marginBottom: 0 }}>
            MWP
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <div className="dev-badge">
            <span>⚠️</span> Active Development — Use at your own risk
          </div>
        </div>

        <h1 className="card-title" style={{ textAlign: 'center', display: 'block', margin: '0 auto 16px auto' }}>
          Connect My WordPress
        </h1>

        <p className="card-desc" style={{ textAlign: 'center', marginBottom: '24px' }}>
          Bridge your local AI clients (Claude Desktop, Cursor, etc.) directly to your WordPress sites. Secure, 100% private, and session-less.
        </p>

        <div className="download-banner" style={{ textAlign: 'center', marginBottom: '28px' }}>
          ⚡ <strong>Step 1:</strong> Download the <a href="/connectmwp-agent.zip" download>WordPress Agent Plugin (ZIP)</a> and activate it on your WordPress site.
        </div>

        <h3 style={{ fontSize: '15px', fontWeight: '700', color: '#ffffff', marginBottom: '12px' }}>
          🚀 Quick Setup &amp; Pairing Guide
        </h3>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', fontSize: '14px', color: '#a1a1aa', lineHeight: '1.5' }}>
          <div>
            <strong style={{ color: '#ffffff' }}>1. Install the Plugin:</strong> Upload and activate the downloaded ZIP file in your WordPress dashboard under <em>Plugins → Add New</em>.
          </div>
          <div>
            <strong style={{ color: '#ffffff' }}>2. Generate a Pairing Code:</strong> Navigate to <em>Settings → connectMWP</em> in your WordPress dashboard and click <strong style={{ color: '#fbbf24' }}>Generate Pairing Code</strong>.
          </div>
          <div>
            <strong style={{ color: '#ffffff' }}>3. Run Local Setup:</strong> Copy the enrollment string generated on your site, and run the following pairing command in your local terminal:
            <div className="code-block-container" style={{ marginTop: '8px', paddingRight: '80px', background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {pairingCmd}
              <button
                onClick={handleCopyCmd}
                className={`copy-btn ${copiedCmd ? 'copied' : ''}`}
                style={{ right: '8px' }}
              >
                {copiedCmd ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </div>
        </div>
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
          connectMWP Client v2.0.8
        </div>
      </footer>
    </div>
  );
}
