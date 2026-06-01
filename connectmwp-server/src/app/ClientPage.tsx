'use client';

import React, { useState, useRef, useEffect } from 'react';
import Link from 'next/link';
import pkg from '../../package.json';
import { PAIRING_COMMAND } from '@/lib/constants';
import { PageShell, GlassCard } from '@/components/Surfaces';

const COPY_FEEDBACK_MS = 2000;

interface ClientPageProps {
  faqs: {
    q: string;
    a: string;
  }[];
}

export default function ClientPage({ faqs }: ClientPageProps) {
  const [openFaq, setOpenFaq] = useState<number | null>(null);
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);

  const pairingCmd = PAIRING_COMMAND;

  // Track the "Copied!" reset timer so rapid re-clicks don't stack timers and
  // so a timer never fires setState after the component unmounts.
  const copyTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // T056: gate the success UI on the clipboard write actually resolving. A
  // rejection (non-secure context, unfocused doc, restrictive permissions
  // policy) must NOT show "Copied!" — otherwise the user pastes nothing.
  const handleCopyCmd = () => {
    const flash = (setter: (v: boolean) => void) => {
      setter(true);
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
      copyTimeoutRef.current = setTimeout(() => setter(false), COPY_FEEDBACK_MS);
    };
    navigator.clipboard.writeText(pairingCmd)
      .then(() => flash(setCopiedCmd))
      .catch(() => flash(setCopyFailed));
  };

  useEffect(() => {
    return () => {
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
    };
  }, []);

  return (
    <PageShell>
      {/* Main Container Card */}
      <GlassCard className="max-w-[550px]">
        <div className="flex justify-center mb-2">
          <div className="inline-flex p-3 bg-gradient-to-br from-orange-500 to-amber-500 rounded-xl mb-0 font-bold text-2xl shadow-brand-glow text-white">
            MWP
          </div>
        </div>

        <div className="flex justify-center">
          <div className="inline-flex items-center gap-2 px-4 py-2 bg-amber-500/8 border border-amber-500/25 rounded-[30px] text-[12.5px] text-amber-400 mb-6 font-medium leading-normal text-left">
            <span>⚠️</span> Active Development — Use at your own risk
          </div>
        </div>

        <h1 className="text-3xl font-extrabold mb-3 tracking-tight bg-gradient-to-r from-white to-zinc-400 bg-clip-text text-transparent text-center block mx-auto">
          Connect My WordPress
        </h1>

        <p className="text-[15px] leading-relaxed text-zinc-400 mb-6 text-center">
          Bridge your local AI clients (Claude Desktop, Cursor, etc.) directly to your WordPress sites. Secure, 100% private, and session-less.
        </p>

        <div className="text-[13.5px] text-amber-400 mb-7 p-3 bg-amber-400/5 rounded-lg border border-dashed border-amber-400/20 leading-normal text-center">
          ⚡ <strong>Step 1:</strong> Download the <a href="/connectmwp.zip" download className="text-amber-400 underline font-semibold">connectMWP plugin (ZIP)</a> and activate it on your WordPress site.
        </div>

        <h3 className="text-[15px] font-bold text-white mb-3">
          🚀 Quick Setup &amp; Pairing Guide
        </h3>

        <div className="flex flex-col gap-4 text-sm text-zinc-400 leading-relaxed">
          <div>
            <strong className="text-white">1. Install the Plugin:</strong> Upload and activate the downloaded ZIP file in your WordPress dashboard under <em>Plugins → Add New</em>.
          </div>
          <div>
            <strong className="text-white">2. Generate a Pairing Code:</strong> Navigate to <em>Settings → connectMWP</em> in your WordPress dashboard and click <strong className="text-amber-400">Generate Pairing Code</strong>.
          </div>
          <div>
            <strong className="text-white">3. Run Local Setup:</strong> Copy the enrollment string generated on your site, and run the following pairing command in your local terminal:
            <div className="relative mt-2 pr-20 bg-black/50 border border-white/10 rounded-lg p-4 font-mono text-[13px] break-all leading-normal text-left">
              {pairingCmd}
              <button
                onClick={handleCopyCmd}
                className={`absolute top-1/2 right-3 -translate-y-1/2 border-none text-white px-3.5 py-2 rounded font-semibold text-xs cursor-pointer transition-colors ${copiedCmd ? 'bg-emerald-500 hover:bg-emerald-600' : copyFailed ? 'bg-red-500 hover:bg-red-600' : 'bg-indigo-500 hover:bg-indigo-600'}`}
                aria-label="Copy pairing command to clipboard"
              >
                {copiedCmd ? 'Copied!' : copyFailed ? 'Press ⌘C' : 'Copy'}
              </button>
            </div>
          </div>
        </div>
      </GlassCard>

      {/* FAQ Accordion Card */}
      <div className="max-w-[550px] w-full mt-10 bg-white/2 border border-white/6 rounded-2xl p-9 box-border shadow-card-soft">
        <h2 className="text-lg font-bold text-white mt-0 mb-5 border-b border-white/8 pb-3">
          Frequently Asked Questions
        </h2>
        {faqs.map((item, index) => (
          <div key={index} className="border-b border-white/5 pb-3 mb-3 last:border-b-0 last:mb-0 last:pb-0">
            <button
              onClick={() => setOpenFaq(openFaq === index ? null : index)}
              className="w-full bg-transparent border-none text-white text-[14px] font-semibold text-left cursor-pointer flex justify-between items-center py-1.5 outline-none"
              aria-expanded={openFaq === index}
              aria-controls={`faq-content-${index}`}
            >
              <span>{item.q}</span>
              <span className={`text-amber-400 transition-transform duration-200 text-[10px] ${openFaq === index ? 'rotate-180' : 'rotate-0'}`} aria-hidden="true">
                ▼
              </span>
            </button>
            {/* Body is always rendered so `aria-controls` always resolves and the
                injected HTML isn't re-parsed on every toggle; the `hidden` utility
                (display:none) removes the collapsed body from layout AND the a11y
                tree. `prose prose-invert` styles the now-classless markdown tags. */}
            <div
              id={`faq-content-${index}`}
              className={`prose prose-invert prose-sm max-w-none mt-2 text-left ${openFaq === index ? 'block' : 'hidden'}`}
              dangerouslySetInnerHTML={{ __html: item.a }}
            />
          </div>
        ))}
      </div>

      {/* Footer Links & Info */}
      <footer className="mt-12 text-[13px] text-zinc-500 text-center leading-loose">
        <div className="flex justify-center gap-4 mb-3 flex-wrap">
          <Link href="/legal/about" className="text-zinc-400 no-underline hover:text-white transition-colors">About</Link>
          <span>•</span>
          <Link href="/legal/privacy" className="text-zinc-400 no-underline hover:text-white transition-colors">Privacy Policy</Link>
          <span>•</span>
          <Link href="/legal/terms" className="text-zinc-400 no-underline hover:text-white transition-colors">Terms of Service</Link>
          <span>•</span>
          <a href="mailto:support@connectmwp.com" className="text-zinc-400 no-underline hover:text-white transition-colors">Support</a>
          <span>•</span>
          <a href="https://buy.stripe.com/aFa8wQ0rH2PQ4Msama5kk0l" target="_blank" rel="noopener noreferrer" className="text-amber-400 font-semibold hover:text-amber-500 transition-colors">☕ Buy me a coffee</a>
        </div>
        <div className="mb-4">
          Brought to you by <a href="https://2morrow.ai" target="_blank" rel="noopener noreferrer" className="text-amber-400 no-underline hover:text-amber-500 transition-colors">2morrow.ai</a>
        </div>
        <div className="text-[11px] opacity-60">
          connectMWP Client v{pkg.version}
        </div>
      </footer>
    </PageShell>
  );
}
