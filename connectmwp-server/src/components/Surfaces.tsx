import React from 'react';

/**
 * Shared page-shell + glass-card surfaces (T059 / closes T034 CSS half).
 *
 * The full-viewport brand wrapper and the frosted "glass" card were previously
 * hand-copied verbatim across ClientPage.tsx and legal/[slug]/page.tsx — a brand
 * tweak meant editing two files and drifting the first one forgotten. These are
 * the single source of truth for both surfaces. Class strings are byte-identical
 * to the originals (only relocated), so there is no visual change.
 *
 * Plain (non-'use client') components: safe to render from both the server
 * legal page and the client ClientPage.
 */

export function PageShell({
  align = 'start',
  children,
}: {
  align?: 'start' | 'center';
  children: React.ReactNode;
}) {
  const justify = align === 'center' ? 'justify-center' : 'justify-start';
  return (
    <div
      className={`min-h-screen w-full flex flex-col ${justify} items-center bg-[image:var(--brand-radial)] text-white font-sans px-5 py-20 box-border`}
    >
      {children}
    </div>
  );
}

export function GlassCard({
  className = '',
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div
      className={`w-full bg-white/3 backdrop-blur-[16px] border border-white/8 rounded-2xl p-10 shadow-card text-left ${className}`}
    >
      {children}
    </div>
  );
}
