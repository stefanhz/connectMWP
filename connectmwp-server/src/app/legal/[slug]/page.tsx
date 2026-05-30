import fs from 'fs/promises';
import path from 'path';
import Link from 'next/link';
import { Metadata } from 'next';
import { parseMarkdown } from '@/lib/markdown';
import { PageShell, GlassCard } from '@/components/Surfaces';
import pkg from '../../../../package.json';

interface PageProps {
  params: Promise<{
    slug: string;
  }>;
}

// Generate static params so they are pre-rendered at build time
export async function generateStaticParams() {
  return [
    { slug: 'privacy' },
    { slug: 'terms' },
    { slug: 'about' }
  ];
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { slug } = await params;
  const allowedSlugs = ['privacy', 'terms', 'about'];
  if (!allowedSlugs.includes(slug)) {
    return {
      title: 'Page Not Found — connectMWP',
      description: 'The requested legal page could not be located.'
    };
  }
  const capitalized = slug.charAt(0).toUpperCase() + slug.slice(1);
  return {
    title: `${capitalized} — connectMWP`,
    description: `Read the ${slug} guidelines for connectmwp.com. Secure, decentralized WordPress AI integration.`
  };
}

export default async function LegalPage({ params }: PageProps) {
  const { slug } = await params;
  let parsedHtml = '';
  try {
    const allowedSlugs = ['privacy', 'terms', 'about'];
    if (!allowedSlugs.includes(slug)) {
      throw new Error('Invalid or unauthorized slug parameter.');
    }
    const filePath = path.join(process.cwd(), 'content', `${slug}.md`);
    const rawContent = await fs.readFile(filePath, 'utf-8');
    parsedHtml = parseMarkdown(rawContent);
  } catch {
    parsedHtml = `<h1>Page Not Found</h1><p>The requested legal page could not be located.</p>`;
  }

  return (
    <PageShell align="center">
      <GlassCard className="max-w-[700px]">
        {/* Header navigation */}
        <div className="flex justify-between items-center mb-6 pb-4 border-b border-white/8">
          <Link href="/" className="text-zinc-400 no-underline text-sm hover:text-white transition-colors">
            ← Back Home
          </Link>
          <div className="text-[11px] text-zinc-500 opacity-60">
            connectMWP v{pkg.version}
          </div>
        </div>

        {/* Dynamic HTML Content */}
        <div
          className="prose prose-invert max-w-none text-zinc-300"
          dangerouslySetInnerHTML={{ __html: parsedHtml }}
        />
      </GlassCard>
    </PageShell>
  );
}
