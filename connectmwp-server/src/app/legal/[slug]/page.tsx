import fs from 'fs/promises';
import path from 'path';
import Link from 'next/link';
import { Metadata } from 'next';
import { parseMarkdown } from '@/lib/markdown';
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
    parsedHtml = `<h1 class="md-h1">Page Not Found</h1><p class="md-p">The requested legal page could not be located.</p>`;
  }

  return (
    <div className="min-h-screen w-full flex flex-col justify-center items-center bg-[radial-gradient(circle_at_top,_#1e1e2f_0%,_#0d0d15_100%)] text-white font-sans px-5 py-20 box-border">
      <div className="max-w-[700px] w-full bg-white/3 backdrop-blur-[16px] border border-white/8 rounded-2xl p-10 shadow-[0_20px_50px_rgba(0,0,0,0.3)] text-left">
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
          className="text-[14px] leading-relaxed text-zinc-300"
          dangerouslySetInnerHTML={{ __html: parsedHtml }}
        />
      </div>
    </div>
  );
}
