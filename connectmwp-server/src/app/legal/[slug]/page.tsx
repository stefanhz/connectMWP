import fs from 'fs/promises';
import path from 'path';
import Link from 'next/link';
import { Metadata } from 'next';

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

/**
 * Custom lightweight Markdown parser
 */
function parseMarkdown(markdown: string): string {
  // Escape HTML
  let html = markdown
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Headers (H1, H2, H3)
  html = html.replace(/^# (.*?)$/gm, '<h1>$1</h1>');
  html = html.replace(/^## (.*?)$/gm, '<h2>$1</h2>');
  html = html.replace(/^### (.*?)$/gm, '<h3>$1</h3>');

  // Bold
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

  // Links [text](url)
  html = html.replace(/\[(.*?)\]\((.*?)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');

  // Lists (Unordered)
  html = html.replace(/^- (.*?)$/gm, '<li>$1</li>');
  
  // Wrap contiguous <li> elements in <ul>
  html = html.replace(/(<li>[\s\S]*?<\/li>)+/g, '<ul>$&</ul>');

  // Paragraphs
  const blocks = html.split(/\n\s*\n/);
  const parsedBlocks = blocks.map(block => {
    const trimmed = block.trim();
    if (!trimmed) return '';
    if (trimmed.startsWith('<h') || trimmed.startsWith('<ul') || trimmed.startsWith('<li')) {
      return trimmed;
    }
    return `<p>${trimmed.replace(/\n/g, '<br>')}</p>`;
  });

  return parsedBlocks.join('\n');
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
  } catch (error) {
    parsedHtml = `<h1>Page Not Found</h1><p>The requested legal page could not be located.</p>`;
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
      padding: '40px 20px',
      boxSizing: 'border-box'
    }}>
      <div style={{
        maxWidth: '800px',
        width: '100%',
        background: 'rgba(255, 255, 255, 0.03)',
        backdropFilter: 'blur(16px)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '16px',
        padding: '40px',
        boxShadow: '0 20px 50px rgba(0,0,0,0.3)',
      }}>
        {/* Header navigation */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
          paddingBottom: '20px',
          marginBottom: '30px'
        }}>
          <Link href="/" style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            color: '#a1a1aa',
            textDecoration: 'none',
            fontSize: '14px',
            fontWeight: '600',
            transition: 'color 0.2s'
          }}>
            ← Back Home
          </Link>
          <div style={{
            padding: '6px 12px',
            background: 'linear-gradient(135deg, #f97316 0%, #f59e0b 100%)',
            borderRadius: '6px',
            fontSize: '12px',
            fontWeight: 'bold',
            boxShadow: '0 4px 10px rgba(249, 115, 22, 0.2)'
          }}>
            connectMWP v1.2.3
          </div>
        </div>

        {/* Dynamic HTML Content */}
        <div 
          className="legal-content"
          dangerouslySetInnerHTML={{ __html: parsedHtml }} 
          style={{
            lineHeight: '1.7',
            fontSize: '15px',
            color: '#d1d1d6'
          }}
        />
      </div>

      {/* Inline styles for markdown compiled HTML tags */}
      <style dangerouslySetInnerHTML={{ __html: `
        .legal-content h1 {
          font-size: 32px;
          font-weight: 800;
          color: #ffffff;
          margin-top: 0;
          margin-bottom: 24px;
          letter-spacing: -0.5px;
        }
        .legal-content h2 {
          font-size: 20px;
          font-weight: 700;
          color: #ffffff;
          margin-top: 35px;
          margin-bottom: 15px;
        }
        .legal-content h3 {
          font-size: 16px;
          font-weight: 600;
          color: #ffffff;
          margin-top: 25px;
          margin-bottom: 10px;
        }
        .legal-content p {
          margin-bottom: 20px;
        }
        .legal-content strong {
          color: #ffffff;
        }
        .legal-content a {
          color: #fbbf24;
          text-decoration: none;
          border-bottom: 1px dashed rgba(251, 191, 36, 0.4);
          transition: border-color 0.2s;
        }
        .legal-content a:hover {
          border-bottom-style: solid;
        }
        .legal-content ul {
          margin-left: 20px;
          margin-bottom: 20px;
          list-style-type: disc;
        }
        .legal-content li {
          margin-bottom: 8px;
        }
      `}} />
    </div>
  );
}
