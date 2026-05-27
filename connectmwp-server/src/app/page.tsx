import fs from 'fs/promises';
import path from 'path';
import ClientPage from './ClientPage';

function parseMarkdown(markdown: string): string {
  // Escape HTML
  let html = markdown
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Bold
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

  // Links [text](url)
  html = html.replace(/\[(.*?)\]\((.*?)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer" style="color: #818cf8; text-decoration: none;">$1</a>');

  // Lists (Unordered)
  html = html.replace(/^- (.*?)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>[\s\S]*?<\/li>)+/g, '<ul style="margin: 8px 0; padding-left: 20px;">$&</ul>');

  // Paragraphs
  const blocks = html.split(/\n\s*\n/);
  const parsedBlocks = blocks.map(block => {
    const trimmed = block.trim();
    if (!trimmed) return '';
    if (trimmed.startsWith('<ul') || trimmed.startsWith('<li')) {
      return trimmed;
    }
    return `<p style="margin: 8px 0;">${trimmed.replace(/\n/g, '<br>')}</p>`;
  });

  return parsedBlocks.join('\n');
}

function parseFaqMarkdown(markdown: string) {
  const items: { q: string; a: string }[] = [];
  // Match any ## header as a question, followed by body text up to next header or end
  const regex = /^##\s+(.*?)\r?\n([\s\S]*?)(?=(?:^##\s+)|\Z)/gm;
  let match;
  while ((match = regex.exec(markdown)) !== null) {
    const q = match[1].trim();
    const a = parseMarkdown(match[2].trim());
    items.push({ q, a });
  }
  return items;
}

export default async function Page() {
  const faqPath = path.join(process.cwd(), 'content', 'faq.md');
  let faqs: { q: string; a: string }[] = [];
  try {
    const content = await fs.readFile(faqPath, 'utf-8');
    faqs = parseFaqMarkdown(content);
  } catch (error) {
    console.error('Failed to read FAQ file:', error);
  }

  return <ClientPage faqs={faqs} />;
}
