import fs from 'fs/promises';
import path from 'path';
import ClientPage from './ClientPage';

function parseMarkdown(markdown: string): string {
  // Pre-process to ensure double newlines exist before and after list blocks
  let text = markdown
    .replace(/^([^- \r\n].*?)\r?\n-\s/gm, '$1\n\n- ')
    .replace(/^-\s(.*?)\r?\n([^- \r\n].*?)$/gm, '- $1\n\n$2');

  // Split by double newlines
  const blocks = text.split(/\n\s*\n/);
  
  const parsedBlocks = blocks.map(block => {
    let trimmed = block.trim();
    if (!trimmed) return '';

    // Escape HTML
    trimmed = trimmed
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    // Bold
    trimmed = trimmed.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

    // Links [text](url)
    trimmed = trimmed.replace(/\[(.*?)\]\((.*?)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer" style="color: #fbbf24; text-decoration: none; border-bottom: 1px dashed rgba(251, 191, 36, 0.4);">$1</a>');

    // Unordered list block
    if (trimmed.startsWith('- ')) {
      const lines = trimmed.split('\n');
      const listItems = lines.map(line => {
        const itemText = line.replace(/^-\s+/, '').trim();
        return `<li style="margin-bottom: 6px; list-style-type: disc;">${itemText}</li>`;
      });
      return `<ul style="margin: 4px 0 12px 0; padding-left: 20px; list-style-type: disc;">${listItems.join('\n')}</ul>`;
    }

    // Normal paragraph
    return `<p style="margin: 4px 0 12px 0; line-height: 1.6;">${trimmed.replace(/\n/g, '<br>')}</p>`;
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
