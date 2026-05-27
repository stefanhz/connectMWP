export function parseMarkdown(markdown: string): string {
  // Pre-process to ensure double newlines exist before and after list blocks
  const text = markdown
    .replace(/^([^- \r\n].*?)\r?\n-\s/gm, '$1\n\n- ')
    .replace(/^-\s(.*?)\r?\n([^- \r\n].*?)$/gm, '- $1\n\n$2');

  // Split by double newlines to process paragraphs and blocks
  const blocks = text.split(/\n\s*\n/);
  
  const parsedBlocks = blocks.map(block => {
    let trimmed = block.trim();
    if (!trimmed) return '';

    // Escape HTML
    trimmed = trimmed
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    // Markdown Headers (# H1, ## H2, ### H3)
    if (trimmed.startsWith('# ')) {
      const headerText = trimmed.replace(/^#\s+/, '').trim();
      return `<h1 class="md-h1">${headerText}</h1>`;
    }
    if (trimmed.startsWith('## ')) {
      const headerText = trimmed.replace(/^##\s+/, '').trim();
      return `<h2 class="md-h2">${headerText}</h2>`;
    }
    if (trimmed.startsWith('### ')) {
      const headerText = trimmed.replace(/^###\s+/, '').trim();
      return `<h3 class="md-h3">${headerText}</h3>`;
    }

    // Bold text (**text**)
    trimmed = trimmed.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

    // Markdown Links ([text](url)) - Render with class instead of inline styles
    trimmed = trimmed.replace(
      /\[(.*?)\]\((.*?)\)/g, 
      '<a href="$2" target="_blank" rel="noopener noreferrer" class="md-link">$1</a>'
    );

    // Markdown Unordered lists (- item)
    if (trimmed.startsWith('- ')) {
      const lines = trimmed.split('\n');
      const listItems = lines.map(line => {
        const itemText = line.replace(/^-\s+/, '').trim();
        return `<li class="md-li">${itemText}</li>`;
      });
      return `<ul class="md-ul">${listItems.join('\n')}</ul>`;
    }

    // Normal paragraph block
    return `<p class="md-p">${trimmed.replace(/\n/g, '<br>')}</p>`;
  });

  return parsedBlocks.join('\n');
}

export function parseFaqMarkdown(markdown: string): { q: string; a: string }[] {
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
