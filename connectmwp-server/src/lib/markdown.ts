import config from '@/config.json';

// Site links live in ONE place (src/config.json), never hardcoded in source or
// markdown. Authors write `{{TOKEN}}` placeholders in the .md files; this map
// resolves them to the canonical URLs at render time. Add a token here when a
// new config-driven link is introduced.
const CONFIG_TOKENS: Record<string, string> = {
  '{{DONATE_URL}}': config.links.donate,
  '{{COMPANY_URL}}': config.links.company,
  '{{REPO_URL}}': config.links.repo,
  '{{SUPPORT_EMAIL}}': config.supportEmail,
};

/**
 * Replace `{{TOKEN}}` placeholders in raw markdown with values from
 * src/config.json BEFORE parsing. Unknown tokens are left verbatim (visible in
 * output) so a typo surfaces instead of silently vanishing. Call this on the
 * raw file content right after reading it, ahead of parseMarkdown/parseFaqMarkdown.
 */
export function applyConfigTokens(markdown: string): string {
  return markdown.replace(/\{\{[A-Z0-9_]+\}\}/g, (m) => CONFIG_TOKENS[m] ?? m);
}

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

    // Markdown Headers (# H1, ## H2, ### H3) — emit plain semantic tags; styling
    // comes from the `prose` (Tailwind Typography) wrapper on the consuming
    // container, not bespoke `.md-*` classes.
    if (trimmed.startsWith('# ')) {
      const headerText = trimmed.replace(/^#\s+/, '').trim();
      return `<h1>${headerText}</h1>`;
    }
    if (trimmed.startsWith('## ')) {
      const headerText = trimmed.replace(/^##\s+/, '').trim();
      return `<h2>${headerText}</h2>`;
    }
    if (trimmed.startsWith('### ')) {
      const headerText = trimmed.replace(/^###\s+/, '').trim();
      return `<h3>${headerText}</h3>`;
    }

    // Bold text (**text**)
    trimmed = trimmed.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

    // Markdown Links ([text](url)) - sanitize URL (preserve link safety: only
    // http(s)/relative/mailto allowed, else '#'; always target=_blank +
    // rel=noopener noreferrer). `prose` styles the anchor; no bespoke class.
    trimmed = trimmed.replace(
      /\[(.*?)\]\((.*?)\)/g,
      (match, linkText, url) => {
        const trimmedUrl = url.trim();
        const isSafe = /^https?:\/\//i.test(trimmedUrl) || trimmedUrl.startsWith('/') || trimmedUrl.startsWith('mailto:');
        const safeUrl = isSafe ? trimmedUrl : '#';
        return `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer">${linkText}</a>`;
      }
    );

    // Markdown Unordered lists (- item)
    if (trimmed.startsWith('- ')) {
      const lines = trimmed.split('\n');
      const listItems = lines.map(line => {
        const itemText = line.replace(/^-\s+/, '').trim();
        return `<li>${itemText}</li>`;
      });
      return `<ul>${listItems.join('\n')}</ul>`;
    }

    // Normal paragraph block
    return `<p>${trimmed.replace(/\n/g, '<br>')}</p>`;
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
