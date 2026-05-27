import fs from 'fs/promises';
import path from 'path';
import ClientPage from './ClientPage';
import { parseFaqMarkdown } from '@/lib/markdown';

export default async function Page() {
  const faqPath = path.join(process.cwd(), 'content', 'faq.md');
  let faqs: { q: string; a: string }[] = [];
  try {
    const content = await fs.readFile(faqPath, 'utf-8');
    faqs = parseFaqMarkdown(content);
  } catch (error) {
    console.error('Failed to read FAQ file:', error);
    faqs = [{ q: 'Error Loading FAQ', a: 'We were unable to load the FAQ documentation. Please try refreshing or check server logs.' }];
  }

  return <ClientPage faqs={faqs} />;
}
