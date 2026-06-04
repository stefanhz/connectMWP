import fs from 'fs/promises';
import path from 'path';
import ClientPage from './ClientPage';
import { parseFaqMarkdown, applyConfigTokens } from '@/lib/markdown';

// T067: render at build time so content/faq.md is read during static generation
// (where the file is present + traced) and baked into static HTML — never read
// from process.cwd() at request time on a read-only serverless filesystem.
export const dynamic = 'force-static';

type Faq = { q: string; a: string };

const FALLBACK_FAQS: Faq[] = [
  {
    q: 'Error Loading FAQ',
    a: 'We were unable to load the FAQ documentation. Please try refreshing or check server logs.',
  },
];

/**
 * Classify an FAQ-load failure into a stable category so an operator scanning
 * logs can instantly tell a deploy/packaging bug (missing file) from a server
 * misconfig (permissions) from a content bug (present but unparseable).
 */
function classifyFaqLoadError(err: unknown): string {
  const code = (err as NodeJS.ErrnoException | null)?.code;
  if (code === 'ENOENT') return 'missing-file';
  if (code === 'EACCES' || code === 'EPERM') return 'permission-denied';
  return 'read-or-parse-error';
}

function logFaqLoadFailed(category: string, faqPath: string, err: unknown) {
  const e = err as NodeJS.ErrnoException | null;
  // Structured, discriminated diagnostic on the monitored stream (Vercel/Node
  // stdout). Per ground-rule R8: the failure is visible, not swallowed. No new
  // observability infra is introduced — none exists in this app.
  console.error(
    JSON.stringify({
      event: 'connectmwp.faq_load_failed',
      category,
      faqPath,
      code: e?.code ?? null,
      name: e?.name ?? null,
      message: e?.message ?? (err == null ? null : String(err)),
      at: new Date().toISOString(),
    })
  );
}

export default async function Page() {
  const faqPath = path.join(process.cwd(), 'content', 'faq.md');
  let faqs: Faq[] = [];

  try {
    const content = applyConfigTokens(await fs.readFile(faqPath, 'utf-8'));
    faqs = parseFaqMarkdown(content);

    if (faqs.length === 0) {
      // File present but yielded zero items — a content bug that would otherwise
      // render a silently-empty FAQ. Surface it as its own category, then degrade.
      logFaqLoadFailed('empty-or-unparseable', faqPath, null);
      faqs = FALLBACK_FAQS;
    }
  } catch (error) {
    logFaqLoadFailed(classifyFaqLoadError(error), faqPath, error);
    // FAQ is non-critical to the landing page's primary CTA (plugin download +
    // setup guide); degrade gracefully and log structured rather than 404 the
    // whole page.
    faqs = FALLBACK_FAQS;
  }

  return <ClientPage faqs={faqs} />;
}
