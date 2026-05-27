import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const targetUrl = searchParams.get('url');

  if (!targetUrl) {
    return NextResponse.json({ error: 'Missing url parameter' }, { status: 400 });
  }

  let cleanDomain = targetUrl.trim();
  // Strip protocol for probing domain directly
  cleanDomain = cleanDomain.replace(/^https?:\/\//i, '');
  // Remove path or query string to get only origin/host
  cleanDomain = cleanDomain.split('/')[0];

  if (!cleanDomain) {
    return NextResponse.json({ error: 'Invalid url parameter' }, { status: 400 });
  }

  // Helper to probe a URL with a timeout
  const probe = async (url: string): Promise<boolean> => {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 2000);

    try {
      const res = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': '*/*'
        },
        cache: 'no-store'
      });
      // If we got any response (even status codes like 403 or 401), the protocol is active.
      return true;
    } catch (err) {
      return false;
    } finally {
      clearTimeout(id);
    }
  };

  // Try HTTPS first
  const httpsUrl = `https://${cleanDomain}`;
  const isHttpsOk = await probe(httpsUrl);

  if (isHttpsOk) {
    return NextResponse.json({ url: httpsUrl });
  }

  // Fallback to HTTP
  const httpUrl = `http://${cleanDomain}`;
  const isHttpOk = await probe(httpUrl);

  if (isHttpOk) {
    return NextResponse.json({ url: httpUrl });
  }

  // If both fail, default to HTTPS as it is the secure standard
  return NextResponse.json({ url: httpsUrl });
}
