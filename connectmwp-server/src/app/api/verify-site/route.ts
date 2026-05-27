import { NextResponse } from 'next/server';
import dns from 'dns/promises';

// dns resolution requires the Node.js runtime (not Edge).
export const runtime = 'nodejs';

/**
 * Block private, loopback, and link-local IP ranges (SSRF defense).
 * Mirrors the connectmwp-mcp client's isPrivateIp so both ends are consistent.
 */
function isPrivateIp(ip: string): boolean {
  if (/^(127\.|10\.|169\.254\.|192\.168\.)/.test(ip)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true;
  if (ip === '::1' || ip === '::' || ip.startsWith('fe80:') || ip.startsWith('fc00:') || ip.startsWith('fd00:')) return true;
  return false;
}

/**
 * Resolve a hostname and confirm every address is public. Rejects internal
 * names and private/loopback/link-local targets so this endpoint cannot be
 * abused to probe the server's internal network (SSRF).
 * Residual: DNS rebinding between this check and fetch() is mitigated by
 * disabling redirect-following on the probe below.
 */
async function isSafePublicHost(hostname: string): Promise<boolean> {
  const lower = hostname.toLowerCase();
  if (
    lower === 'localhost' ||
    lower.endsWith('.localhost') ||
    lower.endsWith('.local') ||
    lower.endsWith('.internal')
  ) {
    return false;
  }
  // IP literal (incl. IPv6) — check directly without DNS.
  if (/^[0-9.]+$/.test(hostname) || hostname.includes(':')) {
    return !isPrivateIp(hostname);
  }
  try {
    const records = await dns.lookup(hostname, { all: true });
    if (!records.length) return false;
    return records.every((r) => !isPrivateIp(r.address));
  } catch {
    return false;
  }
}

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

  // SSRF guard: reject internal/private targets before making any outbound request.
  const hostname = cleanDomain.split(':')[0];
  if (!(await isSafePublicHost(hostname))) {
    return NextResponse.json(
      { status: 'BLOCKED', error: 'Target host is not a permitted public address.' },
      { status: 400 }
    );
  }

  interface ProbeResult {
    ok: boolean;
    error?: 'TIMEOUT' | 'FORBIDDEN' | 'DNS_FAILURE' | 'NETWORK_ERROR' | 'SSL_ERROR';
    status?: number;
  }

  // Helper to probe a URL with a timeout
  const probe = async (url: string): Promise<ProbeResult> => {
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
        cache: 'no-store',
        // Do not follow redirects — prevents a public host from bouncing the
        // probe to an internal address (SSRF via redirect / DNS rebinding).
        redirect: 'manual'
      });

      if (res.status === 403) {
        return { ok: true, error: 'FORBIDDEN', status: 403 };
      }

      return { ok: true, status: res.status };
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        return { ok: false, error: 'TIMEOUT' };
      }

      const errMsg = err instanceof Error ? err.message : '';
      if (errMsg.includes('ENOTFOUND') || errMsg.includes('getaddrinfo') || errMsg.includes('DNS')) {
        return { ok: false, error: 'DNS_FAILURE' };
      }
      if (errMsg.includes('SSL') || errMsg.includes('cert') || errMsg.includes('handshake')) {
        return { ok: false, error: 'SSL_ERROR' };
      }
      
      return { ok: false, error: 'NETWORK_ERROR' };
    } finally {
      clearTimeout(id);
    }
  };

  // Try HTTPS first
  const httpsUrl = `https://${cleanDomain}`;
  const httpsResult = await probe(httpsUrl);

  if (httpsResult.ok && httpsResult.error !== 'FORBIDDEN') {
    return NextResponse.json({ url: httpsUrl, status: 'OK' });
  }

  // Fallback to HTTP if HTTPS fails
  const httpUrl = `http://${cleanDomain}`;
  const httpResult = await probe(httpUrl);

  if (httpResult.ok && httpResult.error !== 'FORBIDDEN') {
    return NextResponse.json({ url: httpUrl, status: 'OK' });
  }

  // Check if either was a firewall block (403 Forbidden)
  if (httpsResult.error === 'FORBIDDEN' || httpResult.error === 'FORBIDDEN') {
    return NextResponse.json({
      url: httpsUrl,
      status: 'WARNING',
      warning: 'FORBIDDEN',
      message: 'Connection was blocked (403 Forbidden). This is likely caused by a security plugin or WAF (e.g., Cloudflare) blocking API probes.'
    });
  }

  // Collect the final error details for the fallback response
  const lastError = httpsResult.error || httpResult.error || 'NETWORK_ERROR';
  const errorMessages = {
    TIMEOUT: 'Connection timed out (site failed to respond within 2s).',
    DNS_FAILURE: 'DNS resolution failed (the domain name does not exist).',
    SSL_ERROR: 'SSL handshake failed (the site might have an invalid or missing certificate).',
    NETWORK_ERROR: 'Site was completely unreachable (connection refused or offline).'
  };

  const message = errorMessages[lastError as keyof typeof errorMessages] || 'Site is unreachable.';

  return NextResponse.json({
    url: httpsUrl,
    status: 'WARNING',
    warning: lastError,
    message: message
  });
}
