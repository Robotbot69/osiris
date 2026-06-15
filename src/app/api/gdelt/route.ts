import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

/**
 * OSIRIS / Hermes — GDELT radar.
 *
 * Upstream OSIRIS used the old GDELT GEO endpoint, which currently returns
 * HTTP 404 from this server.  Use the supported DOC 2.0 article API instead
 * and add lightweight coordinate/type heuristics so MapLibre/radar consumers
 * still receive event-like objects.
 */

const CACHE_TTL_MS = 5 * 60 * 1000;
const STALE_CACHE_TTL_MS = 30 * 60 * 1000;
const CIRCUIT_OPEN_MS = 2 * 60 * 1000;
const GDELT_TIMEOUT_MS = 3_500;
const GDELT_MAX_ATTEMPTS = 2;
const GDELT_QUERY_DELAY_MS = 250;
const GDELT_MAX_RATE_LIMITS = 2;
const GDELT_MAX_TIMEOUTS = 3;
const GDELT_REQUEST_DEADLINE_MS = 18_000;
const GDELT_QUERIES = [
  'bitcoin',
  'crypto',
  'hormuz',
  '"red sea"',
  'sanctions',
  'exploit',
];

const KEYWORD_COORDS: Record<string, [number, number]> = {
  hormuz: [26.566, 56.250],
  'red sea': [20.280, 38.512],
  suez: [30.585, 32.265],
  panama: [9.080, -79.680],
  taiwan: [23.697, 120.960],
  iran: [32.427, 53.688],
  israel: [31.046, 34.851],
  gaza: [31.416, 34.333],
  ukraine: [49.487, 31.272],
  russia: [61.524, 105.318],
  china: [35.861, 104.195],
  'united states': [38.907, -77.036],
  europe: [50.850, 4.350],
};

let cache: { ts: number; payload: any } | null = null;
let circuitOpenUntil = 0;

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function coordsFor(text: string): [number, number] | null {
  const lower = text.toLowerCase();
  for (const [keyword, coords] of Object.entries(KEYWORD_COORDS)) {
    if (lower.includes(keyword)) return coords;
  }
  return null;
}

function typeFor(text: string): string {
  const lower = text.toLowerCase();
  if (/(bitcoin|crypto|stablecoin|exchange|hack|exploit|mining|defi|wallet)/.test(lower)) return 'crypto';
  if (/(oil|brent|wti|lng|shipping|hormuz|suez|red sea|panama)/.test(lower)) return 'energy';
  if (/(sanctions|ofac|capital controls|bank crisis)/.test(lower)) return 'sanctions';
  return 'geopolitical';
}

function isRecent(value: string, maxAgeHours = 72) {
  if (!value) return true;
  const ts = Date.parse(value);
  if (!Number.isFinite(ts)) return true;
  return Date.now() - ts <= maxAgeHours * 60 * 60 * 1000;
}

async function fetchNewsFallback(maxrecords = 20) {
  const baseUrl = process.env.OSIRIS_BASE_URL || 'http://127.0.0.1:3030';
  const url = `${baseUrl.replace(/\/$/, '')}/api/news`;
  const res = await fetch(url, {
    signal: AbortSignal.timeout(5_000),
    headers: { Accept: 'application/json', 'User-Agent': 'Hermes-OSIRIS-GDELT-Fallback/1.0' },
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`OSIRIS news fallback HTTP ${res.status}`);
  const data = await res.json();
  return (data.news || []).filter((item: any) => isRecent(String(item.published || item.published_date || ''))).slice(0, maxrecords).map((item: any, idx: number) => {
    const title = item.title || item.description || 'OSIRIS news event';
    const coords = Array.isArray(item.coords) && item.coords.length >= 2 ? item.coords : coordsFor(`${title} ${item.description || ''}`);
    const type = typeFor(`${title} ${item.description || ''}`);
    return {
      id: `news-fallback-${item.id || idx}`,
      lat: coords ? coords[0] : null,
      lng: coords ? coords[1] : null,
      coords_default: !coords || Boolean(item.coords_default),
      name: title,
      url: item.link || '',
      html: '',
      type,
      count: Number(item.risk_score || 1) || 1,
      domain: item.source || '',
      language: '',
      query: 'osiris-news-fallback',
      sourcecountry: '',
      seendate: item.published || '',
      shareimage: '',
      fallback_source: 'OSIRIS /api/news',
    };
  });
}

async function fetchDocEvents(query: string, maxrecords = 8) {
  const url = new URL('https://api.gdeltproject.org/api/v2/doc/doc');
  url.searchParams.set('query', query);
  url.searchParams.set('mode', 'ArtList');
  url.searchParams.set('format', 'json');
  url.searchParams.set('timespan', '24h');
  url.searchParams.set('maxrecords', String(maxrecords));
  url.searchParams.set('sort', 'datedesc');

  const res = await fetch(url.toString(), {
    signal: AbortSignal.timeout(GDELT_TIMEOUT_MS),
    headers: { Accept: 'application/json', 'User-Agent': 'Hermes-OSIRIS-GDELT/1.0' },
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`GDELT DOC HTTP ${res.status}`);
  const contentType = res.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    const text = (await res.text()).slice(0, 160);
    throw new Error(`GDELT DOC non-json response: ${text}`);
  }
  const data = await res.json();
  return (data.articles || []).map((article: any, idx: number) => {
    const title = article.title || 'GDELT article';
    const text = `${title} ${article.domain || ''} ${article.sourcecountry || ''}`;
    const coords = coordsFor(text);
    const type = typeFor(text);
    return {
      id: `gdelt-${type}-${idx}-${article.seendate || ''}`,
      lat: coords ? coords[0] : null,
      lng: coords ? coords[1] : null,
      coords_default: !coords,
      name: title,
      url: article.url || '',
      html: '',
      type,
      count: 1,
      domain: article.domain || '',
      language: article.language || '',
      query,
      sourcecountry: article.sourcecountry || '',
      seendate: article.seendate || '',
      shareimage: article.socialimage || '',
    };
  });
}

async function fetchDocEventsWithRetry(query: string, maxrecords = 8) {
  let lastError: Error | null = null;
  for (let attempt = 0; attempt < GDELT_MAX_ATTEMPTS; attempt += 1) {
    try {
      return await fetchDocEvents(query, maxrecords);
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      const isRateLimit = lastError.message.includes('HTTP 429');
      const isRetryable = isRateLimit || /HTTP 5\d\d/.test(lastError.message);
      if (!isRetryable || attempt === GDELT_MAX_ATTEMPTS - 1) break;
      const backoff = isRateLimit ? 1_500 + Math.floor(Math.random() * 700) : 500 + Math.floor(Math.random() * 500);
      await sleep(backoff);
    }
  }
  throw lastError || new Error(`GDELT fetch failed for ${query}`);
}

function staleCachePayload(errors: string[]) {
  if (!cache || Date.now() - cache.ts > STALE_CACHE_TTL_MS) return null;
  return {
    ...cache.payload,
    stale: true,
    source_mode: 'stale_cache',
    timestamp: new Date().toISOString(),
    errors,
  };
}

export async function GET() {
  if (cache && Date.now() - cache.ts < CACHE_TTL_MS) {
    return NextResponse.json({
      ...cache.payload,
      source_mode: cache.payload.source_mode || 'cache_fresh',
    }, {
      headers: { 'Cache-Control': 'public, s-maxage=300, stale-while-revalidate=600' },
    });
  }

  const allEvents: any[] = [];
  const errors: string[] = [];
  const upstreamStatus: Record<string, string> = {};
  const seen = new Set<string>();
  let rateLimitHits = 0;
  let timeoutHits = 0;
  let stoppedEarly = false;
  const deadline = Date.now() + GDELT_REQUEST_DEADLINE_MS;

  try {
    if (Date.now() < circuitOpenUntil) {
      const cached = staleCachePayload([`GDELT circuit open until ${new Date(circuitOpenUntil).toISOString()}`]);
      if (cached) {
        return NextResponse.json(cached, {
          headers: { 'Cache-Control': 'public, s-maxage=60, stale-while-revalidate=300' },
          status: 200,
        });
      }
    }

    for (const query of GDELT_QUERIES) {
      if (Date.now() > deadline) {
        stoppedEarly = true;
        errors.push(`deadline: GDELT request exceeded ${GDELT_REQUEST_DEADLINE_MS}ms`);
        break;
      }
      try {
        const events = await fetchDocEventsWithRetry(query);
        upstreamStatus[query] = 'ok';
        for (const event of events) {
          const key = event.url || `${event.name}:${event.seendate}`;
          if (seen.has(key)) continue;
          seen.add(key);
          allEvents.push(event);
          if (allEvents.length >= 30) break;
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message.includes('HTTP 429')) {
          upstreamStatus[query] = 'rate_limited';
          rateLimitHits += 1;
        } else if (message.includes('timed out') || message.includes('aborted')) {
          upstreamStatus[query] = 'timeout';
          timeoutHits += 1;
        } else {
          upstreamStatus[query] = 'error';
        }
        errors.push(`${query}: ${message}`);
        if (rateLimitHits >= GDELT_MAX_RATE_LIMITS || timeoutHits >= GDELT_MAX_TIMEOUTS) {
          circuitOpenUntil = Date.now() + CIRCUIT_OPEN_MS;
          stoppedEarly = true;
          break;
        }
      }
      if (allEvents.length >= 30) break;
      await sleep(GDELT_QUERY_DELAY_MS);
    }
    for (const query of GDELT_QUERIES) {
      if (!upstreamStatus[query]) upstreamStatus[query] = stoppedEarly ? 'skipped_circuit' : 'skipped';
    }
  } catch (error) {
    errors.push(error instanceof Error ? error.message : String(error));
  }

  let fallback = false;
  if (allEvents.length === 0 && errors.length > 0) {
    try {
      const fallbackEvents = await fetchNewsFallback();
      for (const event of fallbackEvents) {
        const key = event.url || `${event.name}:${event.seendate}`;
        if (seen.has(key)) continue;
        seen.add(key);
        allEvents.push(event);
      }
      fallback = allEvents.length > 0;
    } catch (error) {
      errors.push(`news-fallback: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  if (allEvents.length === 0 && errors.length > 0) {
    const cached = staleCachePayload(errors);
    if (cached) {
      return NextResponse.json(cached, {
        headers: { 'Cache-Control': 'public, s-maxage=60, stale-while-revalidate=300' },
        status: 200,
      });
    }
  }

  const sourceMode = fallback ? 'fallback_only' : errors.length > 0 ? 'gdelt_partial' : 'gdelt_only';

  const payload = {
    events: allEvents,
    total: allEvents.length,
    timestamp: new Date().toISOString(),
    source: fallback ? 'GDELT 2.0 DOC API + OSIRIS news fallback' : 'GDELT 2.0 DOC API',
    errors,
    partial: errors.length > 0 && allEvents.length > 0,
    fallback,
    source_mode: sourceMode,
    upstream_status: upstreamStatus,
    rate_limit_hits: rateLimitHits,
    timeout_hits: timeoutHits,
    circuit_open_until: circuitOpenUntil > Date.now() ? new Date(circuitOpenUntil).toISOString() : null,
  };
  if (allEvents.length > 0) {
    cache = { ts: Date.now(), payload };
  }

  return NextResponse.json(payload, {
    headers: { 'Cache-Control': errors.length ? 'no-store' : 'public, s-maxage=300, stale-while-revalidate=600' },
    status: 200,
  });
}
