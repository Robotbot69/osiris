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
  return (data.news || []).slice(0, maxrecords).map((item: any, idx: number) => {
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
    signal: AbortSignal.timeout(6_000),
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

export async function GET() {
  if (cache && Date.now() - cache.ts < CACHE_TTL_MS) {
    return NextResponse.json(cache.payload, {
      headers: { 'Cache-Control': 'public, s-maxage=300, stale-while-revalidate=600' },
    });
  }

  const allEvents: any[] = [];
  const errors: string[] = [];
  const seen = new Set<string>();

  try {
    const settled = await Promise.allSettled(GDELT_QUERIES.map((query) => fetchDocEvents(query)));
    for (let idx = 0; idx < settled.length; idx += 1) {
      const query = GDELT_QUERIES[idx];
      const result = settled[idx];
      if (result.status === 'rejected') {
        const reason = result.reason;
        errors.push(`${query}: ${reason instanceof Error ? reason.message : String(reason)}`);
        continue;
      }
      for (const event of result.value) {
        const key = event.url || `${event.name}:${event.seendate}`;
        if (seen.has(key)) continue;
        seen.add(key);
        allEvents.push(event);
        if (allEvents.length >= 30) break;
      }
      if (allEvents.length >= 30) break;
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

  if (errors.length > 0 && cache) {
    return NextResponse.json({
      ...cache.payload,
      stale: true,
      timestamp: new Date().toISOString(),
      errors,
    }, {
      headers: { 'Cache-Control': 'public, s-maxage=60, stale-while-revalidate=300' },
      status: 200,
    });
  }

  const payload = {
    events: allEvents,
    total: allEvents.length,
    timestamp: new Date().toISOString(),
    source: fallback ? 'GDELT 2.0 DOC API + OSIRIS news fallback' : 'GDELT 2.0 DOC API',
    errors,
    partial: errors.length > 0 && allEvents.length > 0,
    fallback,
  };
  if (allEvents.length > 0) {
    cache = { ts: Date.now(), payload };
  }

  return NextResponse.json(payload, {
    headers: { 'Cache-Control': errors.length ? 'no-store' : 'public, s-maxage=300, stale-while-revalidate=600' },
    status: 200,
  });
}
