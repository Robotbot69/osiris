import { NextResponse } from 'next/server';

export function middleware() {
  // Hermes sandbox hardening:
  // Upstream middleware sends page views and client IPs to a hard-coded
  // Umami host. We run OSIRIS as a local-only intelligence dashboard, so
  // analytics egress is disabled by default.
  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
}
