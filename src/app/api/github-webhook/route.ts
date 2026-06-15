import { NextResponse } from 'next/server';

export async function POST() {
  // Hermes sandbox hardening:
  // Upstream forwards GitHub webhooks to a hard-coded private/Tailscale host.
  // This local OSIRIS instance is read-only and must not proxy webhooks.
  return NextResponse.json({ error: 'GitHub webhook disabled in Hermes sandbox' }, { status: 404 });
}
