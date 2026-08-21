import crypto from 'node:crypto';
import { config, hasExternalBackend } from './config';
import { callService } from './clients';

const TOKEN_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // excludes O/0/I/1 to avoid transcription errors

export function generateConsumerToken(): string {
  let token = config.consumerTokenPrefix;
  for (let i = 0; i < 10; i++) {
    token += TOKEN_CHARS[crypto.randomInt(TOKEN_CHARS.length)];
  }
  return token;
}

function supabaseHeaders(extra?: Record<string, string>): Record<string, string> {
  return {
    apikey: config.supabaseServiceKey || '',
    Authorization: `Bearer ${config.supabaseServiceKey || ''}`,
    'Content-Type': 'application/json',
    ...extra
  };
}

function requireSupabase(): void {
  if (!hasExternalBackend('supabase') || !config.supabaseUrl || !config.supabaseServiceKey) {
    throw new Error('Supabase is not configured');
  }
}

export async function supabaseSelect<T = Record<string, unknown>>(
  table: string,
  query: Record<string, string | string[]>
): Promise<T[]> {
  requireSupabase();
  const url = new URL(`/rest/v1/${table}`, config.supabaseUrl);
  for (const [key, value] of Object.entries(query)) {
    // PostgREST allows repeating a filter column with different operators (e.g. two
    // `timestamp` bounds for a range) — arrays let callers express that instead of
    // the last one silently overwriting the first.
    if (Array.isArray(value)) {
      for (const v of value) url.searchParams.append(key, v);
    } else {
      url.searchParams.set(key, value);
    }
  }
  const response = await fetch(url, { headers: supabaseHeaders() });
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Supabase select failed for ${table}: ${response.status} ${body}`.trim());
  }
  return (await response.json()) as T[];
}

export async function supabaseInsert<T = Record<string, unknown>>(
  table: string,
  record: Record<string, unknown>
): Promise<T> {
  requireSupabase();
  const url = new URL(`/rest/v1/${table}`, config.supabaseUrl);
  const response = await fetch(url, {
    method: 'POST',
    headers: supabaseHeaders({ Prefer: 'return=representation' }),
    body: JSON.stringify(record)
  });
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Supabase insert failed for ${table}: ${response.status} ${body}`.trim());
  }
  const rows = (await response.json()) as T[];
  return rows[0];
}

export async function supabaseUpdate<T = Record<string, unknown>>(
  table: string,
  match: Record<string, string>,
  patch: Record<string, unknown>
): Promise<T[]> {
  requireSupabase();
  const url = new URL(`/rest/v1/${table}`, config.supabaseUrl);
  for (const [key, value] of Object.entries(match)) url.searchParams.set(key, `eq.${value}`);
  const response = await fetch(url, {
    method: 'PATCH',
    headers: supabaseHeaders({ Prefer: 'return=representation' }),
    body: JSON.stringify(patch)
  });
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Supabase update failed for ${table}: ${response.status} ${body}`.trim());
  }
  return (await response.json()) as T[];
}

export async function uploadToStorage(
  bucket: string,
  path: string,
  data: Buffer,
  contentType: string
): Promise<void> {
  requireSupabase();
  const url = new URL(`/storage/v1/object/${bucket}/${path}`, config.supabaseUrl);
  const response = await fetch(url, {
    method: 'POST',
    headers: supabaseHeaders({ 'Content-Type': contentType, 'x-upsert': 'false' }),
    body: new Uint8Array(data)
  });
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Storage upload failed for ${bucket}/${path}: ${response.status} ${body}`.trim());
  }
}

export async function signStorageUrl(bucket: string, path: string, expiresInSeconds: number): Promise<string> {
  requireSupabase();
  const url = new URL(`/storage/v1/object/sign/${bucket}/${path}`, config.supabaseUrl);
  const response = await fetch(url, {
    method: 'POST',
    headers: supabaseHeaders(),
    body: JSON.stringify({ expiresIn: expiresInSeconds })
  });
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Storage sign failed for ${bucket}/${path}: ${response.status} ${body}`.trim());
  }
  const data = (await response.json()) as { signedURL?: string };
  return `${config.supabaseUrl}/storage/v1${data.signedURL || ''}`;
}

// Evidence/media paths in forensic views are frequently missing or point at objects
// that were never actually uploaded (e.g. a stub snapshot_ref) — signing those
// shouldn't take down the whole case view, so this swallows failures into null.
export async function signStorageUrlIfNeeded(
  bucket: string,
  path: string,
  expiresInSeconds: number
): Promise<string | null> {
  if (!bucket || !path) return null;
  try {
    return await signStorageUrl(bucket, path, expiresInSeconds);
  } catch {
    return null;
  }
}

export function haversineDistanceM(lat1: number, lng1: number, lat2: number, lng2: number): number {
  const R = 6371000;
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a =
    Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

export type ConsumerSession = {
  id: string;
  organisation_id: string;
  location_id: string | null;
  token: string;
  guest_reference: string | null;
  premises_lat: number | null;
  premises_lng: number | null;
  premises_radius_m: number | null;
  wifi_ssids: string[] | null;
  activated_at: string | null;
  expires_at: string;
  is_active: boolean;
};

export type SessionValidationReason = 'expired' | 'outside_premises' | 'invalid_token' | 'deactivated';

export function isOnPremises(
  session: ConsumerSession,
  device: { lat?: number; lng?: number; wifiSsid?: string }
): boolean {
  const gpsPass =
    typeof device.lat === 'number' &&
    typeof device.lng === 'number' &&
    typeof session.premises_lat === 'number' &&
    typeof session.premises_lng === 'number' &&
    haversineDistanceM(device.lat, device.lng, session.premises_lat, session.premises_lng) <=
      (session.premises_radius_m || 300);
  const wifiPass = Boolean(device.wifiSsid && session.wifi_ssids?.includes(device.wifiSsid));
  // Neither signal is reliable alone: GPS is unreliable indoors, WiFi is only known if the
  // premises has registered its SSIDs. Either signal passing is enough to call it on-premises.
  return gpsPass || wifiPass;
}

export async function lookupConsumerSession(token: string): Promise<ConsumerSession | null> {
  const rows = await supabaseSelect<ConsumerSession>('consumer_sessions', {
    token: `eq.${token}`,
    select: '*',
    limit: '1'
  });
  return rows[0] || null;
}

export async function validateConsumerSession(
  token: string,
  device: { lat?: number; lng?: number; wifiSsid?: string }
): Promise<{ valid: boolean; reason: SessionValidationReason | null; session: ConsumerSession | null }> {
  if (!token) return { valid: false, reason: 'invalid_token', session: null };
  const session = await lookupConsumerSession(token);
  if (!session) return { valid: false, reason: 'invalid_token', session: null };
  if (!session.is_active) return { valid: false, reason: 'deactivated', session };
  if (new Date(session.expires_at).getTime() < Date.now()) return { valid: false, reason: 'expired', session };
  if (!isOnPremises(session, device)) return { valid: false, reason: 'outside_premises', session };
  return { valid: true, reason: null, session };
}

// Fire-and-forget: the guest's response must never wait on triage. masterai decides
// whether this needs a real dispatch the same way it does for every other incident path.
export function triageConsumerReport(params: {
  reportId: string;
  orgId: string;
  description: string;
  locationText?: string | null;
  lat?: number | null;
  lng?: number | null;
}): void {
  void callService({
    service: 'mainAgent',
    path: '/triage',
    body: {
      request_type: 'agent_triage',
      request_id: `consumer-${params.reportId}`,
      org_id: params.orgId,
      incident_raw: {
        description: params.description || 'Consumer emergency report — no description provided yet.',
        reported_by: 'consumer_pwa',
        location_stated: params.locationText || '',
        lat: params.lat ?? undefined,
        lng: params.lng ?? undefined,
        timestamp: new Date().toISOString(),
        source: 'consumer_report'
      }
    }
  }).catch((error) => {
    console.error('Consumer report triage failed', { reportId: params.reportId, error });
  });
}
