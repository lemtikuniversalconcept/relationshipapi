import crypto from 'node:crypto';
import { config, hasExternalBackend } from './config';

const NIL_UUID = '00000000-0000-0000-0000-000000000000';
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const TABLE_ALIASES: Record<string, string> = {
  ai_approvals: 'approvals',
  ai_logs: 'audit_log',
  audit_logs: 'audit_log'
};

function canonicalTableName(table: string): string {
  return TABLE_ALIASES[table] || table;
}

function conflictKeyForTable(table: string, record: Record<string, unknown>): string | undefined {
  const canonicalTable = canonicalTableName(table);
  const candidates: Record<string, string[]> = {
    incidents: ['id'],
    approvals: ['request_id'],
    overrides: ['override_id'],
    entities: ['id'],
    relationships: ['id'],
    relationship_events: ['id'],
    devices: ['id'],
    bridges: ['id'],
    infrastructure: ['id'],
    autonomous_logs: ['action_log_id'],
    inventory_alerts: ['alert_id'],
    graph_snapshots: ['route_id'],
    audit_log: ['id']
  };
  for (const key of candidates[canonicalTable] || []) {
    if (typeof record[key] === 'string' && record[key]) return key;
  }
  return undefined;
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_REGEX.test(value);
}

function uuidFromSeed(seed: string): string {
  const hash = crypto.createHash('sha1').update(`lemtik-relationship-api:${seed}`).digest();
  const bytes = Buffer.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32)
  ].join('-');
}

function normalizeUuidLikeValue(value: unknown, seed: string): string {
  if (isUuid(value)) return value;
  if (typeof value === 'string' && value.trim()) {
    return uuidFromSeed(`${seed}:${value.trim()}`);
  }
  return NIL_UUID;
}

function normalizeRecordForSupabase<T extends Record<string, unknown>>(table: string, record: T): T {
  const canonicalTable = canonicalTableName(table);
  const visit = (value: unknown, path: string): unknown => {
    if (Array.isArray(value)) {
      return value.map((item, index) => visit(item, `${path}[${index}]`));
    }
    if (!value || typeof value !== 'object') {
      return value;
    }
    const next: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      if (key === 'org_id' || key === 'organisation_id' || key === 'organization_id') {
        next[key] = normalizeUuidLikeValue(nested, `${canonicalTable}.${path}.${key}`);
        continue;
      }
      next[key] = visit(nested, `${path}.${key}`);
    }
    return next;
  };

  return visit(record, canonicalTable) as T;
}

async function postSupabase<T extends Record<string, unknown>>(table: string, record: T): Promise<void> {
  if (!hasExternalBackend('supabase') || !config.supabaseUrl || !config.supabaseServiceKey) return;
  const canonicalTable = canonicalTableName(table);
  const normalizedRecord = normalizeRecordForSupabase(canonicalTable, record);
  const url = new URL(`/rest/v1/${canonicalTable}`, config.supabaseUrl);
  const key = conflictKeyForTable(canonicalTable, normalizedRecord);
  if (key) url.searchParams.set('on_conflict', key);
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      apikey: config.supabaseServiceKey,
      Authorization: `Bearer ${config.supabaseServiceKey}`,
      'Content-Type': 'application/json',
      Prefer: 'resolution=merge-duplicates,return=representation'
    },
    body: JSON.stringify(normalizedRecord)
  });
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Supabase sync failed for ${canonicalTable}: ${response.status} ${body}`.trim());
  }
}

export function syncSupabaseRecord(table: string, record: Record<string, unknown>): void {
  void postSupabase(table, record).catch((error) => {
    console.error(error);
  });
}
