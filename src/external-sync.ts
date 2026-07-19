import { config, hasExternalBackend } from './config';

function conflictKeyForTable(table: string, record: Record<string, unknown>): string | undefined {
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
    graph_snapshots: ['route_id']
  };
  for (const key of candidates[table] || []) {
    if (typeof record[key] === 'string' && record[key]) return key;
  }
  return undefined;
}

async function postSupabase<T extends Record<string, unknown>>(table: string, record: T): Promise<void> {
  if (!hasExternalBackend('supabase') || !config.supabaseUrl || !config.supabaseServiceKey) return;
  const url = new URL(`/rest/v1/${table}`, config.supabaseUrl);
  const key = conflictKeyForTable(table, record);
  if (key) url.searchParams.set('on_conflict', key);
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      apikey: config.supabaseServiceKey,
      Authorization: `Bearer ${config.supabaseServiceKey}`,
      'Content-Type': 'application/json',
      Prefer: 'resolution=merge-duplicates,return=representation'
    },
    body: JSON.stringify(record)
  });
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Supabase sync failed for ${table}: ${response.status} ${body}`.trim());
  }
}

export function syncSupabaseRecord(table: string, record: Record<string, unknown>): void {
  void postSupabase(table, record).catch((error) => {
    console.error(error);
  });
}
