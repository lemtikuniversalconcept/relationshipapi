import { supabaseSelect, supabaseInsert, signStorageUrlIfNeeded } from './consumer';
import { config } from './config';

// Evidence chain-of-custody already tracks who ADDED each item; nothing tracked who
// VIEWED a case or its evidence, which matters just as much for a tool whose whole
// point is being defensible under scrutiny. Fire-and-forget and best-effort: a
// missing/malformed analyst id (e.g. an older dashboard build that hasn't been
// redeployed yet) should never block the analyst from actually seeing the case.
export type ForensicViewAction = 'forensic_case_viewed' | 'forensic_timeline_viewed' | 'forensic_evidence_viewed';

export async function logForensicAccess(params: {
  analystId: string | null | undefined;
  orgId: string;
  incidentId: string;
  action: ForensicViewAction;
}): Promise<void> {
  if (!params.analystId) return;
  try {
    await supabaseInsert('audit_log', {
      actor_id: params.analystId,
      entity: 'incident',
      entity_id: params.incidentId,
      action: params.action,
      details: { via: 'forensic_portal' },
      organisation_id: params.orgId
    });
  } catch (error) {
    console.error('forensic access audit log failed', { action: params.action, incidentId: params.incidentId, error });
  }
}

type IncidentRow = Record<string, unknown> & {
  id: string;
  code: string;
  organisation_id: string;
  occurred_at?: string;
  reported_at: string;
  evidence?: Array<Record<string, unknown>>;
  analysis?: Record<string, unknown> | null;
  dispatch_plan?: Record<string, unknown> | null;
  agent_output?: Record<string, unknown> | null;
  warnings?: string[] | null;
  services?: Record<string, unknown> | null;
};

type ActivityRow = {
  id: string;
  incident_id: string;
  actor_id: string | null;
  actor_name: string | null;
  kind: string;
  message: string | null;
  meta: Record<string, unknown> | null;
  created_at: string;
};

type ConsumerSessionRow = {
  id: string;
  guest_reference: string | null;
  activated_at: string | null;
};

type ReidTelemetryRow = {
  id: number;
  target_id: string;
  camera_id: string;
  zone: string;
  timestamp: string;
  reid_confidence: number | null;
  movement_vector: unknown;
  predicted_destination: unknown;
  event_type: string | null;
  snapshot_ref: string | null;
};

type AutonomousLogRow = {
  action_log_id: string;
  incident_id: string | null;
  device_id: string | null;
  device_name: string | null;
  action_key: string | null;
  execution_result: string | null;
  executed_at: string | null;
  confirmed: boolean | null;
  error: string | null;
};

async function fetchIncident(incidentId: string, orgId: string): Promise<IncidentRow | null> {
  const rows = await supabaseSelect<IncidentRow>('incidents', {
    id: `eq.${incidentId}`,
    organisation_id: `eq.${orgId}`,
    select: '*',
    limit: '1'
  });
  return rows[0] || null;
}

async function fetchActivity(incidentId: string): Promise<ActivityRow[]> {
  return supabaseSelect<ActivityRow>('incident_activity', {
    incident_id: `eq.${incidentId}`,
    select: '*',
    order: 'created_at.asc'
  });
}

// consumer_sessions is the only table the guest-report flow still writes on issue/
// activate — the report itself is folded straight into `incidents` (source, evidence,
// consumer_session_id) since the Aug 2026 migration, so this is the one lookup left
// worth doing per case rather than a join against a table the report flow no longer
// populates.
async function fetchConsumerSession(sessionId: string): Promise<ConsumerSessionRow | null> {
  const rows = await supabaseSelect<ConsumerSessionRow>('consumer_sessions', {
    id: `eq.${sessionId}`,
    select: 'id,guest_reference,activated_at',
    limit: '1'
  });
  return rows[0] || null;
}

async function fetchAutonomousActions(incidentId: string): Promise<AutonomousLogRow[]> {
  return supabaseSelect<AutonomousLogRow>('autonomous_logs', {
    incident_id: `eq.${incidentId}`,
    select: '*',
    order: 'executed_at.asc'
  });
}

// cctv_ai_telemetry has no incident_id column, so a target's presence on this
// incident can only be inferred — same org, within a window around when it was
// reported. That's a real limitation of the current schema, not a shortcut:
// callers should treat this as "what was seen nearby," not a confirmed link.
const REID_CORRELATION_WINDOW_MINUTES = 120;

async function fetchReidTelemetry(orgId: string, aroundIso: string): Promise<ReidTelemetryRow[]> {
  const around = new Date(aroundIso);
  const from = new Date(around.getTime() - REID_CORRELATION_WINDOW_MINUTES * 60_000).toISOString();
  const to = new Date(around.getTime() + REID_CORRELATION_WINDOW_MINUTES * 60_000).toISOString();
  return supabaseSelect<ReidTelemetryRow>('cctv_ai_telemetry', {
    org_id: `eq.${orgId}`,
    timestamp: [`gte.${from}`, `lte.${to}`],
    select: 'id,target_id,camera_id,zone,timestamp,reid_confidence,movement_vector,predicted_destination,event_type,snapshot_ref',
    order: 'timestamp.asc',
    limit: '200'
  });
}

function buildAiAnalyses(incident: IncidentRow, activity: ActivityRow[]): Array<Record<string, unknown>> {
  const fromActivity = activity
    .filter((row) => row.kind === 'ai_recommendation')
    .map((row) => ({
      source: 'incident_activity',
      recorded_at: row.created_at,
      message: row.message,
      ...row.meta
    }));
  const latest =
    incident.analysis || incident.dispatch_plan || incident.agent_output
      ? [
          {
            source: 'incident_current',
            recorded_at: incident.reported_at,
            analysis: incident.analysis || null,
            dispatch_plan: incident.dispatch_plan || null,
            agent_output: incident.agent_output || null,
            warnings: incident.warnings || []
          }
        ]
      : [];
  return [...latest, ...fromActivity];
}

export async function getForensicCase(incidentId: string, orgId: string) {
  const incident = await fetchIncident(incidentId, orgId);
  if (!incident) return null;

  const isConsumerReport = incident.source === 'consumer_pwa' && Boolean(incident.consumer_session_id);
  const [activity, consumerSession, autonomousActions, reidTelemetry] = await Promise.all([
    fetchActivity(incidentId),
    isConsumerReport ? fetchConsumerSession(incident.consumer_session_id as string) : Promise.resolve(null),
    fetchAutonomousActions(incidentId),
    fetchReidTelemetry(orgId, incident.occurred_at || incident.reported_at)
  ]);

  return {
    incident,
    officers_involved: (incident.dispatch_plan as any)?.officers_dispatched || [],
    consumer_report: isConsumerReport
      ? { guest_reference: consumerSession?.guest_reference ?? null, activated_at: consumerSession?.activated_at ?? null }
      : null,
    ai_analyses: buildAiAnalyses(incident, activity),
    reid_telemetry: reidTelemetry,
    autonomous_actions: autonomousActions,
    activity_count: activity.length
  };
}

// Analyst notes go into the same incident_activity table every other timeline event
// already comes from — no new table needed, and it means a note shows up in the
// timeline (getForensicTimeline) for free the moment it's added, in the same place
// an analyst is already looking.
export async function addForensicNote(
  incidentId: string,
  orgId: string,
  params: { analystId: string; analystName: string; note: string }
): Promise<{ id: string; created_at: string } | null> {
  const incident = await fetchIncident(incidentId, orgId);
  if (!incident) return null;
  return supabaseInsert<{ id: string; created_at: string }>('incident_activity', {
    incident_id: incidentId,
    organisation_id: orgId,
    actor_id: params.analystId,
    actor_name: params.analystName,
    kind: 'forensic_note',
    message: params.note,
    meta: {}
  });
}

const TIMELINE_KIND_MAP: Record<string, string> = {
  status_changed: 'status_changed',
  autonomous_action: 'autonomous_action',
  escalation: 'escalation',
  assigned: 'officer_dispatched',
  operator_decision: 'human_approval',
  ai_recommendation: 'ai_recommendation',
  client_note: 'note',
  dispatch_ping: 'officer_dispatched',
  dispatch_route: 'officer_dispatched',
  evidence_added: 'evidence_added',
  evidence_legal_flagged: 'evidence_legal_flagged',
  note: 'note',
  forensic_note: 'forensic_note'
};

export type TimelineEvent = {
  timestamp: string;
  type: string;
  actor: string;
  summary: string;
  detail: Record<string, unknown>;
  media_urls: string[];
};

export async function getForensicTimeline(incidentId: string, orgId: string): Promise<TimelineEvent[] | null> {
  const incident = await fetchIncident(incidentId, orgId);
  if (!incident) return null;

  const activity = await fetchActivity(incidentId);

  const events: TimelineEvent[] = [];

  // Guest-reported incidents have no separate "report" row to surface — the report
  // IS the incident (folded in directly since the Aug 2026 migration) — so the
  // opening timeline entry marks that origin instead of a generic "logged" event.
  // The guest's actual intake conversation still appears below via its own
  // incident_activity rows (kind: 'consumer_intake_turn').
  const isConsumerReport = incident.source === 'consumer_pwa';
  events.push({
    timestamp: incident.reported_at,
    type: isConsumerReport ? 'consumer_report' : 'incident_logged',
    actor: isConsumerReport ? 'guest' : (incident.reported_by as string) || 'system',
    summary: isConsumerReport
      ? `Incident ${incident.code} reported via the guest emergency app: ${(incident.description as string) || incident.type}`
      : `Incident ${incident.code} logged: ${(incident.title as string) || (incident.description as string) || incident.type}`,
    detail: { code: incident.code, type: incident.type, severity: incident.severity },
    media_urls: []
  });

  for (const row of activity) {
    events.push({
      timestamp: row.created_at,
      type: TIMELINE_KIND_MAP[row.kind] || row.kind,
      actor: row.actor_name || row.actor_id || 'system',
      summary: row.message || row.kind,
      detail: row.meta || {},
      media_urls: []
    });
  }

  events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  return events;
}

const INCIDENT_EVIDENCE_BUCKET = 'incident-evidence';

// Named (not Record<string, unknown>) so spreading an item below carries its fields
// into the result type — TS drops all properties of a spread index-signature type.
type EvidenceItem = {
  kind: string;
  name: string;
  path: string;
  size: number;
  legal: boolean;
  added_at: string;
  added_by: string | null;
  added_by_name: string | null;
  chain_of_custody?: unknown;
};

export async function getForensicEvidence(incidentId: string, orgId: string) {
  const incident = await fetchIncident(incidentId, orgId);
  if (!incident) return null;

  const rawEvidence = (incident.evidence as EvidenceItem[]) || [];
  const caseFiles = await Promise.all(
    rawEvidence.map(async (item) => ({
      ...item,
      signed_url: await signStorageUrlIfNeeded(INCIDENT_EVIDENCE_BUCKET, String(item.path || ''), config.consumerMediaSignedUrlExpirySeconds)
    }))
  );

  const reidTelemetry = await fetchReidTelemetry(orgId, incident.occurred_at || incident.reported_at);
  const cctvSnapshots = await Promise.all(
    reidTelemetry
      .filter((row) => row.snapshot_ref)
      .map(async (row) => ({
        camera_id: row.camera_id,
        target_id: row.target_id,
        timestamp: row.timestamp,
        confidence: row.reid_confidence,
        event_type: row.event_type,
        signed_url: await signStorageUrlIfNeeded('cctv-snapshots', row.snapshot_ref as string, config.consumerMediaSignedUrlExpirySeconds)
      }))
  );

  // Guest-submitted photos/audio/video land in this same incident.evidence array as
  // every other case file (see /consumer/report/:report_id/media) — the dedicated
  // "Consumer" tab just filters that array back out by who added it, rather than
  // joining consumer_reports/consumer_report_media, which the report flow stopped
  // writing to once guest reports were folded directly into incidents.
  const consumerMedia = caseFiles
    .filter((item) => item.added_by_name === 'Guest (emergency report)')
    .map((item) => ({
      id: item.path,
      media_type: item.kind === 'image' ? 'photo' : item.kind === 'video' ? 'video_chunk' : 'audio_chunk',
      captured_at: item.added_at,
      signed_url: item.signed_url
    }));

  return {
    case_files: caseFiles,
    cctv_snapshots: cctvSnapshots,
    consumer_media: consumerMedia
  };
}
