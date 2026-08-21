import { supabaseSelect, signStorageUrlIfNeeded } from './consumer';
import { config } from './config';

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

type ConsumerReportRow = {
  id: string;
  incident_id: string | null;
  report_type: string;
  description: string | null;
  location_text: string | null;
  status: string;
  ai_transcription: string | null;
  ai_language: string | null;
  created_at: string;
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

async function fetchConsumerReports(incidentId: string): Promise<ConsumerReportRow[]> {
  return supabaseSelect<ConsumerReportRow>('consumer_reports', {
    incident_id: `eq.${incidentId}`,
    select: 'id,incident_id,report_type,description,location_text,status,ai_transcription,ai_language,created_at',
    order: 'created_at.asc'
  });
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

  const [activity, consumerReports, autonomousActions, reidTelemetry] = await Promise.all([
    fetchActivity(incidentId),
    fetchConsumerReports(incidentId),
    fetchAutonomousActions(incidentId),
    fetchReidTelemetry(orgId, incident.occurred_at || incident.reported_at)
  ]);

  return {
    incident,
    officers_involved: (incident.dispatch_plan as any)?.officers_dispatched || [],
    consumer_reports: consumerReports,
    ai_analyses: buildAiAnalyses(incident, activity),
    reid_telemetry: reidTelemetry,
    autonomous_actions: autonomousActions,
    activity_count: activity.length
  };
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
  note: 'note'
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

  const [activity, consumerReports] = await Promise.all([fetchActivity(incidentId), fetchConsumerReports(incidentId)]);

  const events: TimelineEvent[] = [];

  events.push({
    timestamp: incident.reported_at,
    type: 'incident_logged',
    actor: (incident.reported_by as string) || 'system',
    summary: `Incident ${incident.code} logged: ${(incident.title as string) || (incident.description as string) || incident.type}`,
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

  for (const report of consumerReports) {
    events.push({
      timestamp: report.created_at,
      type: 'consumer_report',
      actor: 'guest',
      summary: report.ai_transcription || report.description || `${report.report_type} report received`,
      detail: { status: report.status, location_text: report.location_text, language: report.ai_language },
      media_urls: []
    });
  }

  events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  return events;
}

const INCIDENT_EVIDENCE_BUCKET = 'incident-evidence';

export async function getForensicEvidence(incidentId: string, orgId: string) {
  const incident = await fetchIncident(incidentId, orgId);
  if (!incident) return null;

  const rawEvidence = (incident.evidence as Array<Record<string, unknown>>) || [];
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

  const consumerReports = await fetchConsumerReports(incidentId);
  let consumerMedia: Array<Record<string, unknown>> = [];
  if (consumerReports.length > 0) {
    const media = await supabaseSelect<{
      id: string;
      report_id: string;
      media_type: string;
      storage_path: string;
      chunk_index: number | null;
      captured_at: string;
    }>('consumer_report_media', {
      report_id: `in.(${consumerReports.map((r) => r.id).join(',')})`,
      select: '*',
      order: 'captured_at.asc'
    });
    consumerMedia = await Promise.all(
      media.map(async (item) => {
        const [bucket, ...rest] = item.storage_path.split('/');
        return {
          ...item,
          signed_url: await signStorageUrlIfNeeded(bucket, rest.join('/'), config.consumerMediaSignedUrlExpirySeconds)
        };
      })
    );
  }

  return {
    case_files: caseFiles,
    cctv_snapshots: cctvSnapshots,
    consumer_media: consumerMedia
  };
}
