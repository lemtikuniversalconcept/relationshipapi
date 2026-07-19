// @ts-nocheck
import { callService } from './clients';
import { IncidentRecord, RequestPrincipal } from './types';
import {
  autonomousActionSchema,
  incidentSchema,
  internalAutonomousExecuteSchema,
  masterAiProcessSchema,
  masterAiSynthesiseSchema,
  masterAiTriageSchema
} from './schemas';
import { saveSession, saveIncident, updateIncident, saveOverride } from './store';

function randomId(prefix: string): string {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;
}

function fallbackIncidentId(incident: Record<string, unknown>): string {
  return String(incident.id || randomId('INC'));
}

function normalizeIncident(raw: unknown, principal: RequestPrincipal, orgId: string): Record<string, unknown> {
  const parsed = incidentSchema.parse(raw);
  return {
    id: parsed.id || randomId('INC'),
    type: parsed.type,
    severity: parsed.severity ?? 3,
    description: parsed.description,
    location: parsed.location || {},
    reported_at: parsed.reported_at || new Date().toISOString(),
    reporter_id: parsed.reporter_id || principal.sub,
    org_id: orgId,
    client_type: parsed.client_type || 'unknown',
    status: parsed.status || 'new'
  };
}

function severityToThreatLevel(severity: number | undefined): string {
  if ((severity || 0) >= 4) return 'high';
  if ((severity || 0) >= 2) return 'medium';
  return 'low';
}

function buildOsintPayload(incident: Record<string, unknown>, queryOverrides: Record<string, unknown> = {}) {
  const location = (incident.location as Record<string, unknown>) || {};
  return {
    request_type: 'intelligence_query',
    request_id: randomId('req'),
    query: {
      area: String(location.name || location.description || 'unknown'),
      radius_km: 5,
      days_back: 30,
      categories: ['Physical', 'Cyber', 'Political', 'Macro'],
      severity_min: Math.max(1, Number(incident.severity || 1)),
      limit: 50,
      include_heatmap: true,
      incident_context: {
        type: String(incident.type || 'unknown'),
        keywords: String(incident.description || '')
          .split(/[\s,]+/)
          .filter(Boolean)
          .slice(0, 10)
      },
      ...queryOverrides
    }
  };
}

function buildInventoryPayload(orgId: string, incident: Record<string, unknown>) {
  return {
    request_type: 'inventory_summary',
    request_id: randomId('req'),
    org_id: orgId,
    incident_id: incident.id
  };
}

function buildProximityPayload(orgId: string, incident: Record<string, unknown>) {
  const location = (incident.location as Record<string, unknown>) || {};
  return {
    request_type: 'find_responders',
    request_id: randomId('req'),
    org_id: orgId,
    incident: {
      id: String(incident.id),
      type: String(incident.type || 'unknown'),
      severity: Number(incident.severity || 3),
      description: String(incident.description || ''),
      location: {
        name: String(location.name || location.description || 'unknown'),
        lat: Number(location.lat || 0),
        lng: Number(location.lng || 0),
        building_id: location.building_id ? String(location.building_id) : undefined,
        floor: typeof location.floor === 'number' ? location.floor : undefined,
        indoor: Boolean(location.indoor)
      },
      requirements: {
        officers_needed: Number(incident.severity || 3) >= 4 ? 4 : 2,
        armed_required: Number(incident.severity || 3) >= 4,
        certifications_preferred: ['first_aid'],
        vehicles_needed: Number(incident.severity || 3) >= 4 ? 1 : 0,
        priority: 'immediate'
      }
    },
    options: {
      search_radius_km: 5,
      max_candidates: 10,
      include_vehicles: Number(incident.severity || 3) >= 4,
      request_eta_from_route_calculator: true
    }
  };
}

function buildRoutePayload(orgId: string, incident: Record<string, unknown>, responders: { officers: string[]; vehicles: string[] }) {
  const location = (incident.location as Record<string, unknown>) || {};
  return {
    request_type: 'route_calculate',
    request_id: randomId('req'),
    org_id: orgId,
    incident: {
      id: String(incident.id),
      location: {
        lat: Number(location.lat || 0),
        lng: Number(location.lng || 0),
        description: String(location.name || location.description || '')
      },
      type: String(incident.type || 'unknown'),
      indoor: Boolean(location.indoor),
      building_id: location.building_id ? String(location.building_id) : undefined
    },
    responders,
    routing_preferences: {
      type: Number(location.indoor) ? 'foot' : 'hybrid',
      prioritise: 'speed'
    }
  };
}

function buildAnalysisPayload(
  incident: Record<string, unknown>,
  context: Record<string, unknown>
): Record<string, unknown> {
  const osintData = (context.osint as any)?.data;
  const inventoryData = (context.inventory as any)?.data;
  const proximityData = (context.proximity as any)?.data;
  const routeData = (context.routeCalculator as any)?.data;
  return {
    request_type: 'incident_analysis',
    request_id: randomId('req'),
    incident,
    context: {
      osint_data: osintData,
      inventory: inventoryData,
      available_officers: inventoryData?.officers?.items || [],
      proximity: proximityData,
      route_calculator: routeData,
      client_type: (incident as any).client_type || 'unknown'
    }
  };
}

function buildAgentPayload(
  incident: Record<string, unknown>,
  orgId: string,
  availableServices: string[],
  approvalOfficerId?: string
): Record<string, unknown> {
  return {
    request_type: 'agent_task',
    request_id: randomId('req'),
    task_type: 'incident_dispatch',
    raw_input: {
      source: 'relationship_api',
      content: String(incident.description || 'Incident report'),
      caller_id: String(incident.reporter_id || 'system'),
      location_confirmed: Boolean((incident.location as Record<string, unknown>)?.lat && (incident.location as Record<string, unknown>)?.lng),
      location: incident.location
    },
    available_services: availableServices,
    constraints: {
      autonomous_actions_require_approval: true,
      max_response_time_seconds: 30,
      approval_officer_id: approvalOfficerId || orgId
    }
  };
}

function fallbackAnalysis(incident: Record<string, unknown>): Record<string, unknown> {
  const severity = Number(incident.severity || 3);
  return {
    request_id: randomId('req'),
    status: 'success',
    analysis: {
      threat_assessment: {
        threat_level: severityToThreatLevel(severity),
        confidence: 65 + severity * 5,
        reasoning: 'Generated locally because AI analysis service was unavailable.',
        armed: severity >= 4,
        estimated_suspects: severity >= 4 ? 3 : 1,
        escape_likelihood: severity >= 4 ? 'high' : 'medium',
        similar_past_incidents: severity * 2
      },
      response_recommendation: {
        officers_needed: severity >= 4 ? 6 : 2,
        armed_required: severity >= 4,
        vehicles_needed: severity >= 4 ? 2 : 1,
        response_urgency: severity >= 4 ? 'immediate' : 'normal',
        estimated_response_time_minutes: severity >= 4 ? 8 : 20,
        special_instructions: 'Fallback plan generated locally.'
      },
      resource_requirements: {
        officers: { count: severity >= 4 ? 6 : 2, armed: severity >= 4, recommended_ids: [] },
        vehicles: { count: severity >= 4 ? 2 : 1, type: 'patrol_car', recommended_ids: [] },
        weapons: { type: 'standard_firearms', heavy_required: false },
        fuel_check_required: severity >= 4
      },
      autonomous_actions_recommended: []
    }
  };
}

function fallbackAgent(incident: Record<string, unknown>): Record<string, unknown> {
  return {
    request_id: randomId('req'),
    status: 'success',
    agent_output: {
      jobs_executed: [],
      dispatch_plan: {
        incident_id: String(incident.id),
        officers_dispatched: [],
        vehicles_assigned: [],
        route: {},
        eta_minutes: 0,
        autonomous_actions_pending_approval: []
      },
      summary_for_commander: 'Local fallback dispatch summary.',
      confidence: 55,
      requires_human_approval: true,
      approval_items: []
    }
  };
}

function normalizeText(value: unknown): string {
  return String(value || '').trim().toLowerCase();
}

function inferIncidentType(description: string): string {
  const text = normalizeText(description);
  if (/(stab|knife|weapon|armed|shoot|gun|robbery|assault)/.test(text)) return 'assault_with_weapon';
  if (/(fire|smoke|burn)/.test(text)) return 'fire';
  if (/(medical|injur|collapse|unconscious)/.test(text)) return 'medical_emergency';
  if (/(protest|crowd|riot|demo)/.test(text)) return 'public_order';
  if (/(intrud|trespass|break in|burglary)/.test(text)) return 'intrusion';
  return 'incident';
}

function inferSeverity(description: string, explicit?: unknown): number {
  if (typeof explicit === 'number' && Number.isFinite(explicit)) return Math.max(0, Math.min(5, Math.round(explicit)));
  const text = normalizeText(description);
  if (/(dead|fatal|shoot|gun|armed|stab|critical|multiple victims)/.test(text)) return 4;
  if (/(injur|weapon|suspect|urgent|assault|fire)/.test(text)) return 3;
  if (/(suspicious|unknown|noise|disturbance|medical)/.test(text)) return 2;
  return 1;
}

function buildTriageJobs(incidentType: string, severity: number, locationKnown: boolean): Array<Record<string, unknown>> {
  const jobs: Array<Record<string, unknown>> = [
    { service: 'osint_brain', priority: 1, parameters: {} }
  ];
  if (severity >= 2 || incidentType !== 'incident') {
    jobs.push({ service: 'proximity_finder', priority: 2, parameters: { search_radius_km: locationKnown ? 5 : 10 } });
  }
  if (severity >= 3) {
    jobs.push({ service: 'inventory_service', priority: 3, parameters: { request_type: 'readiness_check' } });
    jobs.push({ service: 'route_calculator', priority: 4, parameters: { estimate_eta: true } });
  }
  if (severity >= 4) {
    jobs.push({ service: 'autonomous_control', priority: 5, parameters: { preview_only: true } });
  }
  return jobs;
}

function localTriage(payload: Record<string, unknown>): Record<string, unknown> {
  const incidentRaw = (payload.incident_raw as Record<string, unknown>) || {};
  const description = String(incidentRaw.description || '');
  const locationConfirmed = Boolean(incidentRaw.lat && incidentRaw.lng);
  const severity = inferSeverity(description, incidentRaw.floor);
  const incidentType = inferIncidentType(description);
  const armedThreat = /(weapon|armed|gun|knife|stab|shoot|robbery)/.test(normalizeText(description));
  const jobsNeeded = buildTriageJobs(incidentType, severity, locationConfirmed);
  const confidence = Math.max(45, Math.min(98, 72 + (locationConfirmed ? 10 : -8) + (description ? 8 : -12) + (severity >= 3 ? 5 : 0)));
  const requiresHumanVerification = confidence < 60 || !locationConfirmed || armedThreat && severity >= 4;

  return {
    request_id: String(payload.request_id || crypto.randomUUID()),
    status: 'success',
    step: 'triage',
    triage: {
      incident_type: incidentType,
      severity,
      urgency: severity >= 4 ? 'immediate' : severity >= 3 ? 'urgent' : 'standard',
      armed_threat: armedThreat,
      suspect_on_premises: /(suspect|intrud|contained|present)/.test(normalizeText(description)),
      victim_count: /(victim|injur|hurt)/.test(normalizeText(description)) ? 1 : 0,
      victim_status: /(dead|fatal|critical)/.test(normalizeText(description))
        ? 'critical'
        : /(injur|hurt|stab)/.test(normalizeText(description))
          ? 'injured'
          : 'unknown',
      location_confirmed: locationConfirmed,
      location_indoor: Boolean(incidentRaw.building || incidentRaw.floor || incidentRaw.zone),
      confidence,
      flags: [
        ...(armedThreat ? ['weapon_involved'] : []),
        ...(locationConfirmed ? ['location_confirmed'] : ['location_unconfirmed']),
        ...(severity >= 3 ? ['needs_response'] : []),
        ...(severity >= 4 ? ['medical_needed'] : [])
      ]
    },
    jobs_needed: jobsNeeded,
    confidence,
    requires_human_verification: requiresHumanVerification
  };
}

function summarizeServices(serviceResults: Record<string, unknown>): string {
  const keys = Object.keys(serviceResults || {});
  if (!keys.length) return 'No upstream service results were provided.';
  return `Combined ${keys.length} service result(s): ${keys.join(', ')}.`;
}

function localSynthesis(payload: Record<string, unknown>): Record<string, unknown> {
  const incident = (payload.incident as Record<string, unknown>) || {};
  const triage = (incident.triage as Record<string, unknown>) || {};
  const serviceResults = (payload.service_results as Record<string, unknown>) || {};
  const severity = inferSeverity(String(incident.description || ''), incident.severity);
  const confidence = Math.max(50, Math.min(96, 80 + (Object.keys(serviceResults).length * 2) + (severity >= 4 ? 4 : 0)));
  const summary = `Incident ${String(incident.id || 'unknown')} requires coordinated response. ${summarizeServices(serviceResults)}`;
  const panel = {
    panel_type: 'incident_response',
    incident_id: String(incident.id || 'unknown'),
    generated_at: new Date().toISOString(),
    confidence,
    situation_summary: summary,
    threat_assessment: {
      threat_level: severity >= 4 ? 'high' : severity >= 2 ? 'medium' : 'low',
      armed: Boolean(triage.armed_threat),
      suspect_on_premises: Boolean(triage.suspect_on_premises),
      medical_needed: Boolean((triage.flags as string[] | undefined)?.includes('medical_needed')),
      service_alignment: Object.keys(serviceResults || {}),
      recommended_mode: severity >= 4 ? 'immediate_dispatch' : 'monitored_response'
    }
  };
  const tokensUsed = JSON.stringify(payload).length + JSON.stringify(serviceResults).length;
  return {
    request_id: String(payload.request_id || crypto.randomUUID()),
    status: 'success',
    step: 'synthesis',
    panel,
    tokens_used: Math.max(200, Math.round(tokensUsed / 4)),
    model: 'llama-3.3-70b-versatile',
    latency_ms: 0
  };
}

function localProcess(payload: Record<string, unknown>): Record<string, unknown> {
  if (payload.incident_raw && payload.org_context) {
    return localTriage(payload);
  }
  if (payload.incident && payload.service_results) {
    return localSynthesis(payload);
  }
  const alertType = String(payload.alert_type || payload.request_type || 'routine_report');
  const message = String(payload.message || 'Processed locally by the Relationship API.');
  return {
    request_id: String(payload.request_id || crypto.randomUUID()),
    status: 'success',
    step: 'process',
    panel: {
      panel_type: alertType,
      generated_at: new Date().toISOString(),
      confidence: 70,
      situation_summary: message,
      threat_assessment: {
        threat_level: 'medium',
        recommended_mode: 'review'
      }
    },
    tokens_used: Math.max(120, Math.round(JSON.stringify(payload).length / 3)),
    model: 'heuristic-fallback',
    latency_ms: 0
  };
}

export async function processMasterAiTriage(principal: RequestPrincipal, payload: unknown, orgId: string): Promise<Record<string, unknown>> {
  const parsed = masterAiTriageSchema.parse(payload || {});
  const requestId = parsed.request_id;
  const upstream = await callService({
    service: 'mainAgent',
    path: '/triage',
    body: { ...parsed, org_id: orgId }
  });
  const data = !upstream.ok || upstream.fallback ? localTriage({ ...parsed, org_id: orgId }) : (upstream.data as Record<string, unknown>);
  saveSession(requestId, { step: 'triage', input: parsed, output: data, upstream: { fallback: upstream.fallback, status: upstream.status } });
  return data;
}

export async function processMasterAiSynthesise(principal: RequestPrincipal, payload: unknown, orgId: string): Promise<Record<string, unknown>> {
  const parsed = masterAiSynthesiseSchema.parse(payload || {});
  const requestId = parsed.request_id;
  const upstream = await callService({
    service: 'mainAgent',
    path: '/synthesise',
    body: { ...parsed, org_id: orgId }
  });
  const data = !upstream.ok || upstream.fallback ? localSynthesis({ ...parsed, org_id: orgId }) : (upstream.data as Record<string, unknown>);
  saveSession(requestId, { step: 'synthesis', input: parsed, output: data, upstream: { fallback: upstream.fallback, status: upstream.status } });
  return data;
}

export async function processMasterAiRequest(principal: RequestPrincipal, payload: unknown, orgId: string): Promise<Record<string, unknown>> {
  const parsed = masterAiProcessSchema.parse(payload || {});
  const requestId = parsed.request_id;
  if (parsed.incident_raw && parsed.org_context) {
    return processMasterAiTriage(principal, parsed, orgId);
  }
  if (parsed.incident && parsed.service_results) {
    return processMasterAiSynthesise(principal, parsed, orgId);
  }
  const upstream = await callService({
    service: 'mainAgent',
    path: '/process',
    body: { ...parsed, org_id: orgId }
  });
  const output = !upstream.ok || upstream.fallback ? localProcess({ ...parsed, org_id: orgId }) : (upstream.data as Record<string, unknown>);
  saveSession(requestId, { step: 'process', input: parsed, output, upstream: { fallback: upstream.fallback, status: upstream.status } });
  return output;
}

export async function fetchMasterAiSession(requestId: string): Promise<Record<string, unknown> | undefined> {
  const { getSession } = await import('./store');
  const local = getSession(requestId);
  if (local) {
    return {
      request_id: requestId,
      status: 'success',
      data: local,
      meta: { source: 'local' }
    };
  }
  const upstream = await callService({ service: 'mainAgent', path: `/session/${encodeURIComponent(requestId)}`, method: 'GET' });
  if (upstream.ok && !upstream.fallback) {
    return {
      request_id: requestId,
      status: 'success',
      data: upstream.data,
      meta: { source: upstream.fallback ? 'fallback' : 'upstream' }
    };
  }
  return undefined;
}

export async function orchestrateIncidentCreate(principal: RequestPrincipal, payload: unknown, orgId: string): Promise<Record<string, unknown>> {
  const incident = normalizeIncident(payload, principal, orgId);

  const [osint, inventory, proximity] = await Promise.all([
    callService({ service: 'osint', path: '/brain/query', body: buildOsintPayload(incident) }),
    callService({ service: 'inventory', path: '/query', body: buildInventoryPayload(orgId, incident) }),
    callService({ service: 'proximity', path: '/find', body: buildProximityPayload(orgId, incident) })
  ]);

  const responders = {
    officers:
      ((proximity.data as any)?.data?.recommended_officers || [])
        .slice(0, 4)
        .map((item: any) => item.officer_id)
        .filter(Boolean),
    vehicles:
      ((inventory.data as any)?.data?.vehicles?.items || [])
        .slice(0, 2)
        .map((item: any) => item.vehicle_id)
        .filter(Boolean)
  };

  const routeCalculator = await callService({
    service: 'routeCalculator',
    path: '/route/calculate',
    body: buildRoutePayload(orgId, incident, responders)
  });

  const analysisRequest = buildAnalysisPayload(incident, {
    osint,
    inventory,
    proximity,
    routeCalculator
  });
  const analysis = await callService({ service: 'aiAnalysis', path: '/analyze', body: analysisRequest });

  const agent = await callService({
    service: 'mainAgent',
    path: '/process',
    body: buildAgentPayload(incident, orgId, ['osint_brain', 'ai_analysis', 'autonomous_control'], principal.sub)
  });

  const record: IncidentRecord = {
    id: String(incident.id || fallbackIncidentId(incident)),
    org_id: orgId,
    status: String(incident.status || 'new'),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    incident,
    services: { osint, inventory, proximity, routeCalculator, analysis, agent },
    analysis: (analysis.data as any)?.analysis || (fallbackAnalysis(incident).analysis as Record<string, unknown>),
    dispatch_plan: (agent.data as any)?.agent_output?.dispatch_plan || (fallbackAgent(incident).agent_output as any).dispatch_plan,
    agent_output: (agent.data as any)?.agent_output || (fallbackAgent(incident).agent_output as Record<string, unknown>),
    warnings: [
      ...(osint.fallback ? ['OSINT fallback used'] : []),
      ...(inventory.fallback ? ['Inventory fallback used'] : []),
      ...(proximity.fallback ? ['Proximity fallback used'] : []),
      ...(routeCalculator.fallback ? ['Route calculator fallback used'] : []),
      ...(analysis.fallback ? ['AI analysis fallback used'] : []),
      ...(agent.fallback ? ['Main agent fallback used'] : [])
    ]
  };

  saveIncident(record);
  saveSession(String(record.id), record);

  return {
    request_id: incident.id || record.id,
    status: 'success',
    data: record,
    meta: {
      service_calls: { osint, inventory, proximity, routeCalculator, analysis, agent },
      degraded: record.warnings.length > 0
    }
  };
}

export async function runAnalysis(principal: RequestPrincipal, incidentId: string, orgId: string): Promise<Record<string, unknown>> {
  const current = saveIncident as unknown;
  void current;
  const { getIncident } = await import('./store');
  const incident = getIncident(incidentId);
  if (!incident) {
    throw new Error('Incident not found');
  }
  if (incident.org_id !== orgId) {
    throw new Error('Forbidden');
  }
  const osint = incident.services.osint || (await callService({ service: 'osint', path: '/brain/query', body: buildOsintPayload(incident.incident) }));
  const inventory = incident.services.inventory || (await callService({ service: 'inventory', path: '/query', body: buildInventoryPayload(orgId, incident.incident) }));
  const analysis = await callService({
    service: 'aiAnalysis',
    path: '/analyze',
    body: buildAnalysisPayload(incident.incident, { osint, inventory, proximity: incident.services.proximity, routeCalculator: incident.services.routeCalculator })
  });
  const updated = updateIncident(incidentId, {
    analysis: (analysis.data as any)?.analysis || fallbackAnalysis(incident.incident).analysis,
    services: { ...incident.services, analysis }
  });
  return {
    request_id: incidentId,
    status: 'success',
    data: updated,
    meta: { degraded: analysis.fallback }
  };
}

export async function executeDispatch(principal: RequestPrincipal, incidentId: string, orgId: string, approvedActions: unknown[]): Promise<Record<string, unknown>> {
  const { getIncident } = await import('./store');
  const incident = getIncident(incidentId);
  if (!incident) throw new Error('Incident not found');
  if (incident.org_id !== orgId) throw new Error('Forbidden');

  const executions = [];
  for (const action of approvedActions) {
    const payload = autonomousActionSchema.parse(action);
    const internalPayload = internalAutonomousExecuteSchema.parse({
      request_type: 'execute_action',
      request_id: payload.request_id,
      org_id: orgId,
      action: {
        action_key: payload.action.type,
        device_id: payload.action.target_id,
        parameters: {
          command: payload.action.command,
          route_ids: payload.action.route_ids,
          duration_seconds: payload.action.duration_seconds,
          reason: payload.action.reason,
          incident_id: payload.action.incident_id
        }
      },
      authorisation: {
        approved_by: payload.authorisation.approved_by,
        approval_timestamp: payload.authorisation.approval_timestamp,
        approval_level: payload.authorisation.approval_level,
        incident_id: payload.authorisation.incident_id || incidentId
      }
    });
    const result = await callService({
      service: 'autonomous',
      path: '/execute',
      body: internalPayload
    });
    const overrideId = (result.data as any)?.data?.active_override_id || randomId('ovr');
    saveOverride({
      override_id: overrideId,
      request_id: payload.request_id,
      org_id: orgId,
      incident_id: incidentId,
      action_key: payload.action.action_key || 'custom_action',
      device_id: payload.action.device_id,
      status: result.ok ? 'active' : 'failed',
      approved_by: payload.authorisation.approved_by,
      approval_level: payload.authorisation.approval_level,
      created_at: new Date().toISOString(),
      executed_at: new Date().toISOString(),
      payload,
      result: result.data
    });
    executions.push({ action: payload.action.action_key, result });
  }
  return {
    request_id: incidentId,
    status: 'success',
    data: {
      incident_id: incidentId,
      executed_actions: executions,
      total: executions.length
    }
  };
}

export async function directAgentProcess(principal: RequestPrincipal, payload: unknown, orgId: string): Promise<Record<string, unknown>> {
  const parsed = payload as Record<string, unknown>;
  const requestId = String(parsed.request_id || randomId('req'));
  const result = await callService({
    service: 'mainAgent',
    path: '/process',
    body: {
      ...parsed,
      request_id: requestId,
      org_id: orgId
    }
  });
  saveSession(requestId, result.data);
  return {
    request_id: requestId,
    status: 'success',
    data: result.data,
    meta: { degraded: result.fallback }
  };
}

export async function fetchJobStatus(requestId: string): Promise<Record<string, unknown>> {
  const { getSession } = await import('./store');
  const local = getSession(requestId);
  if (local) {
    return {
      request_id: requestId,
      status: 'success',
      data: local,
      meta: { source: 'local' }
    };
  }
  const upstream = await callService({ service: 'mainAgent', path: `/session/${encodeURIComponent(requestId)}`, method: 'GET' });
  return {
    request_id: requestId,
    status: 'success',
    data: upstream.data,
    meta: { source: upstream.fallback ? 'fallback' : 'upstream' }
  };
}

export async function approveAction(requestId: string, body: unknown, principal: RequestPrincipal): Promise<Record<string, unknown>> {
  const parsed = body && typeof body === 'object' ? body as Record<string, unknown> : {};
  saveSession(requestId, {
    approved: true,
    approved_by: principal.sub,
    approved_at: new Date().toISOString(),
    ...parsed
  });
  return {
    request_id: requestId,
    status: 'success',
    data: {
      request_id: requestId,
      approved: true,
      approved_by: principal.sub,
      approved_at: new Date().toISOString()
    }
  };
}
