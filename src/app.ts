// @ts-nocheck
import fastify from 'fastify';
import cors from '@fastify/cors';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import { config, hasExternalBackend, isAdminRole, isElevatedRole, normalizeRole } from './config';
import {
  agentTaskSchema,
  approvalSchema,
  autonomousActionSchema,
  osintAlertDispatchSchema,
  osintBriefSchema,
  osintBrainQuerySchema,
  osintCollectSchema,
  entitySchema,
  graphQuerySchema,
  incidentSchema,
  intelligenceQuerySchema,
  inventoryQuerySchema,
  inventoryAlertSchema,
  internalAutonomousExecuteSchema,
  relationshipSchema,
  queryParamsListSchema,
  routeCalculateSchema,
  osintPacketSchema,
  osintTaskResolveSchema,
  proximityRequestSchema,
  routePushSchema,
  routeUpdateSchema,
  infrastructureRegisterSchema,
  infrastructureQuerySchema,
  osintTaskSchema,
  qwenAnalyzeIncidentSchema,
  qwenAnalyzeImageSchema,
  qwenApprovalSchema,
  qwenProcessRadioSchema,
  qwenRecommendResponseSchema,
  cctvCameraRegisterSchema,
  cctvStreamStartSchema,
  cctvStreamStopSchema,
  cctvReidAnalyzeSchema,
  cctvTargetPredictSchema,
  cctvTelemetryIngestSchema,
  cctvFramesIngestSchema,
  cctvVisionVerifySchema,
  cctvJudgementAnalyzeSchema,
  cctvReidCorrelateSchema,
  aiGenerateSummarySchema,
  toBool,
  toNumber
} from './schemas';
import {
  findRelationshipsByEntity,
  getAiOperation,
  getAiApproval,
  findAutonomousLog,
  getApproval,
  getBridge,
  getEntity,
  getDevice,
  getIncident,
  getIdempotentResponse,
  getIdempotentRecord,
  getRelationship,
  listEntities,
  listGraphEvents,
  listAutonomousLogs,
  listAiOperations,
  listAiApprovals,
  listAiLogs,
  getAiLog,
  saveAiLog,
  listIncidents,
  listBridges,
  getInventoryAlert,
  listInventoryAlerts,
  listOverrides,
  listDevices,
  listRelationships,
  pushAudit,
  queryAudit,
  saveApproval,
  saveAutonomousLog,
  saveBridge,
  saveDevice,
  saveEntity,
  saveGraphEvent,
  saveOverride,
  saveInventoryAlert,
  saveRelationship,
  setIdempotentResponse,
  updateIncident,
  saveInfrastructure,
  getInfrastructure,
  listInfrastructure,
  saveRoutePlan,
  getRoutePlan,
  listRoutePlans
} from './store';
import { getServiceHealth, callService } from './clients';
import {
  approveAction,
  directAgentProcess,
  executeDispatch,
  fetchJobStatus,
  fetchMasterAiSession,
  processMasterAiRequest,
  processMasterAiSynthesise,
  processMasterAiTriage,
  processQwenAnalyzeIncident,
  processQwenAnalyzeImage,
  processQwenApproval,
  processQwenRadio,
  processQwenRecommendResponse,
  orchestrateIncidentCreate,
  runAnalysis
} from './orchestrator';
import { RequestPrincipal, ServiceName } from './types';

export const app = fastify({ logger: true, bodyLimit: 2 * 1024 * 1024 });

void app.register(cors, {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (!config.corsAllowedOrigins.length && config.env !== 'production') {
      return cb(null, true);
    }
    if (config.corsAllowedOrigins.includes(origin)) {
      return cb(null, true);
    }
    return cb(new Error('CORS origin not allowed'), false);
  },
  credentials: true
});

function enableRouteAliasArrays(instance: typeof app): void {
  const registered = new Set<string>();
  const methods = ['get', 'post', 'patch', 'put', 'delete', 'head', 'options'] as const;
  for (const method of methods) {
    const original = (instance as any)[method].bind(instance);
    (instance as any)[method] = (pathOrPaths: string | string[], ...rest: any[]) => {
      if (Array.isArray(pathOrPaths)) {
        let lastResult;
        for (const path of pathOrPaths) {
          const key = `${method.toUpperCase()}:${path}`;
          if (registered.has(key)) {
            continue;
          }
          registered.add(key);
          lastResult = original(path, ...rest);
        }
        return lastResult;
      }
      const key = `${method.toUpperCase()}:${pathOrPaths}`;
      if (registered.has(key)) {
        return instance;
      }
      registered.add(key);
      return original(pathOrPaths, ...rest);
    };
  }
}

enableRouteAliasArrays(app);

app.addHook('onRequest', async (request, reply) => {
  const path = request.raw.url || request.url || '';
  const isHealth =
    path.startsWith('/health') ||
    path.startsWith('/v1/health') ||
    path.startsWith('/api/v1/health') ||
    path.startsWith('/ready') ||
    path.startsWith('/v1/ready') ||
    path.startsWith('/api/v1/ready');
  const started = Date.now();
  (request as any).startedAt = started;
  if (isHealth) return;

  const ip = request.ip || 'unknown';
  const bucket = ((globalThis as any).__relationshipRateLimit ||= new Map<string, { count: number; resetAt: number }>());
  const now = Date.now();
  const state = bucket.get(ip) || { count: 0, resetAt: now + 60_000 };
  if (now > state.resetAt) {
    state.count = 0;
    state.resetAt = now + 60_000;
  }
  state.count += 1;
  bucket.set(ip, state);
  if (state.count > 120) {
    return reply.code(429).send({ status: 'error', error: 'Rate limit exceeded' });
  }
});

app.addHook('preValidation', async (request) => {
  const path = request.raw.url || request.url || '';
  if (!path.startsWith('/ai/') || request.method !== 'POST') return;
  try {
    (request as any).aiInboundPayload = JSON.parse(JSON.stringify(request.body || {}));
  } catch {
    (request as any).aiInboundPayload = request.body || {};
  }
});

async function parsePrincipal(request: any): Promise<RequestPrincipal> {
  const auth = String(request.headers.authorization || '');
  const apiKey = String(request.headers['x-api-key'] || request.headers['x-internal-key'] || '');
  const webhookSignature = String(request.headers['x-webhook-signature'] || '');
  const headerOrg = String(request.headers['x-org-id'] || request.headers['x-organisation-id'] || '');
  const actorId = String(request.headers['x-actor-id'] || '');
  const actorRole = String(request.headers['x-actor-role'] || '');
  const clientName = String(request.headers['x-client-name'] || '');

  if (auth.startsWith('Bearer ')) {
    const token = auth.slice(7).trim();
    if (config.jwtSecret && token.includes('.')) {
      const decoded = jwt.verify(token, config.jwtSecret) as jwt.JwtPayload;
      return {
        sub: String(decoded.sub || decoded.user_id || 'jwt-user'),
        org_id: decoded.org_id ? String(decoded.org_id) : headerOrg || undefined,
        role: normalizeRole(String(decoded.role || 'operator')) as RequestPrincipal['role'],
        scope: Array.isArray(decoded.scope) ? decoded.scope.map(String) : [],
        caller_type: 'jwt',
        actor_id: actorId || undefined,
        actor_role: actorRole || undefined,
        client_name: clientName || undefined
      };
    }
    if (config.sharedInternalKey && token === config.sharedInternalKey) {
      return {
        sub: 'service',
        org_id: config.orgDefault,
        role: 'service',
        scope: ['*'],
        caller_type: 'api_key',
        actor_id: actorId || undefined,
        actor_role: actorRole || undefined,
        client_name: clientName || undefined
      };
    }
  }

  const matchingKey = config.apiKeys.find((entry) => entry.key === apiKey);
  if (matchingKey) {
    return {
      sub: matchingKey.sub || matchingKey.key,
      org_id: matchingKey.org_id || headerOrg || config.orgDefault,
      role: (normalizeRole(matchingKey.role) as RequestPrincipal['role']) || 'service',
      scope: ['*'],
      caller_type: 'api_key',
      actor_id: actorId || undefined,
      actor_role: actorRole || undefined,
      client_name: clientName || undefined
    };
  }

  if (webhookSignature && config.webHookSecret) {
    const rawBody = typeof request.rawBody === 'string' ? request.rawBody : JSON.stringify(request.body || {});
    const expected = crypto.createHmac('sha256', config.webHookSecret).update(rawBody).digest('hex');
    if (expected === webhookSignature) {
      return {
        sub: 'webhook',
        org_id: headerOrg || config.orgDefault,
        role: 'integration',
        scope: ['relationships:write'],
        caller_type: 'webhook',
        actor_id: actorId || undefined,
        actor_role: actorRole || undefined,
        client_name: clientName || undefined
      };
    }
  }

  if (config.allowDevAuth) {
    return {
      sub: 'dev-local',
      org_id: headerOrg || config.orgDefault,
      role: 'admin',
      scope: ['*'],
      caller_type: 'anonymous',
      actor_id: actorId || undefined,
      actor_role: actorRole || undefined,
      client_name: clientName || undefined
    };
  }

  throw new Error('Unauthorized');
}

function principalFromRequest(request: any): RequestPrincipal {
  return request.principal as RequestPrincipal;
}

function assertOrgAccess(principal: RequestPrincipal, candidate?: string): string {
  const org = candidate || principal.org_id || config.orgDefault;
  if (principal.org_id && candidate && candidate !== principal.org_id) {
    throw new Error('Forbidden organization scope');
  }
  return org;
}

function hasScope(principal: RequestPrincipal, scope: string): boolean {
  return principal.scope.includes('*') || principal.scope.includes(scope);
}

function requireScope(principal: RequestPrincipal, scope: string, message = 'Forbidden scope'): void {
  if (!hasScope(principal, scope)) {
    throw new Error(message);
  }
}

function requireRole(principal: RequestPrincipal, checker: (role?: string) => boolean, message: string): void {
  if (!checker(principal.role)) {
    throw new Error(message);
  }
}

function isAiGatewayRole(role?: string): boolean {
  return role === 'operator' || role === 'admin';
}

function matchesAiLogFilter(log: Record<string, unknown>, query: Record<string, unknown>, org: string): boolean {
  if (org && String(log.org_id || '') !== org) return false;
  if (query.request_id && String(log.request_id || '') !== String(query.request_id)) return false;
  if (query.operator_id && String(log.operator_id || '') !== String(query.operator_id)) return false;
  if (query.endpoint && String(log.endpoint || '') !== String(query.endpoint)) return false;
  if (query.user_decision && String(log.user_decision || '') !== String(query.user_decision)) return false;
  return true;
}

function summarizeAiLogs(logs: Array<Record<string, unknown>>) {
  const total = logs.length;
  const fallbackCount = logs.filter((log) => Boolean(log.output_data && typeof log.output_data === 'object' && (log.output_data as Record<string, unknown>).meta && (log.output_data as Record<string, unknown>).meta?.fallback_used)).length;
  const byEndpoint = new Map<string, number>();
  const byModel = new Map<string, number>();
  const byDecision = new Map<string, number>();
  const byOperator = new Map<string, number>();
  let latestAt: string | null = null;

  for (const log of logs) {
    const endpoint = String(log.endpoint || 'unknown');
    const model = String(log.model_used || 'unknown');
    const decision = String(log.user_decision || 'n/a');
    const operator = String(log.operator_id || 'unknown');
    byEndpoint.set(endpoint, (byEndpoint.get(endpoint) || 0) + 1);
    byModel.set(model, (byModel.get(model) || 0) + 1);
    byDecision.set(decision, (byDecision.get(decision) || 0) + 1);
    byOperator.set(operator, (byOperator.get(operator) || 0) + 1);
    const updatedAt = String(log.updated_at || log.created_at || '');
    if (updatedAt && (!latestAt || updatedAt > latestAt)) {
      latestAt = updatedAt;
    }
  }

  return {
    total,
    fallback_count: fallbackCount,
    fallback_rate: total ? Number((fallbackCount / total).toFixed(3)) : 0,
    by_endpoint: Object.fromEntries(byEndpoint.entries()),
    by_model: Object.fromEntries(byModel.entries()),
    by_decision: Object.fromEntries(byDecision.entries()),
    by_operator: Object.fromEntries(byOperator.entries()),
    latest_at: latestAt
  };
}

function csvEscape(value: unknown): string {
  const text = String(value ?? '');
  if (/[",\n\r]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

function aiLogsToCsv(logs: Array<Record<string, unknown>>): string {
  const headers = ['id', 'org_id', 'request_id', 'operator_id', 'prompt_version', 'model_used', 'endpoint', 'user_decision', 'created_at', 'updated_at'];
  const rows = [headers.join(',')];
  for (const log of logs) {
    rows.push(headers.map((header) => csvEscape((log as Record<string, unknown>)[header])).join(','));
  }
  return `${rows.join('\n')}\n`;
}

async function serviceHealthSnapshot() {
  const services: ServiceName[] = ['osint', 'aiAnalysis', 'qwen', 'mainAgent', 'autonomous', 'inventory', 'proximity', 'routeCalculator', 'cctv'];
  const entries = await Promise.all(services.map(async (service) => [service, await getServiceHealth(service)] as const));
  const serviceStatus = Object.fromEntries(entries);
  const missing = services.filter((service) => !config.services[service].baseUrl);
  const unhealthy = entries
    .filter(([, health]) => !health.ok)
    .map(([service]) => service);
  return {
    ...serviceStatus,
    storage: {
      database: Boolean(config.databaseUrl),
      supabase: hasExternalBackend('supabase'),
      redis: hasExternalBackend('redis'),
      blob: hasExternalBackend('blob'),
      resend: hasExternalBackend('resend'),
      mode: hasExternalBackend('supabase') ? 'local_json_with_supabase_best_effort_sync' : 'local_json_files'
    },
    summary: {
      configured_services: services.length - missing.length,
      missing_services: missing,
      unhealthy_services: unhealthy,
      local_persistence: true
    }
  };
}

function now(): string {
  return new Date().toISOString();
}

function hashJson(value: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(value ?? {})).digest('hex');
}

function parseCursor(value: unknown): number {
  if (typeof value !== 'string' || !value.trim()) return 0;
  try {
    const decoded = Buffer.from(value, 'base64url').toString('utf8');
    const parsed = Number(decoded);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
  } catch {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
  }
}

function encodeCursor(offset: number): string {
  return Buffer.from(String(Math.max(0, offset)), 'utf8').toString('base64url');
}

function paginate<T>(items: T[], query: Record<string, unknown>, defaultLimit = 50) {
  const limit = Math.max(1, Math.min(200, toNumber(query.limit, defaultLimit) || defaultLimit));
  const offset = parseCursor(query.cursor) || Math.max(0, Math.floor(toNumber(query.offset, 0) || 0));
  const sliced = items.slice(offset, offset + limit);
  return {
    items: sliced,
    page: {
      limit,
      offset,
      next_cursor: offset + limit < items.length ? encodeCursor(offset + limit) : null,
      total: items.length
    }
  };
}

type OsintTaskRecord = {
  task_id: string;
  org_id: string;
  task_type: string;
  extra_keywords?: string;
  priority: number;
  source_id?: string;
  source_ids?: Array<string | number>;
  status: 'Pending' | 'Running' | 'Completed' | 'Failed';
  created_at: string;
  updated_at: string;
  result?: Record<string, unknown>;
};

const osintSources = [
  { id: '1', name: 'News feeds', status: 'online', type: 'news', last_collected_at: now() },
  { id: '2', name: 'Public web', status: 'online', type: 'web', last_collected_at: now() },
  { id: '3', name: 'Social signals', status: 'degraded', type: 'social', last_collected_at: now() }
];
const osintTasks = new Map<string, OsintTaskRecord>();
const osintAlertWorker = { running: false, updated_at: now() };
const osintTaskWorker = { running: false, updated_at: now() };

function osintLocalHealth() {
  return {
    status: 'success',
    service: 'osint',
    environment: config.env,
    storage: hasExternalBackend('supabase') ? 'supabase' : 'memory',
    sources: osintSources.length,
    tasks: osintTasks.size,
    worker_running: osintAlertWorker.running
  };
}

function osintLocalNlpStatus() {
  return {
    status: 'success',
    service: 'osint',
    nlp: {
      configured: false,
      spacy_enabled: false,
      transformers_enabled: false,
      model: null,
      status: 'heuristic'
    }
  };
}

function osintLocalDiagnostics() {
  return {
    status: 'success',
    service: 'osint',
    nlp: {
      spacy_enabled: false,
      transformers_enabled: false,
      status: 'heuristic'
    },
    queue: {
      pending_tasks: [...osintTasks.values()].filter((task) => task.status === 'Pending').length,
      running_tasks: [...osintTasks.values()].filter((task) => task.status === 'Running').length,
      completed_tasks: [...osintTasks.values()].filter((task) => task.status === 'Completed').length,
      failed_tasks: [...osintTasks.values()].filter((task) => task.status === 'Failed').length
    },
    worker: osintAlertWorker
  };
}

function osintLocalSourcePlan() {
  return {
    status: 'success',
    service: 'osint',
    data: {
      sources: osintSources,
      plan: osintSources.map((source) => ({
        source_id: source.id,
        source_name: source.name,
        collect: true,
        priority: source.id === '1' ? 1 : source.id === '2' ? 2 : 3
      }))
    }
  };
}

function buildOsintQueryResponse(body: Record<string, unknown>) {
  const question = String(body.question || body.query || 'OSINT query');
  const location = String(body.location || body.area || 'unknown');
  const lookbackDays = toNumber(body.lookback_days ?? body.days_back, 180) || 180;
  const recentLimit = toNumber(body.recent_limit ?? body.limit, 10) || 10;
  const riskRating = /robber|assault|weapon|gun|knife/i.test(question + ' ' + location) ? 'Amber' : 'Green';
  return {
    query: question,
    intent: 'intel',
    classification: {
      topic: 'public_safety',
      location,
      lookback_days: lookbackDays,
      recent_limit: recentLimit,
      confidence: riskRating === 'Amber' ? 84 : 68
    },
    entities: {
      people: [],
      locations: [location].filter(Boolean),
      organizations: []
    },
    packet: {
      summary: `OSINT packet for ${location}`,
      items: [],
      lookback_days: lookbackDays
    },
    source_health: {
      configured: osintSources.length > 0,
      total_sources: osintSources.length
    },
    operations: {
      queued_tasks: [...osintTasks.values()].filter((task) => task.status === 'Pending').length
    },
    source_rollup: osintSources.map((source) => ({
      id: source.id,
      name: source.name,
      status: source.status,
      last_collected_at: source.last_collected_at
    })),
    latest_brief: {
      org_id: String(body.org_id || config.orgDefault),
      days: lookbackDays,
      summary: `Latest intelligence brief for ${location}`
    },
    dashboard: {
      area: location,
      risk_rating: riskRating,
      recent_limit: recentLimit
    },
    recommended_action: riskRating === 'Amber' ? 'monitor' : 'review',
    risk_rating: riskRating
  };
}

function buildOsintPacketResponse(body: Record<string, unknown>) {
  const packet = body.packet || body;
  return {
    status: 'success',
    query: String(body.question || body.query || 'intel packet'),
    intent: 'intel',
    classification: body.classification || {
      category: 'general_intelligence',
      confidence: 70
    },
    entities: body.entities || {},
    packet: packet || {},
    source_health: {
      configured: osintSources.length > 0,
      total_sources: osintSources.length
    },
    operations: {
      queued_tasks: [...osintTasks.values()].filter((task) => task.status === 'Pending').length
    },
    source_rollup: osintSources,
    latest_brief: {
      org_id: String(body.org_id || config.orgDefault),
      days: toNumber(body.days, 7) || 7
    },
    dashboard: {
      risk_rating: 'Green'
    },
    recommended_action: 'monitor',
    risk_rating: 'Green'
  };
}

function upsertOsintTask(task: Partial<OsintTaskRecord> & { task_type: string; org_id: string }): OsintTaskRecord {
  const taskRecord: OsintTaskRecord = {
    task_id: task.task_id || crypto.randomUUID(),
    org_id: task.org_id,
    task_type: task.task_type,
    extra_keywords: task.extra_keywords,
    priority: task.priority ?? 5,
    source_id: task.source_id,
    source_ids: task.source_ids,
    status: task.status || 'Pending',
    created_at: task.created_at || now(),
    updated_at: now(),
    result: task.result
  };
  osintTasks.set(taskRecord.task_id, taskRecord);
  return taskRecord;
}

type ProximityQueryLogRecord = {
  request_id: string;
  incident_id: string;
  org_id: string;
  search_radius_km: number;
  total_on_shift: number;
  total_candidates_found: number;
  eta_available: boolean;
  query_time_ms: number;
  route_calculator_called: boolean;
  candidates_sent_to_route_calculator: number;
  timestamp: string;
};

const proximityQueryLogs: ProximityQueryLogRecord[] = [];

function recordProximityQueryLog(entry: ProximityQueryLogRecord): void {
  proximityQueryLogs.push(entry);
}

type RoutePushLogRecord = {
  route_id: string;
  org_id: string;
  officer_ids: string[];
  timestamp: string;
  delivered: boolean;
  relationship_api_delivered: boolean;
};

const routePushLogs: RoutePushLogRecord[] = [];

function routeRecommendedInfrastructure(incident: any, responders: { officers: string[]; vehicles: string[] }, routingType: string) {
  const recommendations: Array<Record<string, unknown>> = [];
  const indoor = Boolean(incident?.location?.indoor);
  const buildingId = String(incident?.building_id || incident?.location?.building_id || '');

  if (indoor) {
    recommendations.push({
      device_id: buildingId ? `AC-${buildingId}-ENTRY` : 'ACCESS-ENTRY-UNKNOWN',
      device_type: 'access_control',
      recommended_action: 'unlock_access_path',
      priority: 'critical',
      requires_approval: true,
      approval_level: 'supervisor',
      sequence_order: 1
    });
  }

  if (responders.officers.length) {
    recommendations.push({
      device_id: responders.officers[0],
      device_type: 'responder_channel',
      recommended_action: 'push_route_to_officers',
      priority: 'high',
      requires_approval: false,
      approval_level: 'none',
      sequence_order: 2
    });
  }

  if (responders.vehicles.length) {
    recommendations.push({
      device_id: responders.vehicles[0],
      device_type: 'vehicle_dispatch',
      recommended_action: 'dispatch_vehicle',
      priority: 'medium',
      requires_approval: false,
      approval_level: 'none',
      sequence_order: 3
    });
  }

  if (routingType === 'vehicle') {
    recommendations.push({
      device_id: 'route-calculator',
      device_type: 'routing_engine',
      recommended_action: 'push_geojson_to_dashboards',
      priority: 'low',
      requires_approval: false,
      approval_level: 'none',
      sequence_order: 4
    });
  }

  return recommendations;
}

function localRouteFromRequest(body: Record<string, unknown>, routeId?: string) {
  const requestId = String(body.request_id || crypto.randomUUID());
  const orgId = String(body.org_id || config.orgDefault);
  const incident = (body.incident as Record<string, unknown>) || {};
  const responders = (body.responders as Record<string, unknown>) || { officers: [], vehicles: [] };
  const preferences = (body.routing_preferences as Record<string, unknown>) || {};
  const officers = Array.isArray(responders.officers) ? responders.officers.map(String) : [];
  const vehicles = Array.isArray(responders.vehicles) ? responders.vehicles.map(String) : [];
  const indoor = Boolean(incident.indoor ?? (incident.location as Record<string, unknown>)?.indoor);
  const preferredType = String(preferences.type || (indoor ? 'foot' : vehicles.length ? 'hybrid' : 'foot'));
  const routeCount = Math.max(1, officers.length || vehicles.length || 1);
  const totalMs = 12 + routeCount * 5;
  const routes = Array.from({ length: routeCount }).map((_, index) => {
    const targetOfficer = officers[index] || officers[0] || null;
    const targetVehicle = vehicles[index] || vehicles[0] || null;
    const etaSeconds = preferredType === 'foot' ? 90 + index * 20 : 120 + index * 30;
    return {
      route_id: `${routeId || requestId}-segment-${index + 1}`,
      officer_id: targetOfficer,
      vehicle_id: targetVehicle,
      route_type: preferredType,
      eta_seconds: etaSeconds,
      eta_display: `${Math.floor(etaSeconds / 60)} min ${etaSeconds % 60} sec`,
      distance_metres: 1200 + index * 250,
      geometry: {
        type: 'LineString',
        coordinates: [
          [Number((incident.location as Record<string, unknown>)?.lng || 0), Number((incident.location as Record<string, unknown>)?.lat || 0)]
        ]
      }
    };
  });
  const infrastructureRecommendations = routeRecommendedInfrastructure(incident, { officers, vehicles }, preferredType);
  const pushRouteToOfficers = officers.slice(0, Math.max(1, officers.length));
  const routePlan = {
    route_id: routeId || requestId,
    request_id: requestId,
    org_id: orgId,
    incident_id: String(incident.id || requestId),
    incident,
    responders: { officers, vehicles },
    recommended_routing_type: preferredType,
    reasoning: indoor
      ? `Incident is indoor at ${(incident.location as Record<string, unknown>)?.description || 'unknown location'}.`
      : 'Outdoor or hybrid routing chosen based on responders and incident context.',
    routes,
    infrastructure_recommendations: infrastructureRecommendations,
    push_route_to_officers: pushRouteToOfficers,
    mapbox_route_geojson: {
      type: 'FeatureCollection',
      features: routes.map((route) => ({
        type: 'Feature',
        properties: { route_id: route.route_id, officer_id: route.officer_id, vehicle_id: route.vehicle_id },
        geometry: route.geometry
      }))
    },
    meta: {
      valhalla_query_ms: 0,
      radar_query_ms: 0,
      infra_query_ms: 0,
      total_ms: totalMs
    },
    pushed: false,
    created_at: now(),
    updated_at: now()
  };
  return saveRoutePlan(routePlan);
}

function haversineMetres(
  lat1: number,
  lng1: number,
  lat2: number,
  lng2: number
): number {
  const toRadians = (value: number) => (value * Math.PI) / 180;
  const earthRadiusMetres = 6371000;
  const deltaLat = toRadians(lat2 - lat1);
  const deltaLng = toRadians(lng2 - lng1);
  const a =
    Math.sin(deltaLat / 2) ** 2 +
    Math.cos(toRadians(lat1)) * Math.cos(toRadians(lat2)) * Math.sin(deltaLng / 2) ** 2;
  return 2 * earthRadiusMetres * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function formatEta(seconds: number): string {
  const rounded = Math.max(0, Math.round(seconds));
  const minutes = Math.floor(rounded / 60);
  const remainder = rounded % 60;
  if (!minutes) return `${remainder} sec`;
  return `${minutes} min ${remainder} sec`;
}

function normalizeCertifications(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map(String).filter(Boolean);
}

function getEntityCoordinate(entity: any): { lat?: number; lng?: number; description?: string; last_updated?: string } {
  const location = entity?.attributes?.current_location || entity?.attributes?.location || entity?.location || {};
  return {
    lat: Number(location.lat ?? entity?.attributes?.lat ?? entity?.lat),
    lng: Number(location.lng ?? entity?.attributes?.lng ?? entity?.lng),
    description: String(location.description || location.name || entity?.attributes?.location_description || entity?.name || ''),
    last_updated: String(location.last_updated || entity?.updated_at || entity?.attributes?.last_updated || '')
  };
}

function scoreOfficerCandidate(entity: any, incident: any): { candidate?: Record<string, unknown>; exclusionReason?: string } {
  const status = String(entity?.status || entity?.attributes?.status || '').toLowerCase();
  const shiftStatus = String(entity?.attributes?.shift_status || entity?.attributes?.duty_status || '').toLowerCase();
  const activeStatuses = new Set(['available', 'on_duty', 'active']);
  if (!activeStatuses.has(status) && !activeStatuses.has(shiftStatus)) {
    return { exclusionReason: 'not_on_shift' };
  }

  const currentIncidentId = String(entity?.attributes?.incident_id || entity?.attributes?.active_incident_id || '');
  if (currentIncidentId && currentIncidentId !== String(incident.id || '')) {
    return { exclusionReason: 'already_responding' };
  }

  const coord = getEntityCoordinate(entity);
  if (!Number.isFinite(coord.lat) || !Number.isFinite(coord.lng)) {
    return { exclusionReason: 'location_stale' };
  }

  const incidentLat = Number(incident?.location?.lat);
  const incidentLng = Number(incident?.location?.lng);
  if (!Number.isFinite(incidentLat) || !Number.isFinite(incidentLng)) {
    return { exclusionReason: 'incident_location_missing' };
  }

  const distanceMetres = haversineMetres(incidentLat, incidentLng, coord.lat!, coord.lng!);
  const searchRadiusMetres = Number(incident?._searchRadiusMetres || 5000);
  if (distanceMetres > searchRadiusMetres) {
    return { exclusionReason: 'outside_search_radius' };
  }

  const armed = Boolean(entity?.attributes?.armed ?? entity?.attributes?.weapon ?? entity?.attributes?.is_armed);
  const certifications = normalizeCertifications(entity?.attributes?.certifications);
  const preferredCerts = normalizeCertifications(incident?.requirements?.certifications_preferred);
  const matchedCertifications = preferredCerts.filter((cert) => certifications.includes(cert));
  const missingCertifications = preferredCerts.filter((cert) => !certifications.includes(cert));
  const fatigueFlag = Boolean(entity?.attributes?.fatigue_flag || Number(entity?.attributes?.hours_on_shift || 0) >= 8);
  const armedMatch = !incident?.requirements?.armed_required || armed;
  const distanceScore = Math.max(0, 100 - Math.min(100, Math.round((distanceMetres / Math.max(1, searchRadiusMetres)) * 100)));
  const fitScore = Math.max(
    0,
    Math.min(
      100,
      Math.round(
        distanceScore * 0.45 +
          (armedMatch ? 25 : 0) +
          Math.min(15, matchedCertifications.length * 7) +
          (fatigueFlag ? -15 : 0) +
          (String(incident?.location?.building_id || '') &&
          String(entity?.attributes?.current_location?.building_id || entity?.attributes?.building_id || '') === String(incident.location.building_id)
            ? 5
            : 0)
      )
    )
  );

  const etaSeconds = Math.max(20, Math.round(distanceMetres / 2.2));
  const routeType = String(incident?.location?.indoor ? 'foot' : 'vehicle');
  const parsedUpdatedAt = coord.last_updated ? Date.parse(coord.last_updated) : NaN;
  return {
    candidate: {
      rank: 0,
      officer_id: String(entity.id),
      name: String(entity.name || entity.id),
      badge: String(entity?.attributes?.badge || entity?.attributes?.badge_number || ''),
      contact: String(entity?.attributes?.contact || entity?.attributes?.phone || ''),
      status: status || shiftStatus || 'available',
      armed,
      weapon: String(entity?.attributes?.weapon || entity?.attributes?.primary_weapon || ''),
      certifications,
      current_location: {
        lat: coord.lat,
        lng: coord.lng,
        description: coord.description || '',
        last_updated: coord.last_updated || now(),
        seconds_since_update: Number.isFinite(parsedUpdatedAt)
          ? Math.max(0, Math.round((Date.now() - parsedUpdatedAt) / 1000))
          : 0
      },
      distance_metres: Math.round(distanceMetres),
      haversine_distance_metres: Math.round(distanceMetres),
      eta_seconds: etaSeconds,
      eta_display: formatEta(etaSeconds),
      route_type: routeType,
      fit_score: fitScore,
      fit_breakdown: {
        distance_score: distanceScore,
        armed_match: armedMatch,
        certifications_matched: matchedCertifications,
        certifications_missing: missingCertifications,
        fatigue_flag: fatigueFlag,
        hours_on_shift: Number(entity?.attributes?.hours_on_shift || 0)
      },
      recommendation_reason:
        `${distanceScore <= 30 ? 'Farther away' : 'Closest available'} officer` +
        `${matchedCertifications.length ? `, ${matchedCertifications.join(', ')} certified` : ''}` +
        `${armed ? ', armed' : ''}${etaSeconds ? `, ${etaSeconds}s ETA` : ''}`
    }
  };
}

function scoreVehicleCandidate(entity: any, incident: any): { candidate?: Record<string, unknown>; exclusionReason?: string } {
  const status = String(entity?.status || entity?.attributes?.status || '').toLowerCase();
  if (!['available', 'online', 'ready'].includes(status)) {
    return { exclusionReason: 'vehicle_unavailable' };
  }

  const coord = getEntityCoordinate(entity);
  if (!Number.isFinite(coord.lat) || !Number.isFinite(coord.lng)) {
    return { exclusionReason: 'location_stale' };
  }

  const incidentLat = Number(incident?.location?.lat);
  const incidentLng = Number(incident?.location?.lng);
  if (!Number.isFinite(incidentLat) || !Number.isFinite(incidentLng)) {
    return { exclusionReason: 'incident_location_missing' };
  }

  const distanceMetres = haversineMetres(incidentLat, incidentLng, coord.lat!, coord.lng!);
  const searchRadiusMetres = Number(incident?._searchRadiusMetres || 5000);
  if (distanceMetres > searchRadiusMetres) {
    return { exclusionReason: 'outside_search_radius' };
  }

  const fuelPercentage = Number(entity?.attributes?.fuel_percentage || entity?.attributes?.fuel || 100);
  if (fuelPercentage < 10) {
    return { exclusionReason: 'low_fuel' };
  }

  const etaSeconds = Math.max(30, Math.round(distanceMetres / 3));
  return {
    candidate: {
      rank: 0,
      vehicle_id: String(entity.id),
      name: String(entity.name || entity.id),
      status,
      current_location: {
        lat: coord.lat,
        lng: coord.lng,
        description: coord.description || '',
        last_updated: coord.last_updated || now()
      },
      distance_metres: Math.round(distanceMetres),
      eta_seconds: etaSeconds,
      eta_display: formatEta(etaSeconds),
      fit_score: Math.max(0, 100 - Math.round((distanceMetres / Math.max(1, searchRadiusMetres)) * 100) - (fuelPercentage < 30 ? 10 : 0)),
      fuel_percentage: fuelPercentage,
      recommendation_reason: 'Closest available vehicle'
    }
  };
}

async function buildProximityResult(body: Record<string, unknown>) {
  const started = Date.now();
  const requestId = String(body.request_id || crypto.randomUUID());
  const orgId = String(body.org_id || config.orgDefault);
  const incident = (body.incident as Record<string, unknown>) || {};
  const options = (body.options as Record<string, unknown>) || {};
  const requirements = (incident.requirements as Record<string, unknown>) || {};
  const searchRadiusKm = toNumber(options.search_radius_km, 5) || 5;
  const includeVehicles = toBool(options.include_vehicles, Number(requirements.vehicles_needed || 0) > 0);
  const requestEta = toBool(options.request_eta_from_route_calculator, true);
  const searchRadiusMetres = searchRadiusKm * 1000;
  (incident as any)._searchRadiusMetres = searchRadiusMetres;

  const allEntities = listEntities().filter((entity) => entity.org_id === orgId);
  const officers = allEntities.filter((entity) => entity.entity_type === 'officer');
  const vehicles = includeVehicles ? allEntities.filter((entity) => entity.entity_type === 'vehicle') : [];

  const officerResults: Array<Record<string, unknown>> = [];
  const excludedOfficers: Array<Record<string, unknown>> = [];
  for (const officer of officers) {
    const scored = scoreOfficerCandidate(officer, incident);
    if (scored.candidate) {
      officerResults.push(scored.candidate);
    } else if (scored.exclusionReason) {
      excludedOfficers.push({
        officer_id: String(officer.id),
        name: String(officer.name || officer.id),
        reason: scored.exclusionReason
      });
    }
  }

  officerResults.sort((a, b) => Number(b.fit_score || 0) - Number(a.fit_score || 0) || Number(a.distance_metres || 0) - Number(b.distance_metres || 0));

  const vehicleResults: Array<Record<string, unknown>> = [];
  for (const vehicle of vehicles) {
    const scored = scoreVehicleCandidate(vehicle, incident);
    if (scored.candidate) {
      vehicleResults.push(scored.candidate);
    }
  }
  vehicleResults.sort((a, b) => Number(b.fit_score || 0) - Number(a.fit_score || 0) || Number(a.distance_metres || 0) - Number(b.distance_metres || 0));

  let routeCalculatorCalled = false;
  let candidatesSentToRouteCalculator = 0;
  const warnings: string[] = [];
  const selectedOfficers = officerResults.slice(0, toNumber(requirements.officers_needed, 3) || 3);
  const selectedVehicles = vehicleResults.slice(0, toNumber(requirements.vehicles_needed, 0) || 0);
  if (requestEta && (selectedOfficers.length || selectedVehicles.length)) {
    const routePayload = {
      request_type: 'route_calculate',
      request_id: requestId,
      org_id: orgId,
      incident: {
        id: String(incident.id || requestId),
        location: incident.location || {},
        type: String(incident.type || 'unknown'),
        indoor: Boolean((incident.location as Record<string, unknown>)?.indoor),
        building_id: String((incident.location as Record<string, unknown>)?.building_id || '')
      },
      responders: {
        officers: selectedOfficers.map((officer) => String(officer.officer_id)),
        vehicles: selectedVehicles.map((vehicle) => String(vehicle.vehicle_id))
      },
      routing_preferences: {
        type: Boolean((incident.location as Record<string, unknown>)?.indoor) ? 'foot' : 'hybrid',
        prioritise: 'speed'
      }
    };
    const routeResult = await callService({ service: 'routeCalculator', path: '/route/calculate', body: routePayload });
    routeCalculatorCalled = true;
    candidatesSentToRouteCalculator = selectedOfficers.length + selectedVehicles.length;
    if (routeResult.fallback || !routeResult.ok) {
      warnings.push('route_calculator_unavailable');
    }
    if (!routeResult.fallback && routeResult.ok && routeResult.data && typeof routeResult.data === 'object') {
      const routes = (routeResult.data as any)?.data?.routes || (routeResult.data as any)?.routes || [];
      if (Array.isArray(routes)) {
        for (const officer of officerResults) {
          const route = routes.find((entry: any) => String(entry?.officer_id || entry?.target_id || '') === String(officer.officer_id));
          if (route) {
            officer.eta_seconds = route.eta_seconds ?? officer.eta_seconds;
            officer.eta_display = route.eta_display ?? officer.eta_display;
            officer.distance_metres = route.distance_metres ?? officer.distance_metres;
            officer.route_type = route.route_type ?? officer.route_type;
          }
        }
        for (const vehicle of vehicleResults) {
          const route = routes.find((entry: any) => String(entry?.vehicle_id || entry?.target_id || '') === String(vehicle.vehicle_id));
          if (route) {
            vehicle.eta_seconds = route.eta_seconds ?? vehicle.eta_seconds;
            vehicle.eta_display = route.eta_display ?? vehicle.eta_display;
            vehicle.distance_metres = route.distance_metres ?? vehicle.distance_metres;
            vehicle.route_type = route.route_type ?? vehicle.route_type;
          }
        }
      }
    }
  }

  const recommendedOfficers = officerResults.slice(0, toNumber(requirements.officers_needed, 3) || 3).map((officer, index) => ({
    ...officer,
    rank: index + 1
  }));
  const recommendedVehicles = vehicleResults.slice(0, toNumber(requirements.vehicles_needed, 0) || 0).map((vehicle, index) => ({
    ...vehicle,
    rank: index + 1
  }));

  const fastestResponder = recommendedOfficers[0]?.officer_id || recommendedVehicles[0]?.vehicle_id || null;
  const fastestEta = Math.min(
    ...[
      ...recommendedOfficers.map((officer) => Number(officer.eta_seconds || 0)).filter(Boolean),
      ...recommendedVehicles.map((vehicle) => Number(vehicle.eta_seconds || 0)).filter(Boolean)
    ]
  );
  const queryTimeMs = Date.now() - started;
  const totalCandidatesFound = officerResults.length + vehicleResults.length;
  const allRequirementsMet =
    recommendedOfficers.length >= (toNumber(requirements.officers_needed, 0) || 0) &&
    recommendedVehicles.length >= (toNumber(requirements.vehicles_needed, 0) || 0);

  const response = {
    request_id: requestId,
    status: 'success',
    data: {
      incident_id: String(incident.id || requestId),
      search_radius_km: searchRadiusKm,
      total_on_shift: officers.length,
      total_candidates_found: totalCandidatesFound,
      recommended_officers: recommendedOfficers,
      recommended_vehicles: recommendedVehicles,
      excluded_officers: excludedOfficers,
      summary: {
        fastest_responder: fastestResponder,
        fastest_eta_seconds: Number.isFinite(fastestEta) ? fastestEta : null,
        officers_available_in_area: officerResults.length,
        officers_recommended: recommendedOfficers.length,
        all_requirements_met: allRequirementsMet,
        warnings
      }
    },
    meta: {
      query_time_ms: queryTimeMs,
      route_calculator_called: routeCalculatorCalled,
      candidates_sent_to_route_calculator: candidatesSentToRouteCalculator
    }
  };

  return response;
}

function buildOrg(principal: RequestPrincipal, candidate?: string): string {
  return candidate || principal.org_id || config.orgDefault;
}

function normalizeEntityPayload(body: any, principal: RequestPrincipal) {
  const parsed = entitySchema.parse(body || {});
  return {
    id: parsed.id || crypto.randomUUID(),
    org_id: parsed.org_id || buildOrg(principal),
    entity_type: parsed.entity_type || 'unknown',
    name: parsed.name,
    status: parsed.status || 'active',
    attributes: parsed.attributes || {},
    aliases: parsed.aliases || []
  };
}

function normalizeRelationshipPayload(body: any, principal: RequestPrincipal) {
  const parsed = relationshipSchema.parse(body || {});
  return {
    id: parsed.id || crypto.randomUUID(),
    org_id: parsed.org_id || buildOrg(principal),
    source_entity_id: parsed.source_entity_id,
    target_entity_id: parsed.target_entity_id,
    relationship_type: parsed.relationship_type,
    confidence: parsed.confidence,
    status: parsed.status || 'active',
    metadata: parsed.metadata || {},
    created_by: parsed.created_by || principal.sub,
    idempotency_key: parsed.idempotency_key
  };
}

function graphNeighbors(
  entityId: string,
  orgId: string,
  depth = 2,
  direction = 'both',
  relationshipTypes: string[] = [],
  entityTypes: string[] = [],
  includeInactive = false
) {
  const visited = new Set<string>([entityId]);
  const queue = [{ id: entityId, level: 0 }];
  const foundEntities: any[] = [];
  const foundRelationships: any[] = [];

  while (queue.length) {
    const current = queue.shift();
    if (!current || current.level >= depth) continue;
    const edges = findRelationshipsByEntity(current.id).filter((relationship) => {
      if (relationship.org_id !== orgId) return false;
      if (!includeInactive && relationship.status === 'inactive') return false;
      if (relationshipTypes.length && !relationshipTypes.includes(relationship.relationship_type)) return false;
      return true;
    });
    for (const relationship of edges) {
      if (!foundRelationships.find((entry) => entry.id === relationship.id)) {
        foundRelationships.push(relationship);
      }
      const nextIds: string[] = [];
      if (direction === 'both' || direction === 'outbound') nextIds.push(relationship.target_entity_id);
      if (direction === 'both' || direction === 'inbound') nextIds.push(relationship.source_entity_id);
      for (const nextId of nextIds) {
        if (visited.has(nextId)) continue;
        visited.add(nextId);
        const entity = getEntity(nextId);
        if (entity && entity.org_id === orgId) {
          if (!entityTypes.length || entityTypes.includes(entity.entity_type)) {
            foundEntities.push(entity);
          }
          queue.push({ id: nextId, level: current.level + 1 });
        }
      }
    }
  }

  const root = getEntity(entityId);
  if (root && root.org_id === orgId && !foundEntities.find((entry) => entry.id === root.id)) {
    foundEntities.unshift(root);
  }

  return { entities: foundEntities, relationships: foundRelationships };
}

function normalizeDevicePayload(body: any, principal: RequestPrincipal) {
  return {
    id: String(body?.id || crypto.randomUUID()),
    org_id: String(body?.org_id || buildOrg(principal)),
    name: String(body?.name || 'Unnamed Device'),
    type: String(body?.type || 'device'),
    connection_type: String(body?.connection_type || 'REST_API'),
    supported_actions: Array.isArray(body?.supported_actions) ? body.supported_actions.map(String) : [],
    status: String(body?.status || 'offline'),
    connection_details: body?.connection_details || {},
    metadata: body?.metadata || {},
    created_at: body?.created_at || now(),
    updated_at: now()
  };
}

function normalizeBridgePayload(body: any, principal: RequestPrincipal) {
  return {
    id: String(body?.id || crypto.randomUUID()),
    org_id: String(body?.org_id || buildOrg(principal)),
    name: String(body?.name || 'Unnamed Bridge'),
    type: String(body?.type || 'bridge'),
    status: String(body?.status || 'offline'),
    metadata: body?.metadata || {},
    created_at: body?.created_at || now(),
    updated_at: now()
  };
}

function normalizeInventoryAlert(body: any, principal: RequestPrincipal) {
  const parsed = inventoryAlertSchema.parse(body || {});
  return {
    ...parsed,
    org_id: parsed.org_id || buildOrg(principal),
    timestamp: parsed.timestamp || now(),
    affected_resources: parsed.affected_resources || [],
    repeat_alert: parsed.repeat_alert ?? false
  };
}

function inventoryLocalQuery(body: any) {
  const requestType = String(body?.request_type || '');
  const orgId = String(body?.org_id || config.orgDefault);
  const alerts = listInventoryAlerts(orgId).filter((alert) => !alert.resolved);
  const base = {
    request_id: String(body?.request_id || crypto.randomUUID()),
    status: 'success',
    meta: { elapsed_ms: 0, soft_target_ms: 500, within_soft_target: true, degraded: true }
  };
  if (requestType === 'available_officers') {
    return {
      ...base,
      data: {
        officers: [],
        total_returned: 0
      }
    };
  }
  if (requestType === 'available_vehicles') {
    return {
      ...base,
      data: {
        vehicles: [],
        total_returned: 0
      }
    };
  }
  if (requestType === 'readiness_check') {
    const requirements = body?.operation_requirements || {};
    return {
      ...base,
      data: {
        ready: false,
        gaps: [
          ...(Number(requirements.officers_needed || 0) > 0 ? ['officers'] : []),
          ...(Number(requirements.vehicles_needed || 0) > 0 ? ['vehicles'] : []),
          ...(Array.isArray(requirements.equipment) && requirements.equipment.length ? requirements.equipment : [])
        ],
        available_to_deploy: {
          officers: 0,
          vehicles: 0,
          equipment: 0
        },
        recommendation: 'Manual review required; inventory service unavailable.',
        llm_review: null
      }
    };
  }
  return {
    ...base,
    data: {
      officers: {
        total: 0,
        available: 0,
        on_duty: 0,
        off_duty: 0,
        on_leave: 0,
        armed_available: 0,
        below_threshold: false
      },
      vehicles: {
        total: 0,
        available: 0,
        deployed: 0,
        fuelled: 0,
        below_threshold: true,
        threshold_alert_level: 'WARNING'
      },
      weapons: {
        pistols_available: 0,
        rifles_available: 0,
        tasers_available: 0,
        below_threshold: false
      },
      ammunition: {
        pistol_rounds: 0,
        rifle_rounds: 0,
        below_threshold: false
      },
      tactical: {
        body_armour_available: 0,
        radios_available: 0,
        first_aid_kits: 0,
        below_threshold: false
      },
      fuel_reserve: {
        litres: 0,
        percentage: 0,
        below_threshold: true,
        threshold_alert_level: 'WARNING'
      },
      cadence: {
        officers: {
          cadence_seconds: 60,
          stale_count: 0,
          stale_officers: []
        },
        vehicles: {
          running_cadence_seconds: 30,
          parked_cadence_seconds: 300,
          stale_count: 0,
          stale_vehicles: []
        }
      },
      active_alerts: alerts.length,
      last_updated: now(),
      llm_review: {
        approved: true,
        issues: [],
        risk_level: 'medium',
        missing_fields: [],
        recommended_actions: alerts.map((alert) => alert.recommended_action).filter(Boolean)
      }
    }
  };
}

function inventoryLocalUpdate(body: any) {
  const requestId = String(body?.request_id || crypto.randomUUID());
  return {
    request_id: requestId,
    status: 'success',
    data: {
      updated: true,
      request_type: body?.request_type,
      org_id: body?.org_id || config.orgDefault,
      payload: body
    }
  };
}

function inventoryLocalAlerts(orgId: string) {
  return {
    request_id: crypto.randomUUID(),
    status: 'success',
    data: listInventoryAlerts(orgId)
  };
}

function normalizeActionLogFromExecution(input: {
  request_id: string;
  org_id: string;
  incident_id?: string;
  device_id: string;
  device_name?: string;
  action_key: string;
  result: any;
  override_id: string;
}): ReturnType<typeof saveAutonomousLog> {
  const executedAt = now();
  const status = input.result?.ok === false || input.result?.status === 'failed' ? 'failed' : 'success';
  const payload = input.result?.data || input.result || {};
  const confirmed = Boolean(payload?.confirmed ?? payload?.success ?? status === 'success');
  const revertAt = payload?.revert_at || payload?.revert_at_scheduled || payload?.auto_revert_scheduled_at;
  return saveAutonomousLog({
    action_log_id: String(payload?.action_log_id || crypto.randomUUID()),
    request_id: input.request_id,
    org_id: input.org_id,
    incident_id: input.incident_id,
    device_id: input.device_id,
    device_name: input.device_name,
    action_key: input.action_key,
    execution_result: status === 'success' && confirmed ? 'success' : status === 'failed' ? 'failed' : 'unconfirmed',
    adapter_used: String(payload?.adapter_used || payload?.adapter || 'REST_API'),
    executed_at: String(payload?.executed_at || executedAt),
    confirmed,
    auto_revert_scheduled: Boolean(payload?.auto_revert_scheduled || payload?.auto_revert_scheduled === true || revertAt),
    revert_at: revertAt ? String(revertAt) : undefined,
    revert_action: payload?.revert_action ? String(payload.revert_action) : undefined,
    warnings: Array.isArray(payload?.warnings) ? payload.warnings.map(String) : [],
    active_override_id: String(payload?.active_override_id || input.override_id),
    error: typeof input.result?.error === 'string' ? input.result.error : typeof payload?.error === 'string' ? payload.error : undefined
  });
}

async function executeAutonomousAction(principal: RequestPrincipal, body: any) {
  requireRole(principal, isElevatedRole, 'Supervisor approval required');
  const parsed = autonomousActionSchema.parse(body || {});
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const device = getDevice(parsed.action.target_id);
  if (!device) {
    return {
      request_id: parsed.request_id,
      status: 'failed',
      error: 'Device not found',
      data: {
        approval_required: false,
        approval_level: parsed.authorisation.approval_level,
        pending: false
      }
    };
  }
  if (device.org_id !== org) {
    return {
      request_id: parsed.request_id,
      status: 'failed',
      error: 'Forbidden',
      data: {
        approval_required: false,
        approval_level: parsed.authorisation.approval_level,
        pending: false
      }
    };
  }
  if (device.supported_actions.length && !device.supported_actions.includes(parsed.action.type) && !device.supported_actions.includes(parsed.action.command)) {
    return {
      request_id: parsed.request_id,
      status: 'failed',
      error: 'Action not supported by device',
      data: {
        approval_required: false,
        approval_level: parsed.authorisation.approval_level,
        pending: false
      }
    };
  }
  const internalBody = internalAutonomousExecuteSchema.parse({
    request_type: 'execute_action',
    request_id: parsed.request_id,
    org_id: org,
    action: {
      action_key: parsed.action.type,
      device_id: parsed.action.target_id,
      parameters: {
        command: parsed.action.command,
        route_ids: parsed.action.route_ids,
        duration_seconds: parsed.action.duration_seconds,
        reason: parsed.action.reason,
        incident_id: parsed.action.incident_id
      }
    },
    authorisation: {
      approved_by: parsed.authorisation.approved_by,
      approval_timestamp: parsed.authorisation.approval_timestamp,
      approval_level: parsed.authorisation.approval_level,
      incident_id: parsed.authorisation.incident_id || parsed.action.incident_id
    }
  });
  const result = await callService({
    service: 'autonomous',
    path: '/execute',
    body: internalBody
  });
  const payload = (result.data as any)?.data || (result.data as any)?.action_result || result.data || {};
  const overrideId = String(payload.active_override_id || crypto.randomUUID());
  saveOverride({
    override_id: overrideId,
    request_id: parsed.request_id,
    org_id: org,
    incident_id: parsed.authorisation.incident_id || parsed.action.incident_id,
    action_key: parsed.action.type,
    device_id: parsed.action.target_id,
    status: result.ok ? 'active' : 'failed',
    approved_by: parsed.authorisation.approved_by,
    approval_level: parsed.authorisation.approval_level,
    created_at: now(),
    executed_at: now(),
    payload: parsed,
    result: result.data
  });
  const actionLog = normalizeActionLogFromExecution({
    request_id: parsed.request_id,
    org_id: org,
    incident_id: parsed.authorisation.incident_id || parsed.action.incident_id,
    device_id: parsed.action.target_id,
    device_name: device?.name,
    action_key: parsed.action.type,
    result,
    override_id: overrideId
  });
  return {
    request_id: parsed.request_id,
    status: result.ok ? 'success' : 'failed',
    data: {
      action_log_id: actionLog.action_log_id,
      device_id: actionLog.device_id,
      device_name: actionLog.device_name,
      action_key: actionLog.action_key,
      execution_result: actionLog.execution_result,
      adapter_used: actionLog.adapter_used,
      executed_at: actionLog.executed_at,
      confirmed: actionLog.confirmed,
      auto_revert_scheduled: actionLog.auto_revert_scheduled,
      revert_at: actionLog.revert_at,
      revert_action: actionLog.revert_action || 'release',
      warnings: actionLog.warnings,
      active_override_id: actionLog.active_override_id,
      error: actionLog.error
    },
    meta: { degraded: result.fallback }
  };
}

async function revertAutonomousOverride(principal: RequestPrincipal, overrideId: string) {
  requireRole(principal, isElevatedRole, 'Supervisor approval required');
  const record = listOverrides().find((entry) => entry.override_id === overrideId);
  if (record) {
    record.status = 'reverted';
    record.revert_at = now();
  }
  const result = await callService({
    service: 'autonomous',
    path: `/revert/${encodeURIComponent(overrideId)}`,
    method: 'POST',
    body: { override_id: overrideId }
  });
  return {
    status: 'success',
    data: {
      override_id: overrideId,
      success: true,
      adapter: 'REST_API',
      response: {
        result: 'ok'
      },
      local_record: record || null,
      upstream: result.data
    },
    meta: { degraded: result.fallback }
  };
}

app.addHook('preHandler', async (request, reply) => {
  const path = request.raw.url || request.url || '';
  const isPublic =
    path.startsWith('/health') ||
    path.startsWith('/v1/health') ||
    path.startsWith('/api/v1/health') ||
    path.startsWith('/ready') ||
    path.startsWith('/v1/ready') ||
    path.startsWith('/api/v1/ready') ||
    path.startsWith('/masterai/health') ||
    path.startsWith('/api/v1/masterai/health');
  if (isPublic) return;
  try {
    const principal = await parsePrincipal(request);
    request.principal = principal;
  } catch (error) {
    return reply.code(401).send({ status: 'error', error: error instanceof Error ? error.message : 'Unauthorized' });
  }
});

app.addHook('onResponse', async (request, reply) => {
  const principal = request.principal as RequestPrincipal | undefined;
  const request_id = String(request.headers['x-request-id'] || request.id);
  const statusCode = Number(reply.statusCode || 0);
  const aiAudit = (request as any).aiAudit || {};
  const audit = {
    id: crypto.randomUUID(),
    request_id,
    method: request.method,
    path: request.url,
    status_code: statusCode,
    duration_ms: Date.now() - ((request as any).startedAt || Date.now()),
    org_id: principal?.org_id,
    role: principal?.role,
    sub: principal?.sub,
    client_name: principal?.client_name,
    actor_id: principal?.actor_id,
    actor_role: principal?.actor_role,
    service_calls: (request as any).serviceCalls || [],
    ai_endpoint: aiAudit.ai_endpoint,
    ai_operation_id: aiAudit.ai_operation_id,
    ai_prompt_version: aiAudit.ai_prompt_version,
    ai_model: aiAudit.ai_model,
    ai_confidence: aiAudit.ai_confidence,
    ai_recommendation: aiAudit.ai_recommendation,
    ai_operator_id: aiAudit.ai_operator_id,
    ai_fallback_used: aiAudit.ai_fallback_used,
    success: statusCode < 400,
    timestamp: new Date().toISOString()
  };
  try {
    pushAudit(audit, config.auditLogPath);
  } catch (error) {
    request.log.error({ error }, 'Failed to write audit log');
  }

  const aiLog = (request as any).aiLog;
  if (aiLog) {
    try {
      saveAiLog({
        id: String(aiLog.id || crypto.randomUUID()),
        org_id: aiLog.org_id,
        request_id: String(aiLog.request_id || request_id),
        operator_id: aiLog.operator_id,
        prompt_version: aiLog.prompt_version,
        model_used: aiLog.model_used,
        endpoint: String(aiLog.endpoint || request.url),
        input_data: (aiLog.input_data as Record<string, unknown>) || {},
        output_data: (aiLog.output_data as Record<string, unknown>) || {},
        user_decision: aiLog.user_decision,
        created_at: String(aiLog.created_at || new Date().toISOString()),
        updated_at: new Date().toISOString()
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to write AI log');
    }
  } else if ((request as any).aiInboundPayload && request.url.startsWith('/ai/')) {
    try {
      saveAiLog({
        id: crypto.randomUUID(),
        org_id: principal?.org_id,
        request_id,
        operator_id: principal?.actor_id || principal?.sub,
        prompt_version: config.qwenPromptVersion,
        model_used: config.qwenModel,
        endpoint: request.url,
        input_data: (request as any).aiInboundPayload || {},
        output_data: {
          status_code: statusCode,
          success: statusCode < 400
        },
        user_decision: 'n/a',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to write fallback AI log');
    }
  }
});

app.setErrorHandler(async (error, request, reply) => {
  request.log.error(error);
  await reply.code(500).send({
    status: 'error',
    error: error instanceof Error ? error.message : 'Internal server error'
  });
});

async function recordServiceCall(request: any, label: string): Promise<void> {
  (request as any).serviceCalls ||= [];
  (request as any).serviceCalls.push(label);
}

function validateAiBody<T>(schema: { safeParse: (value: unknown) => { success: boolean; data?: T; error?: any } }) {
  return async (request: any, reply: any) => {
    const parsed = schema.safeParse(request.body || {});
    if (!parsed.success) {
      return reply.code(400).send({
        status: 'error',
        error: 'Invalid AI request payload',
        details: parsed.error?.flatten ? parsed.error.flatten() : parsed.error
      });
    }
    request.aiValidatedBody = parsed.data;
  };
}

function validateBodySchema<T>(schema: { safeParse: (value: unknown) => { success: boolean; data?: T; error?: any } }, label = 'request') {
  return async (request: any, reply: any) => {
    const parsed = schema.safeParse(request.body || {});
    if (!parsed.success) {
      return reply.code(400).send({
        status: 'error',
        error: `Invalid ${label} payload`,
        details: parsed.error?.flatten ? parsed.error.flatten() : parsed.error
      });
    }
    request.validatedBody = parsed.data;
  };
}

function setAiLog(request: any, aiLog: {
  org_id?: string;
  request_id: string;
  operator_id?: string;
  prompt_version?: string;
  model_used?: string;
  endpoint: string;
  input_data: Record<string, unknown>;
  output_data: Record<string, unknown>;
  user_decision?: string;
}) {
  request.aiLog = {
    id: crypto.randomUUID(),
    created_at: new Date().toISOString(),
    ...aiLog
  };
}

async function proxyCctvRequest(
  request: any,
  servicePath: string,
  method: 'GET' | 'POST',
  body?: unknown
): Promise<Record<string, unknown>> {
  const result = await callService({
    service: 'cctv',
    path: servicePath,
    method,
    body
  });
  (request as any).serviceCalls = [...((request as any).serviceCalls || []), 'cctv'];
  return {
    status: result.ok ? 'success' : 'failed',
    data: result.data,
    meta: { degraded: result.fallback, service: 'cctv' }
  };
}

app.get(['/health', '/v1/health', '/api/v1/health'], async () => {
  const bridges = listBridges();
  const devices = listDevices();
  const services: ServiceName[] = ['osint', 'aiAnalysis', 'mainAgent', 'autonomous', 'inventory', 'proximity', 'routeCalculator', 'cctv'];
  const serviceStatus = Object.fromEntries(
    services.map((service) => [
      service,
      {
        ok: true,
        status: 200,
        fallback: !config.services[service].baseUrl,
        duration_ms: 0,
        service
      }
    ])
  );
  const missing = services.filter((service) => !config.services[service].baseUrl);
  const fastServicesSnapshot = {
    ...serviceStatus,
    storage: {
      database: Boolean(config.databaseUrl),
      supabase: hasExternalBackend('supabase'),
      redis: hasExternalBackend('redis'),
      blob: hasExternalBackend('blob'),
      resend: hasExternalBackend('resend'),
      mode: hasExternalBackend('supabase') ? 'local_json_with_supabase_best_effort_sync' : 'local_json_files'
    },
    summary: {
      configured_services: services.length - missing.length,
      missing_services: missing,
      unhealthy_services: [],
      local_persistence: true
    }
  };
  return {
    status: 'success',
    service: 'relationship-api',
    environment: config.env,
    timestamp: new Date().toISOString(),
    device_count: devices.length,
    bridge_count: bridges.length,
    adapter_connectivity: {
      devices: devices.filter((device) => device.status === 'online').length,
      bridges: bridges.filter((bridge) => bridge.status === 'online').length
    },
    services: fastServicesSnapshot
  };
});

app.get(['/health/:service', '/api/v1/health/:service'], async (request, reply) => {
  const service = String((request.params as Record<string, unknown>).service || '');
  const allowed = new Set(['osint', 'aiAnalysis', 'qwen', 'mainAgent', 'autonomous', 'inventory', 'proximity', 'routeCalculator', 'cctv']);
  if (!allowed.has(service)) {
    return reply.code(404).send({ status: 'error', error: 'Unknown service' });
  }
  return {
    status: 'success',
    service,
    health: await getServiceHealth(service as ServiceName)
  };
});

app.get(['/ready', '/v1/ready', '/api/v1/ready'], async (_request, reply) => {
  const services = await serviceHealthSnapshot();
  const upstreams = ['osint', 'aiAnalysis', 'mainAgent', 'autonomous', 'inventory', 'proximity', 'routeCalculator', 'cctv'];
  const healthyCount = upstreams.filter((name) => (services as any)[name]?.ok === true).length;
  const requiredHealthy = Math.min(4, upstreams.length);
  const ready = healthyCount >= requiredHealthy;
  if (!ready) reply.code(503);
  return {
    status: ready ? 'ready' : 'degraded',
    service: 'relationship-api',
    storage: (services as any).storage,
    healthy_services: healthyCount,
    required_healthy_services: requiredHealthy,
    services
  };
});

app.get(['/api/v1/schema', '/v1/schema'], async () => {
  return {
    ok: true,
    entity_types: ['person', 'user', 'officer', 'incident', 'location', 'zone', 'asset', 'device', 'vehicle', 'organization', 'contact', 'evidence'],
    relationship_types: ['assigned_to', 'reported_at', 'located_in', 'linked_to', 'owns', 'monitors', 'responding_to', 'near', 'member_of'],
    endpoints: {
      entities: ['/v1/entities', '/v1/entities/:id', '/v1/entities/:id/relationships', '/v1/entities/:id/graph'],
      relationships: ['/v1/relationships', '/v1/relationships/:id'],
      graph: ['/v1/graph/query']
    }
  };
});

app.get(['/api/v1/entity-types', '/v1/entity-types'], async () => ({
  ok: true,
  entity_types: ['person', 'user', 'officer', 'incident', 'location', 'zone', 'asset', 'device', 'vehicle', 'organization', 'contact', 'evidence']
}));

app.get(['/api/v1/relationship-types', '/v1/relationship-types'], async () => ({
  ok: true,
  relationship_types: ['assigned_to', 'reported_at', 'located_in', 'linked_to', 'owns', 'monitors', 'responding_to', 'near', 'member_of']
}));

app.post(['/api/v1/entities', '/v1/entities'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const entity = normalizeEntityPayload(request.body, principal);
  const saved = saveEntity({ ...entity, created_at: now(), updated_at: now() });
  saveGraphEvent({
    id: crypto.randomUUID(),
    org_id: saved.org_id,
    event_type: 'entity.created',
    entity_id: saved.id,
    payload: { entity: saved },
    created_at: now()
  });
  return { ok: true, entity: saved };
});

app.get(['/api/v1/entities', '/v1/entities'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const org = buildOrg(principal, String((request.query as Record<string, unknown>).org_id || ''));
  const entity_type = String((request.query as Record<string, unknown>).entity_type || '');
  const status = String((request.query as Record<string, unknown>).status || '');
  const items = listEntities().filter((entity) => {
    if (entity.org_id !== org) return false;
    if (entity_type && entity.entity_type !== entity_type) return false;
    if (status && String(entity.status || '').toLowerCase() !== status.toLowerCase()) return false;
    return true;
  });
  const paged = paginate(items, request.query as Record<string, unknown>);
  return { ok: true, entities: paged.items, page: paged.page };
});

app.get(['/api/v1/entities/:id', '/v1/entities/:id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const id = String((request.params as Record<string, unknown>).id);
  const entity = getEntity(id);
  if (!entity) return reply.code(404).send({ ok: false, error: { code: 'ENTITY_NOT_FOUND', message: 'Entity not found' } });
  if (entity.org_id !== buildOrg(principal, entity.org_id)) {
    return reply.code(403).send({ ok: false, error: { code: 'FORBIDDEN', message: 'Forbidden' } });
  }
  return { ok: true, entity };
});

app.patch(['/api/v1/entities/:id', '/v1/entities/:id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const id = String((request.params as Record<string, unknown>).id);
  const existing = getEntity(id);
  if (!existing) return reply.code(404).send({ ok: false, error: { code: 'ENTITY_NOT_FOUND', message: 'Entity not found' } });
  const body = entitySchema.parse(request.body || {});
  const updated = saveEntity({
    ...existing,
    entity_type: body.entity_type || existing.entity_type,
    name: body.name ?? existing.name,
    status: body.status ?? existing.status,
    attributes: { ...existing.attributes, ...(body.attributes || {}) },
    aliases: Array.from(new Set([...(existing.aliases || []), ...((body.aliases || []) as string[])])),
    org_id: existing.org_id,
    updated_at: now()
  });
  saveGraphEvent({
    id: crypto.randomUUID(),
    org_id: updated.org_id,
    event_type: 'entity.updated',
    entity_id: updated.id,
    payload: { entity: updated, actor: principal.sub },
    created_at: now()
  });
  return { ok: true, entity: updated };
});

app.post(['/api/v1/relationships', '/v1/relationships'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const relationship = normalizeRelationshipPayload(request.body, principal);
  if (relationship.idempotency_key) {
    const known = getIdempotentRecord(relationship.idempotency_key);
    const payloadHash = hashJson({
      source_entity_id: relationship.source_entity_id,
      target_entity_id: relationship.target_entity_id,
      relationship_type: relationship.relationship_type,
      confidence: relationship.confidence,
      status: relationship.status,
      metadata: relationship.metadata,
      org_id: relationship.org_id
    });
    if (known) {
      if (known.payloadHash && known.payloadHash !== payloadHash) {
        return {
          ok: false,
          error: {
            code: 'CONFLICT',
            message: 'Idempotency key already used with a different payload'
          }
        };
      }
      const existing = getRelationship(known.responseId);
      if (existing) {
        return { ok: true, relationship: existing, idempotent: true };
      }
    }
  }
  const saved = saveRelationship({ ...relationship, created_at: now(), updated_at: now() });
  if (saved.idempotency_key) {
    setIdempotentResponse(
      saved.idempotency_key,
      saved.id,
      hashJson({
        source_entity_id: saved.source_entity_id,
        target_entity_id: saved.target_entity_id,
        relationship_type: saved.relationship_type,
        confidence: saved.confidence,
        status: saved.status,
        metadata: saved.metadata,
        org_id: saved.org_id
      })
    );
  }
  saveGraphEvent({
    id: crypto.randomUUID(),
    org_id: saved.org_id,
    event_type: 'relationship.created',
    relationship_id: saved.id,
    correlation_id: request.headers['x-request-id'] ? String(request.headers['x-request-id']) : undefined,
    payload: { relationship: saved },
    created_at: now()
  });
  return { ok: true, relationship: saved };
});

app.get(['/api/v1/relationships', '/v1/relationships'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const org = buildOrg(principal, String((request.query as Record<string, unknown>).org_id || ''));
  const entity_id = String((request.query as Record<string, unknown>).entity_id || '');
  const type = String((request.query as Record<string, unknown>).type || '');
  const status = String((request.query as Record<string, unknown>).status || '');
  const confidenceMin = toNumber((request.query as Record<string, unknown>).confidence_min, 0) || 0;
  const confidenceMax = toNumber((request.query as Record<string, unknown>).confidence_max, 1) || 1;
  const items = listRelationships().filter((relationship) => {
    if (relationship.org_id !== org) return false;
    if (entity_id && relationship.source_entity_id !== entity_id && relationship.target_entity_id !== entity_id) return false;
    if (type && relationship.relationship_type !== type) return false;
    if (status && String(relationship.status || '').toLowerCase() !== status.toLowerCase()) return false;
    if (relationship.confidence < confidenceMin || relationship.confidence > confidenceMax) return false;
    return true;
  });
  const paged = paginate(items, request.query as Record<string, unknown>);
  return { ok: true, relationships: paged.items, page: paged.page };
});

app.get(['/api/v1/relationships/:id', '/v1/relationships/:id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const id = String((request.params as Record<string, unknown>).id);
  const relationship = getRelationship(id);
  if (!relationship) return reply.code(404).send({ ok: false, error: { code: 'RELATIONSHIP_NOT_FOUND', message: 'Relationship not found' } });
  if (relationship.org_id !== buildOrg(principal, relationship.org_id)) {
    return reply.code(403).send({ ok: false, error: { code: 'FORBIDDEN', message: 'Forbidden' } });
  }
  return { ok: true, relationship };
});

app.patch(['/api/v1/relationships/:id', '/v1/relationships/:id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const id = String((request.params as Record<string, unknown>).id);
  const existing = getRelationship(id);
  if (!existing) return reply.code(404).send({ ok: false, error: { code: 'RELATIONSHIP_NOT_FOUND', message: 'Relationship not found' } });
  const body = relationshipSchema.parse(request.body || {});
  const updated = saveRelationship({
    ...existing,
    relationship_type: body.relationship_type || existing.relationship_type,
    confidence: body.confidence ?? existing.confidence,
    status: body.status || existing.status,
    metadata: { ...existing.metadata, ...(body.metadata || {}) },
    updated_at: now(),
    ended_at: body.status === 'inactive' ? now() : existing.ended_at,
    ended_reason: body.status === 'inactive' ? String((body.metadata || {}).ended_reason || 'updated') : existing.ended_reason,
    created_by: existing.created_by || principal.sub
  });
  saveGraphEvent({
    id: crypto.randomUUID(),
    org_id: updated.org_id,
    event_type: 'relationship.updated',
    relationship_id: updated.id,
    payload: { relationship: updated, actor: principal.sub },
    created_at: now()
  });
  return { ok: true, relationship: updated };
});

app.delete(['/api/v1/relationships/:id', '/v1/relationships/:id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const id = String((request.params as Record<string, unknown>).id);
  const existing = getRelationship(id);
  if (!existing) return reply.code(404).send({ ok: false, error: { code: 'RELATIONSHIP_NOT_FOUND', message: 'Relationship not found' } });
  const archived = saveRelationship({
    ...existing,
    status: 'inactive',
    ended_at: now(),
    ended_reason: 'deleted'
  });
  saveGraphEvent({
    id: crypto.randomUUID(),
    org_id: archived.org_id,
    event_type: 'relationship.deleted',
    relationship_id: archived.id,
    payload: { relationship: archived },
    created_at: now()
  });
  return { ok: true, relationship: archived };
});

app.post(['/api/v1/graph/query', '/v1/graph/query'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const query = graphQuerySchema.parse(request.body || {});
  const org = buildOrg(principal);
  const graph = graphNeighbors(
    query.root_entity_id,
    org,
    query.depth,
    query.direction,
    query.relationship_types,
    query.entity_types,
    query.include_inactive
  );
  return {
    ok: true,
    root_entity_id: query.root_entity_id,
    depth: query.depth,
    graph
  };
});

app.get(['/api/v1/entities/:id/graph', '/v1/entities/:id/graph'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const id = String((request.params as Record<string, unknown>).id);
  const query = request.query as Record<string, unknown>;
  const depth = toNumber(query.depth, 2) || 2;
  const direction = String(query.direction || 'both') as 'inbound' | 'outbound' | 'both';
  const relationshipTypes = Array.isArray(query.relationship_types)
    ? (query.relationship_types as unknown[]).map(String)
    : String(query.relationship_types || '')
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
  const entityTypes = Array.isArray(query.entity_types)
    ? (query.entity_types as unknown[]).map(String)
    : String(query.entity_types || '')
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
  const graph = graphNeighbors(id, buildOrg(principal), depth, direction, relationshipTypes, entityTypes, Boolean(query.include_inactive));
  return { ok: true, root_entity_id: id, graph };
});

app.get(['/api/v1/entities/:id/relationships', '/v1/entities/:id/relationships'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const id = String((request.params as Record<string, unknown>).id);
  const query = request.query as Record<string, unknown>;
  const depth = toNumber(query.depth, 1) || 1;
  const direction = String(query.direction || 'both') as 'inbound' | 'outbound' | 'both';
  const relationshipTypes = Array.isArray(query.relationship_types)
    ? (query.relationship_types as unknown[]).map(String)
    : String(query.relationship_types || '')
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
  const entityTypes = Array.isArray(query.entity_types)
    ? (query.entity_types as unknown[]).map(String)
    : String(query.entity_types || '')
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
  const graph = graphNeighbors(id, buildOrg(principal), depth, direction, relationshipTypes, entityTypes, Boolean(query.include_inactive));
  return { ok: true, entity_id: id, relationships: graph.relationships };
});

app.post(['/api/v1/ingest', '/v1/ingest'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = request.body as any;
  const eventId = body?.event_id || crypto.randomUUID();
  const org = body?.org_id || buildOrg(principal);
  const event = {
    id: eventId,
    org_id: org,
    event_type: body?.event_type || 'ingest',
    entity_id: body?.entity_id,
    relationship_id: body?.relationship_id,
    correlation_id: body?.correlation_id || (request.headers['x-request-id'] ? String(request.headers['x-request-id']) : undefined),
    payload: body || {},
    created_at: now()
  };
  saveGraphEvent(event);
  if (body?.entity) {
    saveEntity({
      id: body.entity.id || crypto.randomUUID(),
      org_id: org,
      entity_type: body.entity.entity_type || 'unknown',
      name: body.entity.name,
      status: body.entity.status || 'active',
      attributes: body.entity.attributes || {},
      aliases: body.entity.aliases || [],
      created_at: now(),
      updated_at: now()
    });
  }
  if (body?.relationship) {
    saveRelationship({
      id: body.relationship.id || crypto.randomUUID(),
      org_id: org,
      source_entity_id: body.relationship.source_entity_id,
      target_entity_id: body.relationship.target_entity_id,
      relationship_type: body.relationship.relationship_type,
      confidence: body.relationship.confidence ?? 1,
      status: body.relationship.status || 'active',
      metadata: body.relationship.metadata || {},
      created_at: now(),
      updated_at: now()
    });
  }
  return { ok: true, event };
});

app.post(['/api/v1/events', '/v1/events'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = request.body as any;
  const event = {
    id: body?.id || crypto.randomUUID(),
    org_id: body?.org_id || buildOrg(principal),
    event_type: body?.event_type || 'event',
    entity_id: body?.entity_id,
    relationship_id: body?.relationship_id,
    correlation_id: body?.correlation_id,
    payload: body || {},
    created_at: now()
  };
  saveGraphEvent(event);
  return { ok: true, event };
});

app.post(['/api/v1/webhooks', '/v1/webhooks'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = request.body as any;
  const event = {
    id: body?.id || crypto.randomUUID(),
    org_id: body?.org_id || buildOrg(principal),
    event_type: body?.event_type || 'webhook.received',
    entity_id: body?.entity_id,
    relationship_id: body?.relationship_id,
    correlation_id: body?.correlation_id,
    payload: body || {},
    created_at: now()
  };
  saveGraphEvent(event);
  return { ok: true, event };
});

app.post(['/internal/inventory-alert', '/api/v1/internal/inventory-alert'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const alert = normalizeInventoryAlert(request.body, principal);
  saveInventoryAlert(alert);
  const event = saveGraphEvent({
    id: alert.alert_id,
    org_id: alert.org_id || buildOrg(principal),
    event_type: 'inventory.alert',
    correlation_id: request.headers['x-request-id'] ? String(request.headers['x-request-id']) : undefined,
    payload: alert,
    created_at: alert.timestamp || now()
  });
  return { ok: true, alert: event };
});

app.get(['/devices', '/api/v1/devices'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const org = buildOrg(principal, String((request.query as Record<string, unknown>).org_id || ''));
  return {
    status: 'success',
    data: listDevices().filter((device) => device.org_id === org)
  };
});

app.get(['/devices/:device_id', '/api/v1/devices/:device_id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const deviceId = String((request.params as Record<string, unknown>).device_id);
  const device = getDevice(deviceId);
  if (!device) return reply.code(404).send({ status: 'error', error: 'Device not found' });
  if (device.org_id !== buildOrg(principal, device.org_id)) {
    return reply.code(403).send({ status: 'error', error: 'Forbidden' });
  }
  return { status: 'success', data: device };
});

app.post(['/devices', '/api/v1/devices'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const device = normalizeDevicePayload(request.body, principal);
  return { status: 'success', data: saveDevice(device) };
});

app.put(['/devices/:device_id', '/api/v1/devices/:device_id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const deviceId = String((request.params as Record<string, unknown>).device_id);
  const existing = getDevice(deviceId);
  if (!existing) return reply.code(404).send({ status: 'error', error: 'Device not found' });
  const body = request.body as any;
  const updated = saveDevice({
    ...existing,
    name: String(body?.name || existing.name),
    type: String(body?.type || existing.type),
    connection_type: String(body?.connection_type || existing.connection_type),
    supported_actions: Array.isArray(body?.supported_actions) ? body.supported_actions.map(String) : existing.supported_actions,
    status: String(body?.status || existing.status),
    connection_details: body?.connection_details || existing.connection_details || {},
    metadata: body?.metadata || existing.metadata || {},
    org_id: existing.org_id || buildOrg(principal),
    updated_at: now()
  });
  return { status: 'success', data: updated };
});

app.get(['/devices/:device_id/status', '/api/v1/devices/:device_id/status'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const deviceId = String((request.params as Record<string, unknown>).device_id);
  const device = getDevice(deviceId);
  if (!device) return reply.code(404).send({ status: 'error', error: 'Device not found' });
  if (device.org_id !== buildOrg(principal, device.org_id)) {
    return reply.code(403).send({ status: 'error', error: 'Forbidden' });
  }
  return {
    status: 'success',
    data: {
      id: device.id,
      status: device.status,
      latest_command_state: listAutonomousLogs(50).find((entry) => entry.device_id === device.id) || null
    }
  };
});

app.get(['/bridges', '/api/v1/bridges'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const org = buildOrg(principal, String((request.query as Record<string, unknown>).org_id || ''));
  return {
    status: 'success',
    data: listBridges().filter((bridge) => bridge.org_id === org)
  };
});

app.get(['/bridges/:bridge_id', '/api/v1/bridges/:bridge_id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const bridgeId = String((request.params as Record<string, unknown>).bridge_id);
  const bridge = getBridge(bridgeId);
  if (!bridge) return reply.code(404).send({ status: 'error', error: 'Bridge not found' });
  if (bridge.org_id !== buildOrg(principal, bridge.org_id)) {
    return reply.code(403).send({ status: 'error', error: 'Forbidden' });
  }
  return { status: 'success', data: bridge };
});

app.post(['/bridges', '/api/v1/bridges'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const bridge = normalizeBridgePayload(request.body, principal);
  return { status: 'success', data: saveBridge(bridge) };
});

app.put(['/bridges/:bridge_id', '/api/v1/bridges/:bridge_id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const bridgeId = String((request.params as Record<string, unknown>).bridge_id);
  const existing = getBridge(bridgeId);
  if (!existing) return reply.code(404).send({ status: 'error', error: 'Bridge not found' });
  const body = request.body as any;
  const updated = saveBridge({
    ...existing,
    name: String(body?.name || existing.name),
    type: String(body?.type || existing.type),
    status: String(body?.status || existing.status),
    metadata: body?.metadata || existing.metadata || {},
    org_id: existing.org_id || buildOrg(principal),
    updated_at: now()
  });
  return { status: 'success', data: updated };
});

app.get(['/health/bridges', '/api/v1/health/bridges'], async () => {
  const bridges = listBridges();
  return {
    status: 'success',
    data: {
      bridge_count: bridges.length,
      online_bridges: bridges.filter((bridge) => bridge.status === 'online').length,
      device_count: listDevices().length,
      online_devices: listDevices().filter((device) => device.status === 'online').length,
      status: 'ok'
    }
  };
});

app.get(['/api/v1/events', '/v1/events'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const query = request.query as Record<string, unknown>;
  const org = buildOrg(principal, String(query.org_id || principal.org_id || config.orgDefault));
  const eventType = String(query.event_type || '');
  const items = listGraphEvents(1000).filter((event) => {
    if (event.org_id !== org) return false;
    if (eventType && event.event_type !== eventType) return false;
    return true;
  });
  const paged = paginate(items, query, 100);
  return { ok: true, events: paged.items, page: paged.page };
});

app.get(['/api/v1/overrides/active', '/overrides/active'], async (request) => {
  const principal = principalFromRequest(request);
  const org = buildOrg(principal, String((request.query as Record<string, unknown>).org_id || ''));
  return {
    ok: true,
    overrides: listOverrides().filter((override) => override.status === 'active' && (!org || override.org_id === org))
  };
});

app.post(['/api/v1/incident/resolved', '/incident/resolved'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = request.body as any;
  const incidentId = String(body?.incident_id || '');
  const incident = getIncident(incidentId);
  if (!incident) {
    return { ok: false, error: { code: 'NOT_FOUND', message: 'Incident not found' } };
  }
  const reverted: any[] = [];
  for (const override of listOverrides().filter((item) => item.incident_id === incidentId && item.status === 'active')) {
    override.status = 'reverted';
    override.revert_at = now();
    reverted.push(override.override_id);
  }
  updateIncident(incidentId, {
    status: 'resolved',
    incident: { ...incident.incident, status: 'resolved', resolved_by: principal.sub, resolved_at: now() }
  });
  saveGraphEvent({
    id: crypto.randomUUID(),
    org_id: incident.org_id,
    event_type: 'incident.resolved',
    entity_id: incidentId,
    payload: { incident_id: incidentId, reverted },
    created_at: now()
  });
  return { ok: true, incident_id: incidentId, reverted_overrides: reverted };
});

app.post(['/internal/route-push', '/api/v1/internal/route-push'], async (request) => {
  const principal = principalFromRequest(request);
  const body = request.body as any;
  const routeId = String(body?.route_id || '');
  const route = getRoutePlan(routeId);
  if (route) {
    route.pushed = true;
    route.pushed_at = now();
    route.updated_at = now();
    saveRoutePlan(route);
  }
  routePushLogs.push({
    route_id: routeId,
    org_id: String(body?.org_id || principal.org_id || config.orgDefault),
    officer_ids: Array.isArray(body?.officer_ids) ? body.officer_ids.map(String) : [],
    timestamp: now(),
    delivered: true,
    relationship_api_delivered: true
  });
  return {
    status: 'success',
    data: {
      route_id: routeId,
      pushed: true,
      accepted: true
    }
  };
});

app.post(['/find', '/api/v1/find', '/api/v1/proximity/find'], async (request) => {
  const principal = principalFromRequest(request);
  const body = proximityRequestSchema.parse(request.body || {});
  const org = buildOrg(principal, String(body.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  const started = Date.now();
  const upstream = await callService({ service: 'proximity', path: '/find', body: payload });
  (request as any).serviceCalls = ['proximity'];
  const response = upstream.fallback || !upstream.ok ? await buildProximityResult(payload) : upstream.data;
  const responseData = (response as any)?.data || response || {};
  const meta = (response as any)?.meta || {};
  recordProximityQueryLog({
    request_id: String((response as any)?.request_id || body.request_id || crypto.randomUUID()),
    incident_id: String((responseData as any)?.incident_id || body?.incident?.id || body.request_id || crypto.randomUUID()),
    org_id: org,
    search_radius_km: Number((responseData as any)?.search_radius_km || body?.options?.search_radius_km || 5),
    total_on_shift: Number((responseData as any)?.total_on_shift || 0),
    total_candidates_found: Number((responseData as any)?.total_candidates_found || 0),
    eta_available: Boolean(
      (responseData as any)?.recommended_officers?.some?.((officer: any) => officer.eta_seconds) ||
        (responseData as any)?.recommended_vehicles?.some?.((vehicle: any) => vehicle.eta_seconds)
    ),
    query_time_ms: Number(meta.query_time_ms || Date.now() - started),
    route_calculator_called: Boolean(meta.route_calculator_called),
    candidates_sent_to_route_calculator: Number(meta.candidates_sent_to_route_calculator || 0),
    timestamp: now()
  });
  return response;
});

app.get(['/queries', '/api/v1/queries', '/api/v1/proximity/queries'], async (request) => {
  const principal = principalFromRequest(request);
  const query = queryParamsListSchema.parse(request.query || {});
  const limit = toNumber(query.limit, 20) || 20;
  const org = buildOrg(principal, query.org_id || principal.org_id || config.orgDefault);
  const upstream = await callService({
    service: 'proximity',
    path: `/queries?limit=${encodeURIComponent(String(limit))}${org ? `&org_id=${encodeURIComponent(org)}` : ''}`,
    method: 'GET'
  });
  if (!upstream.fallback && upstream.ok) {
    return upstream.data;
  }
  return {
    status: 'success',
    service: 'proximity',
    org_id: org,
    queries: proximityQueryLogs
      .filter((entry) => !org || entry.org_id === org)
      .slice(-Math.max(1, limit))
      .reverse()
  };
});

app.get(['/proximity/health', '/api/v1/proximity/health'], async () => {
  const upstream = await callService({ service: 'proximity', path: '/health', method: 'GET' });
  if (!upstream.fallback && upstream.ok) {
    return upstream.data;
  }
  return {
    status: 'ok',
    service: 'proximity',
    environment: config.env,
    dependencies: {
      database: {
        status: hasExternalBackend('supabase') ? 'ok' : 'memory',
        backend: hasExternalBackend('supabase') ? 'postgres' : 'memory',
        database_connected: hasExternalBackend('supabase')
      },
      route_calculator: Boolean(config.services.routeCalculator.baseUrl)
    },
    timestamp: now()
  };
});

app.post(['/route/calculate', '/api/v1/route/calculate'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const body = routeUpdateSchema.parse(request.body || {});
  const org = buildOrg(principal, String(body.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  const upstream = await callService({ service: 'routeCalculator', path: '/route/calculate', body: payload });
  (request as any).serviceCalls = ['routeCalculator'];
  if (upstream.fallback || !upstream.ok) {
    const route = localRouteFromRequest(payload, body.route_id);
    return {
      request_id: String(payload.request_id || route.request_id),
      status: 'success',
      data: route,
      meta: route.meta
    };
  }
  return upstream.data;
});

app.post(['/route/push', '/api/v1/route/push'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = routePushSchema.parse(request.body || {});
  const org = buildOrg(principal, String(body.org_id || principal.org_id || config.orgDefault));
  const route = getRoutePlan(body.route_id);
  if (!route) {
    return {
      request_id: body.request_id || crypto.randomUUID(),
      status: 'failed',
      error: 'Route not found',
      data: { route_id: body.route_id }
    };
  }

  route.pushed = true;
  route.pushed_at = now();
  route.updated_at = now();
  saveRoutePlan(route);
  routePushLogs.push({
    route_id: route.route_id,
    org_id: org,
    officer_ids: body.officer_ids || route.push_route_to_officers || [],
    timestamp: now(),
    delivered: true,
    relationship_api_delivered: false
  });

  let relationshipApiDelivered = false;
  if (config.relationshipApiUrl && config.relationshipApiKey) {
    try {
      const response = await fetch(new URL('/internal/route-push', config.relationshipApiUrl), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Internal-Key': config.relationshipApiKey
        },
        body: JSON.stringify({
          route_id: route.route_id,
          org_id: org,
          officer_ids: body.officer_ids || route.push_route_to_officers || [],
          route
        })
      });
      relationshipApiDelivered = response.ok;
    } catch {
      relationshipApiDelivered = false;
    }
  }

  const last = routePushLogs[routePushLogs.length - 1];
  if (last) {
    last.relationship_api_delivered = relationshipApiDelivered;
  }

  return {
    request_id: body.request_id || route.request_id,
    status: 'success',
    data: {
      route_id: route.route_id,
      pushed: true,
      relationship_api_delivered: relationshipApiDelivered,
      route
    }
  };
});

app.get(['/route/active/:id', '/api/v1/route/active/:id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  const routeId = String((request.params as Record<string, unknown>).id);
  const route = getRoutePlan(routeId);
  if (!route) {
    return reply.code(404).send({ status: 'error', error: 'Route not found' });
  }
  if (route.org_id !== buildOrg(principal, route.org_id)) {
    return reply.code(403).send({ status: 'error', error: 'Forbidden' });
  }
  return { status: 'success', data: route };
});

app.post(['/route/update/:id', '/api/v1/route/update/:id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const routeId = String((request.params as Record<string, unknown>).id);
  const existing = getRoutePlan(routeId);
  if (!existing) {
    return reply.code(404).send({ status: 'error', error: 'Route not found' });
  }
  if (existing.org_id !== buildOrg(principal, existing.org_id)) {
    return reply.code(403).send({ status: 'error', error: 'Forbidden' });
  }
  const body = routeUpdateSchema.parse(request.body || {});
  const recalc = localRouteFromRequest({ ...body, org_id: existing.org_id, request_id: body.request_id || existing.request_id }, existing.route_id);
  const updated = saveRoutePlan({
    ...existing,
    ...recalc,
    pushed: false,
    pushed_at: undefined,
    updated_at: now()
  });
  return { status: 'success', data: updated };
});

app.get(['/infrastructure/registry', '/api/v1/infrastructure/registry'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const query = infrastructureQuerySchema.parse(request.query || {});
  const org = buildOrg(principal, String(query.org_id || principal.org_id || config.orgDefault));
  return {
    status: 'success',
    data: listInfrastructure(org)
  };
});

app.post(['/infrastructure/register', '/api/v1/infrastructure/register'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = infrastructureRegisterSchema.parse(request.body || {});
  const org = buildOrg(principal, String(body.org_id || principal.org_id || config.orgDefault));
  const record = saveInfrastructure({
    id: body.id || crypto.randomUUID(),
    org_id: org,
    name: body.name || 'Unnamed infrastructure device',
    type: body.type || 'device',
    status: body.status || 'online',
    device_type: body.device_type,
    supported_actions: body.supported_actions || [],
    metadata: body.metadata || {},
    created_at: now(),
    updated_at: now()
  });
  return { status: 'success', data: record };
});

app.get(['/route/health', '/api/v1/route/health'], async () => {
  const upstream = await callService({ service: 'routeCalculator', path: '/health', method: 'GET' });
  if (!upstream.fallback && upstream.ok) {
    return upstream.data;
  }
  return {
    status: 'ok',
    service: 'route-calculator',
    environment: config.env,
    dependencies: {
      route_service: Boolean(config.services.routeCalculator.baseUrl),
      valhalla: false,
      radar: false,
      database: {
        status: hasExternalBackend('supabase') ? 'ok' : 'memory',
        backend: hasExternalBackend('supabase') ? 'postgres' : 'memory',
        database_connected: hasExternalBackend('supabase')
      },
      relationship_api: Boolean(config.relationshipApiUrl)
    },
    timestamp: now()
  };
});

app.get(['/osint/health', '/api/v1/osint/health'], async () => {
  const upstream = await callService({ service: 'osint', path: '/health', method: 'GET' });
  return upstream.fallback ? osintLocalHealth() : upstream.data;
});

app.get(['/nlp/status', '/api/v1/nlp/status'], async () => {
  const upstream = await callService({ service: 'osint', path: '/nlp/status', method: 'GET' });
  return upstream.fallback ? osintLocalNlpStatus() : upstream.data;
});

app.get(['/brain/diagnostics', '/api/v1/brain/diagnostics'], async () => {
  const upstream = await callService({ service: 'osint', path: '/brain/diagnostics', method: 'GET' });
  return upstream.fallback ? osintLocalDiagnostics() : upstream.data;
});

app.get(['/brain/source-plan', '/api/v1/brain/source-plan'], async () => {
  const upstream = await callService({ service: 'osint', path: '/brain/source-plan', method: 'GET' });
  return upstream.fallback ? osintLocalSourcePlan() : upstream.data;
});

app.post(['/brain/query', '/api/v1/brain/query'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const body = osintBrainQuerySchema.parse(request.body || {});
  const org = buildOrg(principal, String(body.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  const upstream = await callService({ service: 'osint', path: '/brain/query', body: payload });
  (request as any).serviceCalls = ['osint'];
  return upstream.fallback ? buildOsintQueryResponse(payload) : upstream.data;
});

app.post(['/intel/packet', '/api/v1/intel/packet'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const body = osintPacketSchema.parse(request.body || {});
  const org = buildOrg(principal, String(body.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  const upstream = await callService({ service: 'osint', path: '/intel/packet', body: payload });
  (request as any).serviceCalls = ['osint'];
  return upstream.fallback ? buildOsintPacketResponse(payload) : upstream.data;
});

app.post(['/tasking/resolve', '/api/v1/tasking/resolve'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = osintTaskResolveSchema.parse(request.body || {});
  const org = buildOrg(principal, String(body.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  const upstream = await callService({ service: 'osint', path: '/tasking/resolve', body: payload });
  return upstream.fallback
    ? {
        status: 'success',
        request_id: String(body.task_id || crypto.randomUUID()),
        data: {
          task_id: body.task_id || crypto.randomUUID(),
          task_type: body.task_type || 'resolve',
          status: 'Completed',
          org_id: org,
          result: body.result || {},
          notes: body.notes || 'Resolved locally'
        }
      }
    : upstream.data;
});

app.post(['/collect', '/api/v1/collect'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = osintCollectSchema.parse(request.body || {});
  const org = buildOrg(principal, String(body.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  const upstream = await callService({ service: 'osint', path: '/collect', body: payload });
  return upstream.fallback
    ? {
        status: 'success',
        org_id: org,
        collected: true,
        sources: body.source_ids || (body.source_id ? [body.source_id] : osintSources.map((source) => source.id)),
        extra_keywords: body.extra_keywords || '',
        task_id: crypto.randomUUID()
      }
    : upstream.data;
});

app.post(['/sources/:id/collect', '/api/v1/sources/:id/collect'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const id = String((request.params as Record<string, unknown>).id);
  const body = osintCollectSchema.parse(request.body || {});
  const org = buildOrg(principal, String(body.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org, source_id: id };
  const upstream = await callService({ service: 'osint', path: `/sources/${encodeURIComponent(id)}/collect`, body: payload });
  return upstream.fallback
    ? {
        status: 'success',
        org_id: org,
        source_id: id,
        collected: true,
        extra_keywords: body.extra_keywords || ''
      }
    : upstream.data;
});

app.get(['/sources', '/api/v1/sources'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const org = buildOrg(principal, String((request.query as Record<string, unknown>).org_id || principal.org_id || config.orgDefault));
  const upstream = await callService({ service: 'osint', path: '/sources', method: 'GET' });
  return upstream.fallback
    ? {
        status: 'success',
        org_id: org,
        sources: osintSources
      }
    : upstream.data;
});

app.get(['/briefs', '/api/v1/briefs'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const query = osintBriefSchema.parse(request.query || {});
  const org = buildOrg(principal, String(query.org_id || principal.org_id || config.orgDefault));
  const days = toNumber(query.days, 7) || 7;
  const upstream = await callService({ service: 'osint', path: `/briefs?org_id=${encodeURIComponent(org)}&days=${encodeURIComponent(String(days))}`, method: 'GET' });
  return upstream.fallback
    ? {
        status: 'success',
        org_id: org,
        days,
        latest_brief: {
          generated_at: now(),
          summary: `Latest brief for ${org}`,
          recommended_action: 'monitor'
        }
      }
    : upstream.data;
});

app.post(['/briefs/generate', '/api/v1/briefs/generate'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = osintBriefSchema.parse(request.body || {});
  const org = buildOrg(principal, String(body.org_id || principal.org_id || config.orgDefault));
  const days = toNumber(body.days, 7) || 7;
  const upstream = await callService({ service: 'osint', path: '/briefs/generate', body: { ...body, org_id: org, days } });
  return upstream.fallback
    ? {
        status: 'success',
        org_id: org,
        days,
        generated_at: now(),
        brief: {
          summary: `Generated brief for ${org}`,
          recommended_action: 'monitor'
        }
      }
    : upstream.data;
});

app.post(['/alerts/dispatch', '/api/v1/alerts/dispatch'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = osintAlertDispatchSchema.parse(request.body || {});
  const org = buildOrg(principal, String(body.org_id || principal.org_id || config.orgDefault));
  const upstream = await callService({ service: 'osint', path: '/alerts/dispatch', body: { ...body, org_id: org } });
  return upstream.fallback
    ? {
        status: 'success',
        org_id: org,
        alert_id: body.alert_id || crypto.randomUUID(),
        dispatched: true
      }
    : upstream.data;
});

app.get(['/alerts/worker', '/api/v1/alerts/worker'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const upstream = await callService({ service: 'osint', path: '/alerts/worker', method: 'GET' });
  return upstream.fallback
    ? {
        status: 'success',
        worker: { ...osintAlertWorker }
      }
    : upstream.data;
});

app.post(['/alerts/worker/start', '/api/v1/alerts/worker/start'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  osintAlertWorker.running = true;
  osintAlertWorker.updated_at = now();
  const upstream = await callService({ service: 'osint', path: '/alerts/worker/start', body: { running: true } });
  return upstream.fallback ? { status: 'success', worker: { ...osintAlertWorker } } : upstream.data;
});

app.post(['/alerts/worker/stop', '/api/v1/alerts/worker/stop'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  osintAlertWorker.running = false;
  osintAlertWorker.updated_at = now();
  const upstream = await callService({ service: 'osint', path: '/alerts/worker/stop', body: { running: false } });
  return upstream.fallback ? { status: 'success', worker: { ...osintAlertWorker } } : upstream.data;
});

app.post(['/brain/tasks', '/api/v1/brain/tasks'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = osintTaskSchema.parse(request.body || {});
  const org = buildOrg(principal, String(body.org_id || principal.org_id || config.orgDefault));
  const task = upsertOsintTask({
    org_id: org,
    task_type: body.task_type,
    extra_keywords: body.extra_keywords,
    priority: body.priority ?? 5,
    source_id: body.source_id,
    source_ids: body.source_ids,
    status: body.status === 'Running' || body.status === 'Completed' || body.status === 'Failed' ? body.status : 'Pending'
  });
  const upstream = await callService({ service: 'osint', path: '/brain/tasks', body: { ...body, org_id: org, task_id: task.task_id } });
  return upstream.fallback
    ? { status: 'success', task }
    : upstream.data;
});

app.get(['/brain/tasks', '/api/v1/brain/tasks'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const org = buildOrg(principal, String((request.query as Record<string, unknown>).org_id || principal.org_id || config.orgDefault));
  const upstream = await callService({ service: 'osint', path: `/brain/tasks?org_id=${encodeURIComponent(org)}`, method: 'GET' });
  return upstream.fallback
    ? {
        status: 'success',
        tasks: [...osintTasks.values()].filter((task) => task.org_id === org)
      }
    : upstream.data;
});

app.get(['/brain/tasks/item/:task_id', '/api/v1/brain/tasks/item/:task_id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const taskId = String((request.params as Record<string, unknown>).task_id);
  const task = osintTasks.get(taskId);
  const org = buildOrg(principal, task?.org_id || principal.org_id || config.orgDefault);
  const upstream = await callService({ service: 'osint', path: `/brain/tasks/item/${encodeURIComponent(taskId)}`, method: 'GET' });
  if (!upstream.fallback) return upstream.data;
  if (!task) {
    return reply.code(404).send({ status: 'error', error: 'Task not found' });
  }
  return { status: 'success', task };
});

app.get(['/brain/tasks/worker', '/api/v1/brain/tasks/worker'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const upstream = await callService({ service: 'osint', path: '/brain/tasks/worker', method: 'GET' });
  return upstream.fallback
    ? {
        status: 'success',
        worker: { ...osintTaskWorker }
      }
    : upstream.data;
});

app.post(['/brain/tasks/worker/start', '/api/v1/brain/tasks/worker/start'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  osintTaskWorker.running = true;
  osintTaskWorker.updated_at = now();
  const upstream = await callService({ service: 'osint', path: '/brain/tasks/worker/start', body: { running: true } });
  return upstream.fallback ? { status: 'success', worker: { ...osintTaskWorker } } : upstream.data;
});

app.post(['/brain/tasks/worker/stop', '/api/v1/brain/tasks/worker/stop'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  osintTaskWorker.running = false;
  osintTaskWorker.updated_at = now();
  const upstream = await callService({ service: 'osint', path: '/brain/tasks/worker/stop', body: { running: false } });
  return upstream.fallback ? { status: 'success', worker: { ...osintTaskWorker } } : upstream.data;
});

app.get(['/api/v1/intelligence', '/intelligence'], async (request) => {
  const query = intelligenceQuerySchema.parse({
    area: String((request.query as Record<string, unknown>).area || 'unknown'),
    radius_km: toNumber((request.query as Record<string, unknown>).radius_km, 5),
    days_back: toNumber((request.query as Record<string, unknown>).days_back, 30),
    categories: (request.query as Record<string, unknown>).categories
      ? String((request.query as Record<string, unknown>).categories).split(',')
      : undefined,
    severity_min: toNumber((request.query as Record<string, unknown>).severity_min, 1),
    limit: toNumber((request.query as Record<string, unknown>).limit, 50),
    include_heatmap: toBool((request.query as Record<string, unknown>).include_heatmap, true),
    incident_context: {
      type: String((request.query as Record<string, unknown>).type || ''),
      keywords: (String((request.query as Record<string, unknown>).keywords || '') || '')
        .split(',')
        .filter(Boolean)
    }
  });
  const result = await callService({ service: 'osint', path: '/brain/query', body: { request_type: 'intelligence_query', request_id: crypto.randomUUID(), query } });
  (request as any).serviceCalls = ['osint'];
  return {
    status: 'success',
    data: result.data,
    meta: { degraded: result.fallback, service: 'osint' }
  };
});

app.get(['/api/v1/intelligence/heatmap', '/intelligence/heatmap'], async (request) => {
  const area = String((request.query as Record<string, unknown>).area || 'unknown');
  const result = await callService({ service: 'osint', path: '/brain/query', body: { request_type: 'intelligence_query', request_id: crypto.randomUUID(), query: { area, include_heatmap: true } } });
  return {
    status: 'success',
    data: (result.data as any)?.data?.heatmap || (result.data as any)?.heatmap || null,
    meta: { degraded: result.fallback }
  };
});

app.get(['/api/v1/intelligence/risk-score', '/intelligence/risk-score'], async (request) => {
  const area = String((request.query as Record<string, unknown>).area || 'unknown');
  const result = await callService({ service: 'osint', path: '/brain/query', body: { request_type: 'intelligence_query', request_id: crypto.randomUUID(), query: { area, include_heatmap: false } } });
  const data = (result.data as any)?.data || result.data || {};
  return {
    status: 'success',
    data: {
      area,
      area_risk_score: data.area_risk_score ?? 50,
      risk_trend: data.risk_trend ?? 'stable'
    },
    meta: { degraded: result.fallback }
  };
});

app.get(['/api/v1/intelligence/brief/:org', '/intelligence/brief/:org'], async (request) => {
  const params = request.params as Record<string, unknown>;
  const org = String(params.org || config.orgDefault);
  const result = await callService({ service: 'osint', path: `/briefs?org_id=${encodeURIComponent(org)}`, method: 'GET' });
  return {
    status: 'success',
    data: result.data,
    meta: { degraded: result.fallback }
  };
});

app.post(['/api/v1/incidents', '/incidents'], async (request) => {
  const principal = principalFromRequest(request);
  const body = incidentSchema.parse(request.body || {});
  const org = assertOrgAccess(principal, String(body.org_id || ''));
  const response = await orchestrateIncidentCreate(principal, body, org);
  (request as any).serviceCalls = Object.keys((response as any).meta?.service_calls || {});
  return response;
});

app.get(['/api/v1/incidents/:id', '/incidents/:id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  const id = String((request.params as Record<string, unknown>).id);
  const incident = getIncident(id);
  if (!incident) return reply.code(404).send({ status: 'error', error: 'Incident not found' });
  if (incident.org_id !== assertOrgAccess(principal, incident.org_id)) {
    return reply.code(403).send({ status: 'error', error: 'Forbidden' });
  }
  return { status: 'success', data: incident };
});

app.patch(['/api/v1/incidents/:id/status', '/incidents/:id/status'], async (request, reply) => {
  const principal = principalFromRequest(request);
  const id = String((request.params as Record<string, unknown>).id);
  const incident = getIncident(id);
  if (!incident) return reply.code(404).send({ status: 'error', error: 'Incident not found' });
  if (incident.org_id !== assertOrgAccess(principal, incident.org_id)) {
    return reply.code(403).send({ status: 'error', error: 'Forbidden' });
  }
  const body = request.body as Record<string, unknown>;
  const updated = updateIncident(id, {
    status: String(body.status || incident.status),
    incident: { ...incident.incident, status: String(body.status || incident.status), status_note: body.note }
  });
  return { status: 'success', data: updated };
});

app.post(['/api/v1/incidents/:id/analyse', '/incidents/:id/analyse'], async (request, reply) => {
  const principal = principalFromRequest(request);
  const id = String((request.params as Record<string, unknown>).id);
  const incident = getIncident(id);
  if (!incident) return reply.code(404).send({ status: 'error', error: 'Incident not found' });
  if (incident.org_id !== assertOrgAccess(principal, incident.org_id)) {
    return reply.code(403).send({ status: 'error', error: 'Forbidden' });
  }
  return runAnalysis(principal, id, incident.org_id);
});

app.post(['/api/v1/incidents/:id/dispatch', '/incidents/:id/dispatch'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireRole(principal, isElevatedRole, 'Supervisor approval required');
  const id = String((request.params as Record<string, unknown>).id);
  const incident = getIncident(id);
  if (!incident) return reply.code(404).send({ status: 'error', error: 'Incident not found' });
  if (incident.org_id !== assertOrgAccess(principal, incident.org_id)) {
    return reply.code(403).send({ status: 'error', error: 'Forbidden' });
  }
  const body = (request.body as Record<string, unknown>) || {};
  let approvedActions = Array.isArray(body.approved_actions) ? body.approved_actions : [];
  const aiApprovalId = body.ai_approval_id ? String(body.ai_approval_id) : '';
  const aiOperationId = body.ai_operation_id ? String(body.ai_operation_id) : '';
  if (!approvedActions.length && (aiApprovalId || aiOperationId)) {
    const aiApproval = aiApprovalId
      ? getAiApproval(aiApprovalId)
      : listAiApprovals(100).reverse().find((record) => record.operation_id === aiOperationId);
    const approvedPayload = aiApproval?.approved_payload;
    if (aiApproval && (aiApproval.decision === 'approved' || aiApproval.decision === 'modified')) {
      const payloadActions = approvedPayload && typeof approvedPayload === 'object'
        ? (Array.isArray((approvedPayload as Record<string, unknown>).approved_actions)
          ? (approvedPayload as Record<string, unknown>).approved_actions
          : Array.isArray((approvedPayload as Record<string, unknown>).actions)
            ? (approvedPayload as Record<string, unknown>).actions
            : [])
        : [];
      approvedActions = payloadActions;
      (request as any).aiAudit = {
        ai_endpoint: '/incidents/dispatch',
        ai_operation_id: aiApproval.operation_id,
        ai_prompt_version: config.qwenPromptVersion,
        ai_model: config.qwenModel,
        ai_confidence: undefined,
        ai_recommendation: `dispatch_from_${aiApproval.decision}`,
        ai_operator_id: aiApproval.approved_by,
        ai_fallback_used: false
      };
    }
  }
  if (!approvedActions.length) {
    return reply.code(400).send({ status: 'error', error: 'approved_actions is required' });
  }
  return executeDispatch(principal, id, incident.org_id, approvedActions);
});

app.post(['/api/v1/agent/process', '/agent/process'], async (request) => {
  const principal = principalFromRequest(request);
  const body = agentTaskSchema.parse(request.body || {});
  const org = assertOrgAccess(principal, String((request.body as Record<string, unknown>)?.org_id || principal.org_id || config.orgDefault));
  const result = await directAgentProcess(principal, { ...body, org_id: org }, org);
  (request as any).serviceCalls = ['mainAgent'];
  return result;
});

app.get(['/masterai/health', '/api/v1/masterai/health'], async () => {
  const upstream = await getServiceHealth('mainAgent');
  return {
    status: 'success',
    service: 'masterai',
    environment: config.env,
    groq: {
      configured: Boolean(config.groqApiKey),
      reachable: Boolean(config.services.mainAgent.baseUrl) && upstream.ok && !upstream.fallback,
      model: config.groqModel
    },
    relationship_api: {
      configured: Boolean(config.relationshipApiUrl && config.relationshipApiKey),
      reachable: Boolean(config.relationshipApiUrl)
    },
    database: {
      status: hasExternalBackend('supabase') ? 'success' : 'memory',
      database: hasExternalBackend('supabase') ? 'supabase' : 'memory',
      path: hasExternalBackend('supabase') ? config.supabaseUrl : null
    }
  };
});

app.get(['/ai/health', '/api/v1/ai/health'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:read');
  const upstream = await getServiceHealth('qwen');
  return {
    status: 'success',
    service: 'qwen',
    configured: Boolean(config.services.qwen.baseUrl),
    healthy: upstream.ok && !upstream.fallback,
    model: config.qwenModel,
    prompt_version: config.qwenPromptVersion,
    upstream
  };
});

app.post(['/ai/analyze-incident', '/api/v1/ai/analyze-incident'], {
  preValidation: validateAiBody(qwenAnalyzeIncidentSchema)
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:write');
  requireRole(principal, isAiGatewayRole, 'Operator or admin role required');
  const body = ((request as any).aiValidatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const result = await processQwenAnalyzeIncident(principal, { ...body, org_id: org }, org);
  (request as any).serviceCalls = ['qwen'];
  (request as any).aiAudit = {
    ...((result as any).meta || {}),
    ai_endpoint: '/ai/analyze-incident',
    ai_operation_id: (result as any).meta?.ai_operation_id,
    ai_prompt_version: (result as any).meta?.prompt_version || config.qwenPromptVersion,
    ai_model: (result as any).meta?.model || config.qwenModel,
    ai_confidence: (result as any).meta?.confidence,
    ai_recommendation: (result as any).meta?.recommendation,
    ai_operator_id: (result as any).meta?.operator_id,
    ai_fallback_used: Boolean((result as any).meta?.fallback_used)
  };
  setAiLog(request, {
    org_id: org,
    request_id: String(body.request_id || request.id),
    operator_id: String((result as any).meta?.operator_id || principal.sub),
    prompt_version: String((result as any).meta?.prompt_version || config.qwenPromptVersion),
    model_used: String((result as any).meta?.model || config.qwenModel),
    endpoint: '/ai/analyze-incident',
    input_data: body,
    output_data: result as Record<string, unknown>,
    user_decision: 'n/a'
  });
  return result;
});

app.post(['/ai/analyze-image', '/api/v1/ai/analyze-image'], {
  preValidation: validateAiBody(qwenAnalyzeImageSchema)
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:write');
  requireRole(principal, isAiGatewayRole, 'Operator or admin role required');
  const body = ((request as any).aiValidatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const result = await processQwenAnalyzeImage(principal, { ...body, org_id: org }, org);
  (request as any).serviceCalls = ['qwen'];
  (request as any).aiAudit = {
    ...((result as any).meta || {}),
    ai_endpoint: '/ai/analyze-image',
    ai_operation_id: (result as any).meta?.ai_operation_id,
    ai_prompt_version: (result as any).meta?.prompt_version || config.qwenPromptVersion,
    ai_model: (result as any).meta?.model || config.qwenModel,
    ai_confidence: (result as any).meta?.confidence,
    ai_recommendation: (result as any).meta?.recommendation,
    ai_operator_id: (result as any).meta?.operator_id,
    ai_fallback_used: Boolean((result as any).meta?.fallback_used)
  };
  setAiLog(request, {
    org_id: org,
    request_id: String(body.request_id || request.id),
    operator_id: String((result as any).meta?.operator_id || principal.sub),
    prompt_version: String((result as any).meta?.prompt_version || config.qwenPromptVersion),
    model_used: String((result as any).meta?.model || config.qwenModel),
    endpoint: '/ai/analyze-image',
    input_data: body,
    output_data: result as Record<string, unknown>,
    user_decision: 'n/a'
  });
  return result;
});

app.post(['/ai/process-radio', '/api/v1/ai/process-radio'], {
  preValidation: validateAiBody(qwenProcessRadioSchema)
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:write');
  requireRole(principal, isAiGatewayRole, 'Operator or admin role required');
  const body = ((request as any).aiValidatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const result = await processQwenRadio(principal, { ...body, org_id: org }, org);
  (request as any).serviceCalls = ['qwen'];
  (request as any).aiAudit = {
    ...((result as any).meta || {}),
    ai_endpoint: '/ai/process-radio',
    ai_operation_id: (result as any).meta?.ai_operation_id,
    ai_prompt_version: (result as any).meta?.prompt_version || config.qwenPromptVersion,
    ai_model: (result as any).meta?.model || config.qwenModel,
    ai_confidence: (result as any).meta?.confidence,
    ai_recommendation: (result as any).meta?.recommendation,
    ai_operator_id: (result as any).meta?.operator_id,
    ai_fallback_used: Boolean((result as any).meta?.fallback_used)
  };
  setAiLog(request, {
    org_id: org,
    request_id: String(body.request_id || request.id),
    operator_id: String((result as any).meta?.operator_id || principal.sub),
    prompt_version: String((result as any).meta?.prompt_version || config.qwenPromptVersion),
    model_used: String((result as any).meta?.model || config.qwenModel),
    endpoint: '/ai/process-radio',
    input_data: body,
    output_data: result as Record<string, unknown>,
    user_decision: 'n/a'
  });
  return result;
});

app.post(['/ai/recommend-response', '/api/v1/ai/recommend-response'], {
  preValidation: validateAiBody(qwenRecommendResponseSchema)
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:write');
  requireRole(principal, isAiGatewayRole, 'Operator or admin role required');
  const body = ((request as any).aiValidatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const result = await processQwenRecommendResponse(principal, { ...body, org_id: org }, org);
  (request as any).serviceCalls = ['qwen'];
  (request as any).aiAudit = {
    ...((result as any).meta || {}),
    ai_endpoint: '/ai/recommend-response',
    ai_operation_id: (result as any).meta?.ai_operation_id,
    ai_prompt_version: (result as any).meta?.prompt_version || config.qwenPromptVersion,
    ai_model: (result as any).meta?.model || config.qwenModel,
    ai_confidence: (result as any).meta?.confidence,
    ai_recommendation: (result as any).meta?.recommendation,
    ai_operator_id: (result as any).meta?.operator_id,
    ai_fallback_used: Boolean((result as any).meta?.fallback_used)
  };
  setAiLog(request, {
    org_id: org,
    request_id: String(body.request_id || request.id),
    operator_id: String((result as any).meta?.operator_id || principal.sub),
    prompt_version: String((result as any).meta?.prompt_version || config.qwenPromptVersion),
    model_used: String((result as any).meta?.model || config.qwenModel),
    endpoint: '/ai/recommend-response',
    input_data: (result as any).meta?.synthesized_request || body,
    output_data: result as Record<string, unknown>,
    user_decision: 'n/a'
  });
  return result;
});

app.post(['/ai/approve', '/api/v1/ai/approve'], {
  preValidation: validateAiBody(qwenApprovalSchema)
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:write');
  requireRole(principal, isAiGatewayRole, 'Operator or admin role required');
  const body = ((request as any).aiValidatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const result = await processQwenApproval(principal, { ...body, org_id: org }, org);
  (request as any).serviceCalls = ['qwen'];
  (request as any).aiAudit = {
    ...((result as any).meta || {}),
    ai_endpoint: '/ai/approve',
    ai_operation_id: (result as any).data?.operation_id || body.operation_id,
    ai_prompt_version: config.qwenPromptVersion,
    ai_model: config.qwenModel,
    ai_confidence: body.confidence ? toNumber(body.confidence, 0) : undefined,
    ai_recommendation: String(body.decision || 'approved'),
    ai_operator_id: String(body.approved_by || principal.sub),
    ai_fallback_used: false
  };
  setAiLog(request, {
    org_id: org,
    request_id: String(body.request_id || request.id),
    operator_id: String(body.approved_by || principal.sub),
    prompt_version: config.qwenPromptVersion,
    model_used: config.qwenModel,
    endpoint: '/ai/approve',
    input_data: body,
    output_data: result as Record<string, unknown>,
    user_decision: String(body.decision || 'approved')
  });
  return result;
});

app.get(['/ai/operations', '/api/v1/ai/operations'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:read');
  const query = request.query as Record<string, unknown>;
  const limit = Math.max(1, Math.min(200, toNumber(query.limit, 50) || 50));
  const org = buildOrg(principal, String(query.org_id || principal.org_id || config.orgDefault));
  return {
    status: 'success',
    data: listAiOperations(limit).filter((operation) => !org || operation.org_id === org)
  };
});

app.get(['/ai/approvals', '/api/v1/ai/approvals'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:read');
  const query = request.query as Record<string, unknown>;
  const limit = Math.max(1, Math.min(200, toNumber(query.limit, 50) || 50));
  const org = buildOrg(principal, String(query.org_id || principal.org_id || config.orgDefault));
  return {
    status: 'success',
    data: listAiApprovals(limit).filter((approval) => !org || approval.org_id === org)
  };
});

app.get(['/ai/approvals/:id', '/api/v1/ai/approvals/:id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:read');
  const approvalId = String((request.params as Record<string, unknown>).id);
  const approval = getAiApproval(approvalId);
  if (!approval) {
    return reply.code(404).send({ status: 'error', error: 'AI approval not found' });
  }
  if (approval.org_id !== buildOrg(principal, approval.org_id)) {
    return reply.code(403).send({ status: 'error', error: 'Forbidden' });
  }
  return { status: 'success', data: approval };
});

app.get(['/ai/logs', '/api/v1/ai/logs'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:read');
  requireRole(principal, isAiGatewayRole, 'Operator or admin role required');
  const query = request.query as Record<string, unknown>;
  const limit = Math.max(1, Math.min(250, toNumber(query.limit, 100) || 100));
  const org = buildOrg(principal, String(query.org_id || principal.org_id || config.orgDefault));
  return {
    status: 'success',
    data: listAiLogs(limit).filter((log) => matchesAiLogFilter(log as Record<string, unknown>, query, org))
  };
});

app.get(['/ai/logs/summary', '/api/v1/ai/logs/summary'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:read');
  requireRole(principal, isAiGatewayRole, 'Operator or admin role required');
  const query = request.query as Record<string, unknown>;
  const limit = Math.max(1, Math.min(500, toNumber(query.limit, 200) || 200));
  const org = buildOrg(principal, String(query.org_id || principal.org_id || config.orgDefault));
  const logs = listAiLogs(limit).filter((log) => matchesAiLogFilter(log as Record<string, unknown>, query, org));
  return {
    status: 'success',
    data: {
      org_id: org,
      sample_size: logs.length,
      summary: summarizeAiLogs(logs as Array<Record<string, unknown>>)
    }
  };
});

app.get(['/ai/logs/export', '/api/v1/ai/logs/export'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:read');
  requireRole(principal, isAiGatewayRole, 'Operator or admin role required');
  const query = request.query as Record<string, unknown>;
  const limit = Math.max(1, Math.min(1000, toNumber(query.limit, 250) || 250));
  const format = String(query.format || 'json').toLowerCase();
  const org = buildOrg(principal, String(query.org_id || principal.org_id || config.orgDefault));
  const logs = listAiLogs(limit).filter((log) => matchesAiLogFilter(log as Record<string, unknown>, query, org));
  if (format === 'csv') {
    reply.header('content-type', 'text/csv; charset=utf-8');
    reply.header('content-disposition', `attachment; filename="ai-logs-${org}-${Date.now()}.csv"`);
    return aiLogsToCsv(logs as Array<Record<string, unknown>>);
  }
  return {
    status: 'success',
    data: {
      org_id: org,
      sample_size: logs.length,
      logs
    }
  };
});

app.get(['/ai/logs/:id', '/api/v1/ai/logs/:id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:read');
  requireRole(principal, isAiGatewayRole, 'Operator or admin role required');
  const logId = String((request.params as Record<string, unknown>).id);
  const log = getAiLog(logId);
  if (!log) {
    return reply.code(404).send({ status: 'error', error: 'AI log not found' });
  }
  if (log.org_id !== buildOrg(principal, log.org_id)) {
    return reply.code(403).send({ status: 'error', error: 'Forbidden' });
  }
  return { status: 'success', data: log };
});

app.get(['/ai/operations/:id', '/api/v1/ai/operations/:id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:read');
  const operationId = String((request.params as Record<string, unknown>).id);
  const operation = getAiOperation(operationId);
  if (!operation) {
    return reply.code(404).send({ status: 'error', error: 'AI operation not found' });
  }
  if (operation.org_id !== buildOrg(principal, operation.org_id)) {
    return reply.code(403).send({ status: 'error', error: 'Forbidden' });
  }
  return { status: 'success', data: operation };
});

app.post(['/triage', '/api/v1/triage'], async (request) => {
  const principal = principalFromRequest(request);
  const body = request.body as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const result = await processMasterAiTriage(principal, { ...body, org_id: org }, org);
  (request as any).serviceCalls = ['mainAgent'];
  return result;
});

app.post(['/synthesise', '/api/v1/synthesise'], async (request) => {
  const principal = principalFromRequest(request);
  const body = request.body as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const result = await processMasterAiSynthesise(principal, { ...body, org_id: org }, org);
  (request as any).serviceCalls = ['mainAgent'];
  return result;
});

app.post(['/process', '/api/v1/process'], async (request) => {
  const principal = principalFromRequest(request);
  const body = request.body as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const result = await processMasterAiRequest(principal, { ...body, org_id: org }, org);
  (request as any).serviceCalls = ['mainAgent'];
  return result;
});

app.get(['/session/:id', '/api/v1/session/:id'], async (request, reply) => {
  const requestId = String((request.params as Record<string, unknown>).id);
  const session = await fetchMasterAiSession(requestId);
  if (!session) {
    return reply.code(404).send({ status: 'error', error: 'Session not found' });
  }
  return session;
});

app.get(['/api/v1/agent/jobs/:request_id', '/agent/jobs/:request_id'], async (request) => {
  const request_id = String((request.params as Record<string, unknown>).request_id);
  return fetchJobStatus(request_id);
});

app.post(['/api/v1/agent/approve/:request_id', '/agent/approve/:request_id'], async (request) => {
  const principal = principalFromRequest(request);
  const request_id = String((request.params as Record<string, unknown>).request_id);
  const body = approvalSchema.parse(request.body || {});
  const approval = saveApproval({
    request_id,
    org_id: buildOrg(principal, String((request.body as Record<string, unknown>)?.org_id || '')),
    incident_id: String((request.body as Record<string, unknown>)?.incident_id || ''),
    approved_by: body.approved_by,
    approval_level: body.approval_level,
    approved_at: new Date().toISOString(),
    notes: body.notes
  });
  return approveAction(request_id, approval, principal);
});

app.get(['/api/v1/inventory/officers', '/inventory/officers'], async (request) => {
  const principal = principalFromRequest(request);
  const org = assertOrgAccess(principal, String((request.query as Record<string, unknown>).org_id || principal.org_id || config.orgDefault));
  const requestId = crypto.randomUUID();
  const filters = {
    armed_only: toBool((request.query as Record<string, unknown>).armed_only, false),
    certified: (request.query as Record<string, unknown>).certified
      ? String((request.query as Record<string, unknown>).certified).split(',')
      : undefined,
    available_only: toBool((request.query as Record<string, unknown>).available_only, true)
  };
  const result = await callService({ service: 'inventory', path: '/query', body: { request_type: 'available_officers', request_id: requestId, org_id: org, filters } });
  (request as any).serviceCalls = ['inventory'];
  return { status: 'success', data: result.fallback ? inventoryLocalQuery({ request_type: 'available_officers', request_id: requestId, org_id: org, filters }).data : result.data, meta: { degraded: result.fallback } };
});

app.get(['/api/v1/inventory/vehicles', '/inventory/vehicles'], async (request) => {
  const principal = principalFromRequest(request);
  const org = assertOrgAccess(principal, String((request.query as Record<string, unknown>).org_id || principal.org_id || config.orgDefault));
  const requestId = crypto.randomUUID();
  const filters = {
    available_only: toBool((request.query as Record<string, unknown>).available_only, true),
    fuelled_only: toBool((request.query as Record<string, unknown>).fuelled_only, true),
    min_fuel_percentage: toNumber((request.query as Record<string, unknown>).min_fuel_percentage, 30),
    type: String((request.query as Record<string, unknown>).type || '')
  };
  const result = await callService({ service: 'inventory', path: '/query', body: { request_type: 'available_vehicles', request_id: requestId, org_id: org, filters } });
  return { status: 'success', data: result.fallback ? inventoryLocalQuery({ request_type: 'available_vehicles', request_id: requestId, org_id: org, filters }).data : result.data, meta: { degraded: result.fallback } };
});

app.get(['/api/v1/inventory/weapons', '/inventory/weapons'], async (request) => {
  const principal = principalFromRequest(request);
  requireRole(principal, isElevatedRole, 'Supervisor approval required');
  const org = assertOrgAccess(principal, String((request.query as Record<string, unknown>).org_id || principal.org_id || config.orgDefault));
  const requestId = crypto.randomUUID();
  const result = await callService({ service: 'inventory', path: '/query', body: { request_type: 'inventory_summary', request_id: requestId, org_id: org } });
  return { status: 'success', data: result.fallback ? inventoryLocalQuery({ request_type: 'inventory_summary', request_id: requestId, org_id: org }).data.weapons : (result.data as any)?.data?.weapons || result.data, meta: { degraded: result.fallback } };
});

app.get(['/api/v1/inventory/summary', '/inventory/summary'], async (request) => {
  const principal = principalFromRequest(request);
  const org = assertOrgAccess(principal, String((request.query as Record<string, unknown>).org_id || principal.org_id || config.orgDefault));
  const requestId = crypto.randomUUID();
  const result = await callService({ service: 'inventory', path: '/query', body: { request_type: 'inventory_summary', request_id: requestId, org_id: org } });
  return { status: 'success', data: result.fallback ? inventoryLocalQuery({ request_type: 'inventory_summary', request_id: requestId, org_id: org }).data : result.data, meta: { degraded: result.fallback } };
});

app.post(['/query', '/api/v1/query'], async (request) => {
  const principal = principalFromRequest(request);
  const body = inventoryQuerySchema.parse(request.body || {});
  const org = assertOrgAccess(principal, body.org_id);
  const result = await callService({
    service: 'inventory',
    path: '/query',
    body: { ...body, org_id: org }
  });
  return {
    request_id: body.request_id,
    status: result.ok ? 'success' : 'failed',
    data: result.fallback ? inventoryLocalQuery({ ...body, org_id: org }).data : result.data,
    meta: { degraded: result.fallback }
  };
});

app.get(['/api/v1/cameras'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const query = request.query as Record<string, unknown>;
  const org = buildOrg(principal, String(query.org_id || principal.org_id || config.orgDefault));
  const result = await callService({
    service: 'cctv',
    path: org ? `/cameras?org_id=${encodeURIComponent(org)}` : '/cameras',
    method: 'GET',
    allowFallback: true
  });
  (request as any).serviceCalls = ['cctv'];
  return {
    status: result.ok ? 'success' : 'failed',
    data: result.data,
    meta: { degraded: result.fallback }
  };
});

app.post(['/api/v1/cameras/register'], {
  preValidation: validateBodySchema(cctvCameraRegisterSchema, 'camera register')
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = ((request as any).validatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  return proxyCctvRequest(request, '/cameras/register', 'POST', payload);
});

app.post(['/api/v1/streams/start'], {
  preValidation: validateBodySchema(cctvStreamStartSchema, 'stream start')
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = ((request as any).validatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  return proxyCctvRequest(request, '/streams/start', 'POST', payload);
});

app.post(['/api/v1/streams/stop'], {
  preValidation: validateBodySchema(cctvStreamStopSchema, 'stream stop')
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = ((request as any).validatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  return proxyCctvRequest(request, '/streams/stop', 'POST', payload);
});

app.post(['/api/v1/reid/analyze'], {
  preValidation: validateBodySchema(cctvReidAnalyzeSchema, 'reid analyze')
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const body = ((request as any).validatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  return proxyCctvRequest(request, '/reid/analyze', 'POST', payload);
});

app.get(['/api/v1/targets/:id'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const query = request.query as Record<string, unknown>;
  const org = buildOrg(principal, String(query.org_id || principal.org_id || config.orgDefault));
  const targetId = String((request.params as Record<string, unknown>).id);
  const result = await callService({
    service: 'cctv',
    path: `/targets/${encodeURIComponent(targetId)}${org ? `?org_id=${encodeURIComponent(org)}` : ''}`,
    method: 'GET',
    allowFallback: true
  });
  (request as any).serviceCalls = ['cctv'];
  return {
    status: result.ok ? 'success' : 'failed',
    data: result.data,
    meta: { degraded: result.fallback }
  };
});

app.post(['/api/v1/targets/predict'], {
  preValidation: validateBodySchema(cctvTargetPredictSchema, 'target predict')
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const body = ((request as any).validatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  return proxyCctvRequest(request, '/targets/predict', 'POST', payload);
});

app.post(['/api/v1/telemetry/ingest'], {
  preValidation: validateBodySchema(cctvTelemetryIngestSchema, 'telemetry ingest')
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = ((request as any).validatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  return proxyCctvRequest(request, '/telemetry/ingest', 'POST', payload);
});

app.post(['/api/v1/frames/ingest'], {
  preValidation: validateBodySchema(cctvFramesIngestSchema, 'frames ingest')
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = ((request as any).validatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  return proxyCctvRequest(request, '/frames/ingest', 'POST', payload);
});

app.post(['/api/v1/vision/verify'], {
  preValidation: validateBodySchema(cctvVisionVerifySchema, 'vision verify')
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = ((request as any).validatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  return proxyCctvRequest(request, '/vision/verify', 'POST', payload);
});

app.post(['/api/v1/judgement/analyze'], {
  preValidation: validateBodySchema(cctvJudgementAnalyzeSchema, 'judgement analyze')
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  const body = ((request as any).validatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  return proxyCctvRequest(request, '/judgement/analyze', 'POST', payload);
});

app.post(['/api/v1/reid/correlate'], {
  preValidation: validateBodySchema(cctvReidCorrelateSchema, 'reid correlate')
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const body = ((request as any).validatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  return proxyCctvRequest(request, '/reid/correlate', 'POST', payload);
});

app.post(['/api/v1/ai/generate-summary'], {
  preValidation: validateBodySchema(aiGenerateSummarySchema, 'generate summary')
}, async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'ai:write');
  requireRole(principal, isAiGatewayRole, 'Operator or admin role required');
  const body = ((request as any).validatedBody || request.body) as Record<string, unknown>;
  const org = assertOrgAccess(principal, String(body?.org_id || principal.org_id || config.orgDefault));
  const payload = { ...body, org_id: org };
  const result = await callService({
    service: 'mainAgent',
    path: '/ai/generate-summary',
    method: 'POST',
    body: payload,
    allowFallback: true
  });
  (request as any).serviceCalls = ['mainAgent'];
  return {
    status: result.ok ? 'success' : 'failed',
    summary: result.data?.summary || result.data,
    meta: { degraded: result.fallback }
  };
});

function inventoryUpdateRoute(path: string) {
  return async (request: any) => {
    const principal = principalFromRequest(request);
    const org = buildOrg(principal, String(request.body?.org_id || principal.org_id || config.orgDefault));
    const payload = { ...(request.body || {}), org_id: org };
    const result = await callService({ service: 'inventory', path, body: payload });
    return {
      request_id: String(request.body?.request_id || crypto.randomUUID()),
      status: result.ok ? 'success' : 'failed',
      data: result.fallback ? inventoryLocalUpdate(payload).data : result.data,
      meta: { degraded: result.fallback }
    };
  };
}

app.post(['/update/officer', '/api/v1/update/officer'], inventoryUpdateRoute('/update/officer'));
app.post(['/update/vehicle', '/api/v1/update/vehicle'], inventoryUpdateRoute('/update/vehicle'));
app.post(['/update/weapon', '/api/v1/update/weapon'], inventoryUpdateRoute('/update/weapon'));
app.post(['/update/equipment', '/api/v1/update/equipment'], inventoryUpdateRoute('/update/equipment'));
app.post(['/update/fuel-reserve', '/api/v1/update/fuel-reserve'], inventoryUpdateRoute('/update/fuel-reserve'));
app.post(['/update/cadence', '/api/v1/update/cadence'], inventoryUpdateRoute('/update/cadence'));
app.post(['/update/ammunition', '/api/v1/update/ammunition'], inventoryUpdateRoute('/update/ammunition'));
app.post(['/update/threshold', '/api/v1/update/threshold'], inventoryUpdateRoute('/update/threshold'));

app.get(['/alerts/active', '/api/v1/alerts/active'], async (request) => {
  const principal = principalFromRequest(request);
  const org = buildOrg(principal, String((request.query as Record<string, unknown>).org_id || ''));
  const upstream = await callService({
    service: 'inventory',
    path: `/alerts/active${org ? `?org_id=${encodeURIComponent(org)}` : ''}`,
    method: 'GET'
  });
  return {
    status: upstream.ok ? 'success' : 'failed',
    data: upstream.fallback ? listInventoryAlerts(org) : upstream.data,
    meta: { degraded: upstream.fallback }
  };
});

app.post(['/alerts/resolve', '/api/v1/alerts/resolve'], async (request) => {
  const principal = principalFromRequest(request);
  const body = request.body as any;
  const alertId = String(body?.alert_id || '');
  const resolvedBy = String(body?.resolved_by || principal.sub);
  const notes = body?.notes ? String(body.notes) : undefined;
  const local = getInventoryAlert(alertId);
  if (local) {
    saveInventoryAlert({
      ...local,
      resolved: true,
      resolved_by: resolvedBy,
      resolved_at: now(),
      notes: notes || local.notes
    });
  }
  const result = await callService({
    service: 'inventory',
    path: '/alerts/resolve',
    body: { alert_id: alertId, resolved_by: resolvedBy, notes }
  });
  return {
    status: result.ok ? 'success' : 'failed',
    data: result.fallback ? { alert_id: alertId, resolved: true, notes } : result.data,
    meta: { degraded: result.fallback }
  };
});

app.post(['/perf/check', '/api/v1/perf/check'], async (request) => {
  const principal = principalFromRequest(request);
  const org = buildOrg(principal, String((request.body as Record<string, unknown>)?.org_id || principal.org_id || config.orgDefault));
  const payload = { ...(request.body || {}), org_id: org };
  const result = await callService({ service: 'inventory', path: '/perf/check', body: payload });
  return {
    status: result.ok ? 'success' : 'failed',
    data: result.fallback ? {
      org_id: org,
      results: (Array.isArray(payload.request_types) ? payload.request_types : ['inventory_summary']).map((request_type: string) => ({
        request_type,
        min_ms: 0,
        avg_ms: 0,
        max_ms: 0,
        within_soft_target: true
      })),
      overall_avg_ms: 0,
      within_soft_target: true,
      include_llm: Boolean(payload.include_llm)
    } : result.data,
    meta: { degraded: result.fallback }
  };
});

app.get(['/api/v1/inventory/alerts', '/inventory/alerts'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const org = buildOrg(principal, String((request.query as Record<string, unknown>).org_id || ''));
  return {
    status: 'success',
    data: listInventoryAlerts(org)
  };
});

app.post(['/api/v1/autonomous/action', '/autonomous/action'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  return executeAutonomousAction(principalFromRequest(request), request.body);
});

app.post(['/execute', '/api/v1/execute'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  return executeAutonomousAction(principal, request.body);
});

app.get(['/api/v1/autonomous/status/:id', '/autonomous/status/:id'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const id = String((request.params as Record<string, unknown>).id);
  return {
    status: 'success',
    data: {
      override_id: id,
      local_record: listOverrides().find((entry) => entry.override_id === id) || null
    }
  };
});

app.post(['/api/v1/autonomous/revert/:id', '/autonomous/revert/:id'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  return revertAutonomousOverride(principal, String((request.params as Record<string, unknown>).id));
});

app.post(['/revert/:id'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:write');
  return revertAutonomousOverride(principal, String((request.params as Record<string, unknown>).id));
});

app.get(['/api/v1/autonomous/active', '/autonomous/active'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const org = buildOrg(principal, String((request.query as Record<string, unknown>).org_id || ''));
  return {
    status: 'success',
    data: listOverrides().filter((entry) => entry.status === 'active' && (!org || entry.org_id === org))
  };
});

app.get(['/api/v1/audit-log', '/audit-log'], async (request, reply) => {
  const principal = principalFromRequest(request);
  requireRole(principal, isAdminRole, 'Admin access required');
  const query = queryParamsListSchema.parse(request.query || {});
  const limit = toNumber(query.limit, 100) || 100;
  return {
    status: 'success',
    data: queryAudit(limit)
  };
});

app.get(['/log', '/api/v1/log'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  const org = buildOrg(principal, String((request.query as Record<string, unknown>).org_id || ''));
  return {
    status: 'success',
    data: {
      action_logs: listAutonomousLogs(200).filter((entry) => !org || entry.org_id === org),
      graph_events: listGraphEvents(200).filter((entry) => !org || entry.org_id === org)
    }
  };
});

app.get(['/api/v1/system/registry', '/system/registry'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  return {
    status: 'success',
    data: {
      relationship_api: {
        url: config.relationshipApiUrl || null,
        key_configured: Boolean(config.relationshipApiKey)
      },
      services: {
        osint: config.services.osint.baseUrl,
        aiAnalysis: config.services.aiAnalysis.baseUrl,
        mainAgent: config.services.mainAgent.baseUrl,
        autonomous: config.services.autonomous.baseUrl,
        inventory: config.services.inventory.baseUrl,
        proximity: config.services.proximity.baseUrl,
        routeCalculator: config.services.routeCalculator.baseUrl
      },
      backends: {
        database: Boolean(config.databaseUrl),
        supabase: hasExternalBackend('supabase'),
        redis: hasExternalBackend('redis'),
        blob: hasExternalBackend('blob'),
        resend: hasExternalBackend('resend')
      }
    }
  };
});

app.get(['/api/v1/system/overview', '/system/overview'], async (request) => {
  const principal = principalFromRequest(request);
  requireScope(principal, 'relationships:read');
  return {
    status: 'success',
    data: {
      incidents: listIncidents().length,
      overrides: listOverrides().length,
      approvals: [],
      entities: listEntities().length,
      relationships: listRelationships().length,
      events: listGraphEvents(1000).length,
      storage: {
        database: Boolean(config.databaseUrl),
        supabase: hasExternalBackend('supabase'),
        redis: hasExternalBackend('redis'),
        blob: hasExternalBackend('blob'),
        resend: hasExternalBackend('resend')
      }
    }
  };
});

app.get('/', async () => ({ status: 'success', service: 'relationship-api' }));
