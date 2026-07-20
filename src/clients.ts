import { config } from './config';
import { ServiceName } from './types';

type HttpMethod = 'GET' | 'POST' | 'PATCH';

export type ServiceCallResult<T = unknown> = {
  ok: boolean;
  status: number;
  data?: T;
  error?: string;
  duration_ms: number;
  fallback: boolean;
  service: ServiceName;
};

type CallOptions = {
  service: ServiceName;
  path: string;
  method?: HttpMethod;
  body?: unknown;
  headers?: Record<string, string>;
  timeoutMs?: number;
  allowFallback?: boolean;
  retries?: number;
};

function serviceConfig(service: ServiceName) {
  return config.services[service];
}

function buildHeaders(service: ServiceName, headers?: Record<string, string>): Record<string, string> {
  const serviceHeaders = serviceConfig(service).defaultHeaders || {};
  return {
    'Content-Type': 'application/json',
    ...serviceHeaders,
    ...(headers || {})
  };
}

function emptyFallback(service: ServiceName): any {
  const now = new Date().toISOString();
  switch (service) {
    case 'osint':
      return {
        request_id: `fallback-${Date.now()}`,
        status: 'success',
        data: {
          intelligence_items: [],
          heatmap: {
            area: 'unknown',
            incident_density: 0,
            hotspots: [],
            historical_pattern: {}
          },
          area_risk_score: 50,
          risk_trend: 'stable'
        },
        meta: { total_items: 0, query_time_ms: 0, degraded: true, timestamp: now }
      };
    case 'inventory':
      return {
        request_id: `fallback-${Date.now()}`,
        status: 'success',
        data: {
          officers: { total: 0, available: 0, armed_available: 0, below_threshold: false },
          vehicles: { total: 0, available: 0, below_threshold: false },
          weapons: { pistols_available: 0, rifles_available: 0, tasers_available: 0, below_threshold: false },
          ammunition: { pistol_rounds: 0, rifle_rounds: 0, below_threshold: false },
          tactical: { body_armour_available: 0, radios_available: 0, first_aid_kits: 0, below_threshold: false },
          fuel_reserve: { litres: 0, percentage: 0, below_threshold: true, threshold_alert_level: 'WARNING' },
          cadence: { officers: {}, vehicles: {} },
          active_alerts: 0,
          last_updated: now,
          llm_review: { approved: true, issues: [], risk_level: 'medium', missing_fields: [], recommended_actions: [] }
        },
        meta: { elapsed_ms: 0, soft_target_ms: 500, within_soft_target: true, degraded: true }
      };
    case 'proximity':
      return {
        request_id: `fallback-${Date.now()}`,
        status: 'success',
        data: {
          incident_id: 'unknown',
          search_radius_km: 5,
          total_on_shift: 0,
          total_candidates_found: 0,
          recommended_officers: [],
          recommended_vehicles: [],
          excluded_officers: [],
          summary: {
            fastest_responder: null,
            fastest_eta_seconds: null,
            officers_available_in_area: 0,
            officers_recommended: 0,
            all_requirements_met: false,
            warnings: ['proximity service unavailable']
          }
        },
        meta: { query_time_ms: 0, route_calculator_called: false, candidates_sent_to_route_calculator: 0, degraded: true }
      };
    case 'routeCalculator':
      return {
        request_id: `fallback-${Date.now()}`,
        status: 'success',
        data: {
          recommended_routing_type: 'vehicle',
          reasoning: 'route calculator unavailable',
          routes: [],
          infrastructure_recommendations: [],
          push_route_to_officers: [],
          mapbox_route_geojson: {},
          meta: { total_ms: 0, degraded: true }
        }
      };
    case 'cctv':
      return {
        request_id: `fallback-${Date.now()}`,
        status: 'success',
        data: {
          cameras: [],
          camera_count: 0,
          streams: [],
          targets: [],
          reid_results: [],
          prediction: {
            target_id: null,
            confidence: 0,
            labels: [],
            summary: 'CCTV perception service unavailable'
          }
        },
        meta: { degraded: true, fallback_reason: 'cctv unavailable' }
      };
    case 'aiAnalysis':
      return {
        request_id: `fallback-${Date.now()}`,
        status: 'success',
        analysis: {
          threat_assessment: {
            threat_level: 'medium',
            confidence: 60,
            reasoning: 'AI analysis service unavailable',
            armed: false,
            estimated_suspects: 0,
            escape_likelihood: 'unknown',
            similar_past_incidents: 0
          },
          response_recommendation: {
            officers_needed: 0,
            armed_required: false,
            vehicles_needed: 0,
            response_urgency: 'normal',
            estimated_response_time_minutes: 30,
            special_instructions: 'Manual review required'
          },
          resource_requirements: {
            officers: { count: 0, armed: false, recommended_ids: [] },
            vehicles: { count: 0, type: 'patrol_car', recommended_ids: [] },
            weapons: { type: 'standard_firearms', heavy_required: false },
            fuel_check_required: false
          },
          autonomous_actions_recommended: []
        }
      };
    case 'qwen':
      return {
        request_id: `fallback-${Date.now()}`,
        status: 'success',
        data: {
          incident_id: 'unknown',
          prompt_version: 'v1',
          model: config.qwenModel,
          confidence: 62,
          recommendation: 'Use local heuristic guidance until Qwen is available.',
          reasoning: 'Qwen service unavailable',
          risk_level: 'medium',
          actions: ['Review incident manually', 'Notify supervisor if required']
        },
        meta: { degraded: true, fallback_reason: 'qwen unavailable' }
      };
    case 'mainAgent':
      return {
        request_id: `fallback-${Date.now()}`,
        status: 'success',
        agent_output: {
          jobs_executed: [],
          dispatch_plan: {
            incident_id: 'unknown',
            officers_dispatched: [],
            vehicles_assigned: [],
            route: {},
            eta_minutes: 0,
            autonomous_actions_pending_approval: []
          },
          summary_for_commander: 'Agent service unavailable',
          confidence: 50,
          requires_human_approval: true,
          approval_items: []
        }
      };
    case 'autonomous':
      return {
        request_id: `fallback-${Date.now()}`,
        status: 'executed',
        action_result: {
          target_id: 'unknown',
          command_sent: true,
          confirmed: true,
          executed_at: now,
          revert_scheduled_at: now,
          confirmation_source: 'local_fallback'
        }
      };
    default:
      return {};
  }
}

export async function callService<T = unknown>({
  service,
  path,
  method = 'POST',
  body,
  headers,
  timeoutMs = 8000,
  allowFallback = true,
  retries
}: CallOptions): Promise<ServiceCallResult<T>> {
  const svc = serviceConfig(service);
  const started = Date.now();
  if (!svc.baseUrl) {
    if (!allowFallback) {
      return {
        ok: false,
        status: 503,
        error: `Service ${service} is not configured`,
        duration_ms: Date.now() - started,
        fallback: false,
        service
      };
    }
    return {
      ok: true,
      status: 200,
      data: emptyFallback(service) as T,
      duration_ms: Date.now() - started,
      fallback: true,
      service
    };
  }

  const retryCount = Math.max(
    0,
    Number.isFinite(retries)
      ? Number(retries)
      : Number.isFinite(config.relationshipApiRetryCount)
        ? config.relationshipApiRetryCount
        : 2
  );
  let lastError: unknown;

  for (let attempt = 0; attempt <= retryCount; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs || config.relationshipApiTimeoutMs || 8000);
    try {
      const response = await fetch(new URL(path, svc.baseUrl), {
        method,
        headers: buildHeaders(service, headers),
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal
      });
      const text = await response.text();
      let data: unknown = text;
      try {
        data = text ? JSON.parse(text) : {};
      } catch {
        data = text;
      }
      return {
        ok: response.ok,
        status: response.status,
        data: data as T,
        error: response.ok ? undefined : typeof data === 'string' ? data : 'Upstream request failed',
        duration_ms: Date.now() - started,
        fallback: false,
        service
      };
    } catch (error) {
      lastError = error;
      clearTimeout(timeout);
      if (attempt < retryCount) continue;
      if (!allowFallback) {
        return {
          ok: false,
          status: 503,
          error: error instanceof Error ? error.message : 'Request failed',
          duration_ms: Date.now() - started,
          fallback: false,
          service
        };
      }
      return {
        ok: true,
        status: 200,
        data: emptyFallback(service) as T,
        error: error instanceof Error ? error.message : 'Request failed',
        duration_ms: Date.now() - started,
        fallback: true,
        service
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  if (!allowFallback) {
    return {
      ok: false,
      status: 503,
      error: lastError instanceof Error ? lastError.message : 'Request failed',
      duration_ms: Date.now() - started,
      fallback: false,
      service
    };
  }

  return {
    ok: true,
    status: 200,
    data: emptyFallback(service) as T,
    error: lastError instanceof Error ? lastError.message : 'Request failed',
    duration_ms: Date.now() - started,
    fallback: true,
    service
  };
}

export async function getServiceHealth(service: ServiceName): Promise<ServiceCallResult> {
  return callService({ service, path: serviceConfig(service).healthPath, method: 'GET', allowFallback: false });
}
