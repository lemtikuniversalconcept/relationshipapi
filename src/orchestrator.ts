// @ts-nocheck
import { callService } from './clients';
import { config } from './config';
import { IncidentRecord, RequestPrincipal } from './types';
import {
  autonomousActionSchema,
  incidentSchema,
  internalAutonomousExecuteSchema,
  masterAiProcessSchema,
  masterAiSynthesiseSchema,
  masterAiTriageSchema,
  qwenApprovalSchema,
  qwenAnalyzeIncidentResponseSchema,
  qwenAnalyzeIncidentSchema,
  qwenAnalyzeImageResponseSchema,
  qwenAnalyzeImageSchema,
  qwenProcessRadioResponseSchema,
  qwenProcessRadioSchema,
  qwenRecommendResponseResponseSchema,
  qwenRecommendResponseSchema
} from './schemas';
import { saveAiApproval, saveAiOperation, saveSession, saveIncident, updateIncident, saveOverride, getAiOperation } from './store';

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

function normalizeAiOperatorId(principal: RequestPrincipal, payload: Record<string, unknown>): string {
  const context = (payload.context as Record<string, unknown>) || {};
  return String(context.operator_id || principal.actor_id || principal.sub || principal.role || 'unknown');
}

function buildAiAudit(operation: {
  operation_id: string;
  endpoint: string;
  prompt_version: string;
  model: string;
  confidence?: number;
  recommendation?: string;
  operator_id?: string;
  fallback_used: boolean;
}): Record<string, unknown> {
  return {
    ai_endpoint: operation.endpoint,
    ai_operation_id: operation.operation_id,
    ai_prompt_version: operation.prompt_version,
    ai_model: operation.model,
    ai_confidence: operation.confidence,
    ai_recommendation: operation.recommendation,
    ai_operator_id: operation.operator_id,
    ai_fallback_used: operation.fallback_used
  };
}

function normalizeAiText(value: unknown): string {
  return String(value || '').trim();
}

function extractAiRecommendation(data: Record<string, unknown>): string {
  return normalizeAiText(
    data.recommendation ||
      data.summary ||
      data.reasoning ||
      data.risk_level ||
      'Local heuristic recommendation'
  );
}

function extractAiConfidence(data: Record<string, unknown>): number {
  const raw = Number(data.confidence);
  if (Number.isFinite(raw)) return Math.max(0, Math.min(100, raw));
  return 60;
}

function localQwenAnalyzeIncident(payload: Record<string, unknown>, principal: RequestPrincipal): Record<string, unknown> {
  const incident = (payload.incident as Record<string, unknown>) || {};
  const description = String(incident.description || '');
  const severity = Number(incident.severity || 3);
  const confidence = Math.max(58, Math.min(95, 70 + (severity >= 4 ? 10 : 0) + (description ? 6 : -10)));
  const recommendation = severity >= 4
    ? 'Escalate to immediate response and notify a supervisor.'
    : 'Review incident context and continue with standard response.';
  return {
    request_id: String(payload.request_id || randomId('req')),
    status: 'success',
    data: {
      incident_id: String(incident.id || 'unknown'),
      prompt_version: String((payload.context as Record<string, unknown>)?.prompt_version || config.qwenPromptVersion),
      model: String((payload.context as Record<string, unknown>)?.model || config.qwenModel),
      confidence,
      recommendation,
      reasoning: 'Generated locally because Qwen was unavailable or returned an invalid contract.',
      operator_id: normalizeAiOperatorId(principal, payload),
      analysis: {
        threat_level: severity >= 4 ? 'high' : severity >= 2 ? 'medium' : 'low',
        incident_type: String(incident.type || 'unknown'),
        escalation_required: severity >= 4,
        armed_threat: /(armed|weapon|gun|knife|stab|shoot)/i.test(description)
      },
      risk_level: severity >= 4 ? 'high' : severity >= 2 ? 'medium' : 'low',
      suggested_actions: severity >= 4
        ? ['Dispatch responders immediately', 'Notify supervisor', 'Prepare autonomous controls if approved']
        : ['Monitor incident', 'Verify context', 'Continue standard workflow']
    },
    meta: {
      degraded: true,
      fallback_reason: 'qwen offline'
    }
  };
}

function localQwenAnalyzeImage(payload: Record<string, unknown>, principal: RequestPrincipal): Record<string, unknown> {
  const image = (payload.image as Record<string, unknown>) || {};
  const caption = normalizeAiText(image.caption);
  const mimeType = String(image.mime_type || '');
  const threaty = /(weapon|gun|knife|blood|fire|smoke|crowd|suspicious|vehicle)/i.test(`${caption} ${String(image.filename || '')}`);
  const confidence = Math.max(56, Math.min(96, 66 + (caption ? 10 : -8) + (threaty ? 12 : 0) + (mimeType.startsWith('image/') ? 4 : -4)));
  return {
    request_id: String(payload.request_id || randomId('req')),
    status: 'success',
    data: {
      image_id: String(image.filename || image.url || randomId('img')),
      prompt_version: String((payload.context as Record<string, unknown>)?.prompt_version || config.qwenPromptVersion),
      model: String((payload.context as Record<string, unknown>)?.model || config.qwenModel),
      confidence,
      recommendation: threaty
        ? 'Review the image immediately and escalate if a threat is visible.'
        : 'Image appears routine; verify context and continue monitoring.',
      findings: threaty ? ['Potential threat indicators detected', 'Manual review recommended'] : ['No obvious threat indicators detected'],
      labels: threaty ? ['threat', 'needs_review'] : ['routine'],
      summary: caption || 'Fallback image analysis generated locally.',
      operator_id: normalizeAiOperatorId(principal, payload),
      risk_level: confidence >= 80 ? 'high' : confidence >= 65 ? 'medium' : 'low'
    },
    meta: {
      degraded: true,
      fallback_reason: 'qwen offline'
    }
  };
}

function localQwenProcessRadio(payload: Record<string, unknown>, principal: RequestPrincipal): Record<string, unknown> {
  const radio = (payload.radio as Record<string, unknown>) || {};
  const transcript = normalizeAiText(radio.transcript || radio.message);
  const lower = transcript.toLowerCase();
  const urgent = /(help|shots|gun|weapon|stab|urgent|emergency|attack|assault)/.test(lower);
  const recommendation = urgent
    ? 'Treat this transmission as urgent and escalate to dispatch.'
    : 'Log the transmission and continue monitoring.';
  const confidence = Math.max(55, Math.min(94, 68 + (transcript ? 8 : -15) + (urgent ? 10 : 0)));
  return {
    request_id: String(payload.request_id || randomId('req')),
    status: 'success',
    data: {
      transcript,
      prompt_version: String((payload.context as Record<string, unknown>)?.prompt_version || config.qwenPromptVersion),
      model: String((payload.context as Record<string, unknown>)?.model || config.qwenModel),
      confidence,
      recommendation,
      classification: {
        urgency: urgent ? 'immediate' : 'standard',
        channel_id: String(radio.channel_id || 'unknown'),
        source: String(radio.source || 'radio'),
        contains_distress: urgent,
        likely_incident_type: urgent ? 'incident_alert' : 'routine_update'
      },
      summary: transcript
        ? `Processed radio transmission from ${String(radio.source || 'unknown')}.`
        : 'No transcript provided; used local fallback classification.',
      operator_id: normalizeAiOperatorId(principal, payload),
      action_items: urgent
        ? ['Alert dispatcher', 'Escalate to supervisor', 'Track incident context']
        : ['Archive transmission', 'Monitor for follow-up']
    },
    meta: {
      degraded: true,
      fallback_reason: 'qwen offline'
    }
  };
}

function localQwenRecommendResponse(payload: Record<string, unknown>, principal: RequestPrincipal): Record<string, unknown> {
  const incident = (payload.incident as Record<string, unknown>) || {};
  const analysis = (payload.analysis as Record<string, unknown>) || {};
  const severity = Number(incident.severity || analysis?.threat_assessment?.severity || 3);
  const recommendation = severity >= 4
    ? 'Approve immediate response, prioritize safety, and keep approval chain active.'
    : 'Proceed with monitored response and confirm conditions before escalation.';
  const confidence = Math.max(60, Math.min(96, 75 + (severity >= 4 ? 12 : 0)));
  return {
    request_id: String(payload.request_id || randomId('req')),
    status: 'success',
    data: {
      incident_id: String(incident.id || 'unknown'),
      prompt_version: String((payload.context as Record<string, unknown>)?.prompt_version || config.qwenPromptVersion),
      model: String((payload.context as Record<string, unknown>)?.model || config.qwenModel),
      confidence,
      recommendation,
      response_plan: {
        priority: severity >= 4 ? 'immediate' : 'standard',
        officers_needed: severity >= 4 ? 4 : 2,
        vehicles_needed: severity >= 4 ? 1 : 0,
        approval_required: severity >= 4,
        suggested_channel: severity >= 4 ? 'command' : 'operations'
      },
      operator_id: normalizeAiOperatorId(principal, payload),
      actions: severity >= 4
        ? ['Notify supervisor', 'Dispatch responders', 'Prepare autonomous controls']
        : ['Monitor incident', 'Maintain situational awareness'],
      risk_level: severity >= 4 ? 'high' : severity >= 2 ? 'medium' : 'low'
    },
    meta: {
      degraded: true,
      fallback_reason: 'qwen offline'
    }
  };
}

async function buildAiRecommendationContext(principal: RequestPrincipal, payload: Record<string, unknown>, orgId: string): Promise<Record<string, unknown>> {
  const incident = (payload.incident as Record<string, unknown>) || {};
  const analysis = (payload.analysis as Record<string, unknown>) || {};
  const context = (payload.context as Record<string, unknown>) || {};
  const requestId = String(payload.request_id || randomId('req'));

  const inventoryCall = await callService({
    service: 'inventory',
    path: '/query',
    body: {
      request_type: 'inventory_summary',
      request_id: randomId('req'),
      org_id: orgId
    }
  });

  const proximityPayload = buildProximityPayload(orgId, incident);
  const proximityCall = await callService({
    service: 'proximity',
    path: '/find',
    body: proximityPayload
  });

  const proximityData = (proximityCall.data as Record<string, unknown>)?.data || proximityCall.data || {};
  const recommendedOfficers = Array.isArray((proximityData as Record<string, unknown>)?.recommended_officers)
    ? (proximityData as Record<string, unknown>).recommended_officers as unknown[]
    : [];
  const recommendedVehicles = Array.isArray((proximityData as Record<string, unknown>)?.recommended_vehicles)
    ? (proximityData as Record<string, unknown>).recommended_vehicles as unknown[]
    : [];

  const routeCall = await callService({
    service: 'routeCalculator',
    path: '/route/calculate',
    body: buildRoutePayload(
      orgId,
      incident,
      {
        officers: recommendedOfficers.map((entry) => String((entry as Record<string, unknown>).officer_id || (entry as Record<string, unknown>).id || 'unknown')).filter(Boolean),
        vehicles: recommendedVehicles.map((entry) => String((entry as Record<string, unknown>).vehicle_id || (entry as Record<string, unknown>).id || 'unknown')).filter(Boolean)
      }
    )
  });

  return {
    request_type: 'ai_recommend_response',
    request_id: requestId,
    org_id: orgId,
    incident,
    analysis,
    context: {
      ...context,
      operator_id: String(context.operator_id || principal.actor_id || principal.sub || principal.role || 'unknown'),
      prompt_version: String(context.prompt_version || config.qwenPromptVersion),
      model: String(context.model || config.qwenModel),
      inventory: (inventoryCall.data as Record<string, unknown>) || inventoryCall,
      proximity: proximityData,
      route_calculator: (routeCall.data as Record<string, unknown>) || routeCall,
      osint_data: context.osint_data || {}
    }
  };
}

async function runQwenContractedOperation<TRequest extends Record<string, unknown>, TResponse extends Record<string, unknown>>(
  principal: RequestPrincipal,
  endpoint: string,
  operationType: string,
  payload: TRequest,
  requestSchema: { safeParse: (value: unknown) => { success: boolean; data?: TRequest; error?: unknown } },
  responseSchema: { safeParse: (value: unknown) => { success: boolean; data?: TResponse; error?: unknown } },
  fallbackBuilder: (payload: TRequest, principal: RequestPrincipal) => TResponse
): Promise<Record<string, unknown>> {
  const parsedRequest = requestSchema.safeParse(payload);
  if (!parsedRequest.success) {
    return {
      request_id: String((payload as Record<string, unknown>).request_id || randomId('req')),
      status: 'failed',
      error: 'Invalid AI request payload',
      data: { validation_error: true }
    };
  }

  const request = parsedRequest.data;
  const requestId = String(request.request_id || randomId('req'));
  const orgId = String(request.org_id || principal.org_id || config.orgDefault);
  const operationId = randomId('aio');
  const promptVersion = String((request.context as Record<string, unknown>)?.prompt_version || config.qwenPromptVersion);
  const model = String((request.context as Record<string, unknown>)?.model || config.qwenModel);
  const operatorId = normalizeAiOperatorId(principal, request);
  const started = Date.now();
  const timeoutMs = config.qwenTimeoutMs || 8000;
  const retries = Math.max(0, Number.isFinite(config.qwenRetryCount) ? config.qwenRetryCount : 3);

  const upstream = await callService({
    service: 'qwen',
    path: endpoint,
    body: request,
    timeoutMs,
    retries,
    allowFallback: true
  });

  let output: TResponse;
  let fallbackUsed = upstream.fallback || !upstream.ok;
  let errorText: string | undefined = upstream.error;

  if (!fallbackUsed) {
    const validated = responseSchema.safeParse(upstream.data);
    if (validated.success && validated.data) {
      output = validated.data;
    } else {
      fallbackUsed = true;
      errorText = 'Qwen response contract validation failed';
      output = fallbackBuilder(request, principal);
    }
  } else {
    output = fallbackBuilder(request, principal);
  }

  const confidence = extractAiConfidence((output as Record<string, unknown>).data || {});
  const recommendation = extractAiRecommendation((output as Record<string, unknown>).data || {});
  const durationMs = Date.now() - started;

  saveAiOperation({
    operation_id: operationId,
    request_id: requestId,
    org_id: orgId,
    endpoint,
    operation_type: operationType,
    prompt_version: promptVersion,
    model,
    operator_id: operatorId,
    confidence,
    recommendation,
    status: fallbackUsed ? 'fallback' : 'success',
    fallback_used: fallbackUsed,
    retries,
    request_payload: request,
    response_payload: output,
    error: errorText,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    duration_ms: durationMs
  });

  saveSession(requestId, {
    endpoint,
    operation_type: operationType,
    prompt_version: promptVersion,
    model,
    operator_id: operatorId,
    confidence,
    recommendation,
    fallback_used: fallbackUsed,
    request,
    response: output
  });

  return {
    ...output,
    meta: {
      ...((output as Record<string, unknown>).meta || {}),
      ai_operation_id: operationId,
      prompt_version: promptVersion,
      model,
      confidence,
      recommendation,
      operator_id: operatorId,
      fallback_used: fallbackUsed,
      retries,
      duration_ms: durationMs,
      error: errorText,
      synthesized_request: operationType === 'recommend_response' ? request : undefined
    }
  };
}

export async function processQwenAnalyzeIncident(principal: RequestPrincipal, payload: unknown, orgId: string): Promise<Record<string, unknown>> {
  const parsed = qwenAnalyzeIncidentSchema.parse(payload || {});
  return runQwenContractedOperation(
    principal,
    '/ai/analyze-incident',
    'analyze_incident',
    { ...parsed, org_id: orgId },
    qwenAnalyzeIncidentSchema,
    qwenAnalyzeIncidentResponseSchema,
    (request, currentPrincipal) => localQwenAnalyzeIncident(request, currentPrincipal) as any
  );
}

export async function processQwenAnalyzeImage(principal: RequestPrincipal, payload: unknown, orgId: string): Promise<Record<string, unknown>> {
  const parsed = qwenAnalyzeImageSchema.parse(payload || {});
  return runQwenContractedOperation(
    principal,
    '/ai/analyze-image',
    'analyze_image',
    { ...parsed, org_id: orgId },
    qwenAnalyzeImageSchema,
    qwenAnalyzeImageResponseSchema,
    (request, currentPrincipal) => localQwenAnalyzeImage(request, currentPrincipal) as any
  );
}

export async function processQwenRadio(principal: RequestPrincipal, payload: unknown, orgId: string): Promise<Record<string, unknown>> {
  const parsed = qwenProcessRadioSchema.parse(payload || {});
  return runQwenContractedOperation(
    principal,
    '/ai/process-radio',
    'process_radio',
    { ...parsed, org_id: orgId },
    qwenProcessRadioSchema,
    qwenProcessRadioResponseSchema,
    (request, currentPrincipal) => localQwenProcessRadio(request, currentPrincipal) as any
  );
}

export async function processQwenRecommendResponse(principal: RequestPrincipal, payload: unknown, orgId: string): Promise<Record<string, unknown>> {
  const parsed = qwenRecommendResponseSchema.parse(payload || {});
  const synthesized = await buildAiRecommendationContext(principal, parsed, orgId);
  return runQwenContractedOperation(
    principal,
    '/ai/recommend-response',
    'recommend_response',
    { ...synthesized, org_id: orgId },
    qwenRecommendResponseSchema,
    qwenRecommendResponseResponseSchema,
    (request, currentPrincipal) => localQwenRecommendResponse(request, currentPrincipal) as any
  );
}

export async function processQwenApproval(principal: RequestPrincipal, payload: unknown, orgId: string): Promise<Record<string, unknown>> {
  const parsed = qwenApprovalSchema.parse(payload || {});
  const approvedBy = parsed.approved_by || principal.sub;
  const approvalLevel = parsed.approval_level || principal.role;
  const approvedAt = new Date().toISOString();
  const approvalId = randomId('aiappr');
  const operation = getAiOperation(parsed.operation_id);
  const record = saveAiApproval({
    approval_id: approvalId,
    request_id: parsed.request_id,
    org_id: orgId,
    operation_id: parsed.operation_id,
    approved_by: approvedBy,
    approval_level: approvalLevel,
    decision: parsed.decision,
    notes: parsed.notes,
    approved_payload: parsed.approved_payload,
    created_at: approvedAt,
    updated_at: approvedAt
  });
  saveSession(parsed.request_id, {
    approval_id: approvalId,
    operation_id: parsed.operation_id,
    decision: parsed.decision,
    approved_by: approvedBy,
    approval_level: approvalLevel,
    approved_at: approvedAt,
    operation: operation || null,
    approved_payload: parsed.approved_payload || null
  });
  return {
    request_id: parsed.request_id,
    status: 'success',
    data: {
      approval_id: record.approval_id,
      operation_id: record.operation_id,
      request_id: record.request_id,
      org_id: record.org_id,
      decision: record.decision,
      approved_by: record.approved_by,
      approval_level: record.approval_level,
      approved_at: record.created_at,
      notes: record.notes,
      approved_payload: record.approved_payload
    },
    meta: {
      operation_found: Boolean(operation)
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
