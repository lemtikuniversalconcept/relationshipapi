import { z } from 'zod';

const stringOrNumber = z.union([z.string(), z.number()]);

export const locationSchema = z.object({
  name: z.string().optional(),
  lat: z.number().optional(),
  lng: z.number().optional(),
  address: z.string().optional(),
  description: z.string().optional(),
  building_id: z.string().optional(),
  floor: z.number().optional(),
  indoor: z.boolean().optional()
});

export const incidentSchema = z.object({
  id: z.string().optional(),
  type: z.string().default('unknown'),
  severity: z.number().int().min(0).max(5).optional(),
  description: z.string().optional().default(''),
  location: locationSchema.optional(),
  reported_at: z.string().optional(),
  reporter_id: z.string().optional(),
  org_id: z.string().optional(),
  client_type: z.string().optional(),
  status: z.string().optional()
});

export const intelligenceQuerySchema = z.object({
  area: z.string(),
  radius_km: z.number().positive().optional().default(5),
  days_back: z.number().int().positive().optional().default(30),
  categories: z.array(z.string()).optional().default(['Physical', 'Cyber', 'Political', 'Macro']),
  severity_min: z.number().int().min(0).max(5).optional().default(1),
  limit: z.number().int().positive().max(100).optional().default(50),
  include_heatmap: z.boolean().optional().default(true),
  incident_context: z
    .object({
      type: z.string().optional(),
      keywords: z.array(z.string()).optional().default([])
    })
    .optional()
});

export const osintBrainQuerySchema = z.object({
  org_id: z.string().optional(),
  question: z.string().optional(),
  location: z.string().optional(),
  lookback_days: z.number().int().positive().optional().default(180),
  recent_limit: z.number().int().positive().optional().default(10),
  area: z.string().optional(),
  radius_km: z.number().positive().optional(),
  days_back: z.number().int().positive().optional(),
  categories: z.array(z.string()).optional(),
  severity_min: z.number().int().min(0).max(5).optional(),
  include_heatmap: z.boolean().optional(),
  incident_context: z
    .object({
      type: z.string().optional(),
      keywords: z.array(z.string()).optional()
    })
    .optional()
}).passthrough();

export const osintPacketSchema = z.object({
  org_id: z.string().optional(),
  packet: z.record(z.any()).optional(),
  sources: z.array(z.any()).optional(),
  classification: z.record(z.any()).optional(),
  entities: z.record(z.any()).optional(),
  notes: z.string().optional()
}).passthrough();

export const osintTaskResolveSchema = z.object({
  org_id: z.string().optional(),
  task_id: z.string().optional(),
  task_type: z.string().optional(),
  status: z.string().optional(),
  result: z.record(z.any()).optional(),
  notes: z.string().optional()
}).passthrough();

export const osintCollectSchema = z.object({
  org_id: z.string().optional(),
  extra_keywords: z.string().optional(),
  source_id: z.string().optional(),
  source_ids: z.array(z.union([z.string(), z.number()])).optional(),
  reason: z.string().optional()
}).passthrough();

export const osintBriefSchema = z.object({
  org_id: z.string().optional(),
  days: z.union([z.string(), z.number()]).optional()
}).passthrough();

export const osintAlertDispatchSchema = z.object({
  org_id: z.string().optional(),
  alert_id: z.string().optional(),
  title: z.string().optional(),
  message: z.string().optional(),
  severity: z.string().optional(),
  channel: z.string().optional()
}).passthrough();

export const osintTaskSchema = z.object({
  org_id: z.string().optional(),
  task_type: z.string(),
  extra_keywords: z.string().optional(),
  priority: z.number().int().optional(),
  source_id: z.string().optional(),
  source_ids: z.array(z.union([z.string(), z.number()])).optional(),
  status: z.string().optional()
}).passthrough();

export const inventoryQuerySchema = z.object({
  request_type: z.string(),
  request_id: z.string(),
  org_id: z.string(),
  filters: z.record(z.any()).optional()
});

export const proximityRequestSchema = z.object({
  request_type: z.literal('find_responders'),
  request_id: z.string(),
  org_id: z.string(),
  incident: z.object({
    id: z.string(),
    type: z.string().optional(),
    severity: z.number().optional(),
    description: z.string().optional(),
    location: locationSchema,
    requirements: z
      .object({
        officers_needed: z.number().int().optional(),
        armed_required: z.boolean().optional(),
        certifications_preferred: z.array(z.string()).optional(),
        vehicles_needed: z.number().int().optional(),
        priority: z.string().optional()
      })
      .optional()
  }),
  options: z
    .object({
      search_radius_km: z.number().positive().optional().default(5),
      max_candidates: z.number().int().positive().optional().default(10),
      include_vehicles: z.boolean().optional().default(false),
      request_eta_from_route_calculator: z.boolean().optional().default(true)
    })
    .optional()
});

export const routeCalculateSchema = z.object({
  request_type: z.literal('route_calculate'),
  request_id: z.string(),
  org_id: z.string(),
  incident: z.object({
    id: z.string(),
    location: locationSchema,
    type: z.string().optional(),
    indoor: z.boolean().optional(),
    building_id: z.string().optional()
  }),
  responders: z
    .object({
      officers: z.array(z.string()).optional().default([]),
      vehicles: z.array(z.string()).optional().default([])
    })
    .optional(),
  routing_preferences: z
    .object({
      type: z.string().optional(),
      prioritise: z.string().optional()
    })
    .optional()
});

export const routePushSchema = z.object({
  route_id: z.string(),
  officer_ids: z.array(z.string()).default([]),
  org_id: z.string().optional(),
  request_id: z.string().optional()
}).passthrough();

export const routeUpdateSchema = routeCalculateSchema.extend({
  route_id: z.string().optional()
}).passthrough();

export const infrastructureRegisterSchema = z.object({
  id: z.string().optional(),
  org_id: z.string().optional(),
  name: z.string().optional(),
  type: z.string().optional(),
  status: z.string().optional(),
  device_type: z.string().optional(),
  supported_actions: z.array(z.string()).optional(),
  metadata: z.record(z.any()).optional()
}).passthrough();

export const infrastructureQuerySchema = z.object({
  org_id: z.string().optional()
}).passthrough();

export const aiAnalysisSchema = z.object({
  request_type: z.literal('incident_analysis'),
  request_id: z.string(),
  incident: incidentSchema,
  context: z
    .object({
      osint_data: z.any().optional(),
      inventory: z.any().optional(),
      available_officers: z.array(z.any()).optional(),
      proximity: z.any().optional(),
      route_calculator: z.any().optional(),
      client_type: z.string().optional()
    })
    .optional()
});

export const agentTaskSchema = z.object({
  request_type: z.literal('agent_task'),
  request_id: z.string(),
  task_type: z.string(),
  raw_input: z.object({
    source: z.string().optional(),
    content: z.string(),
    caller_id: z.string().optional(),
    location_confirmed: z.boolean().optional(),
    location: locationSchema.optional()
  }),
  available_services: z.array(z.string()).default([]),
  constraints: z
    .object({
      autonomous_actions_require_approval: z.boolean().optional().default(true),
      max_response_time_seconds: z.number().int().positive().optional().default(30),
      approval_officer_id: z.string().optional()
    })
    .optional()
});

export const masterAiIncidentRawSchema = z
  .object({
    description: z.string().optional(),
    reported_by: z.string().optional(),
    location_stated: z.string().optional(),
    building: z.string().optional(),
    floor: z.number().optional(),
    zone: z.string().optional(),
    lat: z.number().optional(),
    lng: z.number().optional(),
    timestamp: z.string().optional(),
    source: z.string().optional()
  })
  .passthrough();

export const masterAiOrgContextSchema = z
  .object({
    org_type: z.string().optional(),
    location_name: z.string().optional(),
    area: z.string().optional()
  })
  .passthrough();

export const masterAiTriageSchema = z.object({
  request_type: z.literal('agent_triage'),
  request_id: z.string(),
  org_id: z.string(),
  incident_raw: masterAiIncidentRawSchema,
  org_context: masterAiOrgContextSchema.optional()
});

export const masterAiSynthesiseSchema = z.object({
  request_type: z.literal('agent_synthesise'),
  request_id: z.string(),
  org_id: z.string(),
  incident: z
    .object({
      id: z.string(),
      type: z.string().optional(),
      severity: z.number().optional(),
      description: z.string().optional(),
      location: z.union([z.string(), locationSchema]).optional(),
      triage: z.record(z.any()).optional()
    })
    .passthrough(),
  service_results: z.record(z.any())
});

export const masterAiProcessSchema = z
  .object({
    request_type: z.string(),
    request_id: z.string(),
    org_id: z.string().optional(),
    incident_raw: masterAiIncidentRawSchema.optional(),
    org_context: masterAiOrgContextSchema.optional(),
    incident: z.record(z.any()).optional(),
    service_results: z.record(z.any()).optional(),
    alert_type: z.string().optional(),
    message: z.string().optional()
  })
  .passthrough();

export const autonomousActionSchema = z.object({
  request_type: z.literal('autonomous_action'),
  request_id: z.string(),
  org_id: z.string().optional(),
  action: z.object({
    type: z.string(),
    target_id: z.string(),
    command: z.string(),
    route_ids: z.array(z.string()).optional().default([]),
    duration_seconds: z.number().int().positive(),
    reason: z.string(),
    incident_id: z.string()
  }),
  authorisation: z.object({
    approved_by: z.string(),
    approval_timestamp: z.string(),
    approval_level: z.string(),
    incident_id: z.string().optional()
  }),
  constraints: z
    .object({
      auto_revert_after_seconds: z.number().int().positive().optional(),
      revert_on_incident_resolved: z.boolean().optional().default(true),
      max_override_duration_seconds: z.number().int().positive().optional()
    })
    .optional()
});

export const internalAutonomousExecuteSchema = z.object({
  request_type: z.literal('execute_action'),
  request_id: z.string(),
  org_id: z.string(),
  action: z.object({
    action_key: z.string(),
    device_id: z.string(),
    parameters: z.record(z.any()).optional().default({})
  }),
  authorisation: z.object({
    approved_by: z.string(),
    approval_timestamp: z.string(),
    approval_level: z.string(),
    incident_id: z.string()
  })
});

export const approvalSchema = z.object({
  approved_by: z.string(),
  approval_level: z.string(),
  notes: z.string().optional()
});

export const queryParamsListSchema = z.object({
  org_id: z.string().optional(),
  limit: stringOrNumber.optional(),
  days: stringOrNumber.optional(),
  area: z.string().optional(),
  radius_km: stringOrNumber.optional(),
  include_heatmap: z.string().optional(),
  armed_only: z.string().optional(),
  available_only: z.string().optional(),
  fuelled_only: z.string().optional(),
  min_fuel_percentage: stringOrNumber.optional(),
  type: z.string().optional(),
  certified: z.union([z.string(), z.array(z.string())]).optional(),
  max_candidates: stringOrNumber.optional()
});

export const entitySchema = z.object({
  id: z.string().optional(),
  org_id: z.string().optional(),
  entity_type: z.string().default('unknown'),
  name: z.string().optional(),
  status: z.string().optional(),
  attributes: z.record(z.any()).optional().default({}),
  aliases: z.array(z.string()).optional().default([])
});

export const relationshipSchema = z.object({
  id: z.string().optional(),
  org_id: z.string().optional(),
  source_entity_id: z.string(),
  target_entity_id: z.string(),
  relationship_type: z.string(),
  confidence: z.number().min(0).max(1).optional().default(1),
  status: z.enum(['active', 'inactive']).optional().default('active'),
  metadata: z.record(z.any()).optional().default({}),
  created_by: z.string().optional(),
  idempotency_key: z.string().optional()
});

export const graphQuerySchema = z.object({
  root_entity_id: z.string(),
  depth: z.number().int().min(1).max(5).optional().default(2),
  direction: z.enum(['inbound', 'outbound', 'both']).optional().default('both'),
  relationship_types: z.array(z.string()).optional().default([]),
  entity_types: z.array(z.string()).optional().default([]),
  include_inactive: z.boolean().optional().default(false)
});

export const inventoryAlertSchema = z.object({
  alert_id: z.string(),
  org_id: z.string(),
  timestamp: z.string().optional(),
  alert_level: z.string(),
  resource_type: z.string(),
  metric: z.string(),
  current_value: z.any(),
  threshold_value: z.any(),
  message: z.string(),
  affected_resources: z.array(z.string()).optional().default([]),
  recommended_action: z.string().optional(),
  repeat_alert: z.boolean().optional(),
  next_alert_at: z.string().optional(),
  llm_review: z.record(z.any()).optional()
});

export function toBool(value: unknown, fallback = false): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
  return fallback;
}

export function toNumber(value: unknown, fallback?: number): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
}
