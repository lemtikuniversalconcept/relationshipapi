export type Role =
  | 'viewer'
  | 'operator'
  | 'security_manager'
  | 'supervisor'
  | 'manager'
  | 'admin'
  | 'service'
  | 'integration';

export type RequestPrincipal = {
  sub: string;
  org_id?: string;
  role: Role;
  scope: string[];
  caller_type: 'jwt' | 'api_key' | 'webhook' | 'anonymous';
  actor_id?: string;
  actor_role?: string;
  client_name?: string;
};

export type ServiceName =
  | 'osint'
  | 'aiAnalysis'
  | 'mainAgent'
  | 'autonomous'
  | 'inventory'
  | 'proximity'
  | 'routeCalculator';

export type ServiceConfig = {
  name: ServiceName;
  baseUrl?: string;
  healthPath: string;
  defaultHeaders: Record<string, string>;
  authMode: 'api-key' | 'bearer' | 'none';
  fallbackService: ServiceName;
};

export type AuditEntry = {
  id: string;
  request_id: string;
  method: string;
  path: string;
  status_code: number;
  duration_ms: number;
  org_id?: string;
  role?: string;
  sub?: string;
  client_name?: string;
  actor_id?: string;
  actor_role?: string;
  service_calls: string[];
  success: boolean;
  timestamp: string;
};

export type IdempotencyRecord = {
  responseId: string;
  payloadHash: string;
  createdAt: string;
};

export type StoredApproval = {
  request_id: string;
  org_id?: string;
  incident_id?: string;
  approved_by: string;
  approval_level: string;
  approved_at: string;
  notes?: string;
};

export type StoredOverride = {
  override_id: string;
  request_id: string;
  org_id?: string;
  incident_id?: string;
  action_key: string;
  device_id?: string;
  status: 'active' | 'reverted' | 'failed' | 'queued';
  approved_by?: string;
  approval_level?: string;
  created_at: string;
  executed_at?: string;
  revert_at?: string;
  payload?: unknown;
  result?: unknown;
};

export type IncidentRecord = {
  id: string;
  org_id: string;
  status: string;
  created_at: string;
  updated_at: string;
  incident: Record<string, unknown>;
  services: Record<string, unknown>;
  analysis?: Record<string, unknown>;
  dispatch_plan?: Record<string, unknown>;
  agent_output?: Record<string, unknown>;
  warnings: string[];
};

export type EntityType =
  | 'person'
  | 'user'
  | 'officer'
  | 'incident'
  | 'location'
  | 'zone'
  | 'asset'
  | 'device'
  | 'vehicle'
  | 'organization'
  | 'contact'
  | 'evidence'
  | 'unknown';

export type GraphEntity = {
  id: string;
  org_id: string;
  entity_type: EntityType;
  name?: string;
  status?: string;
  attributes: Record<string, unknown>;
  aliases: string[];
  created_at: string;
  updated_at: string;
};

export type GraphRelationship = {
  id: string;
  org_id: string;
  source_entity_id: string;
  target_entity_id: string;
  relationship_type: string;
  confidence: number;
  status: 'active' | 'inactive';
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  created_by?: string;
  idempotency_key?: string;
  ended_at?: string;
  ended_reason?: string;
};

export type GraphEvent = {
  id: string;
  org_id: string;
  event_type: string;
  entity_id?: string;
  relationship_id?: string;
  correlation_id?: string;
  payload: Record<string, unknown>;
  created_at: string;
};

export type DeviceRecord = {
  id: string;
  org_id: string;
  name: string;
  type: string;
  connection_type: string;
  supported_actions: string[];
  status: string;
  connection_details?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type BridgeRecord = {
  id: string;
  org_id: string;
  name: string;
  type: string;
  status: string;
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type InfrastructureRecord = {
  id: string;
  org_id: string;
  name: string;
  type: string;
  status: string;
  device_type?: string;
  supported_actions: string[];
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type RoutePlanRecord = {
  route_id: string;
  request_id: string;
  org_id: string;
  incident_id: string;
  incident: Record<string, unknown>;
  responders: {
    officers: string[];
    vehicles: string[];
  };
  recommended_routing_type: string;
  reasoning: string;
  routes: Array<Record<string, unknown>>;
  infrastructure_recommendations: Array<Record<string, unknown>>;
  push_route_to_officers: string[];
  mapbox_route_geojson: Record<string, unknown>;
  meta: {
    valhalla_query_ms: number;
    radar_query_ms: number;
    infra_query_ms: number;
    total_ms: number;
  };
  pushed: boolean;
  pushed_at?: string;
  updated_at: string;
  created_at: string;
};

export type AutonomousActionLog = {
  action_log_id: string;
  request_id: string;
  org_id: string;
  incident_id?: string;
  device_id: string;
  device_name?: string;
  action_key: string;
  execution_result: 'success' | 'failed' | 'queued' | 'unconfirmed';
  adapter_used: string;
  executed_at: string;
  confirmed: boolean;
  auto_revert_scheduled: boolean;
  revert_at?: string;
  revert_action?: string;
  warnings: string[];
  active_override_id?: string;
  error?: string;
};

export type InventoryAlert = {
  alert_id: string;
  org_id: string;
  timestamp: string;
  alert_level: string;
  resource_type: string;
  metric: string;
  current_value: unknown;
  threshold_value: unknown;
  message: string;
  affected_resources: string[];
  recommended_action?: string;
  repeat_alert?: boolean;
  next_alert_at?: string;
  llm_review?: Record<string, unknown>;
  resolved?: boolean;
  resolved_by?: string;
  resolved_at?: string;
  notes?: string;
};
