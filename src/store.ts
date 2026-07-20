import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { config } from './config';
import { syncSupabaseRecord } from './external-sync';
import {
  AuditEntry,
  AiApprovalRecord,
  AiLogRecord,
  AiOperationRecord,
  AutonomousActionLog,
  BridgeRecord,
  DeviceRecord,
  IdempotencyRecord,
  InventoryAlert,
  GraphEntity,
  GraphEvent,
  GraphRelationship,
  IncidentRecord,
  InfrastructureRecord,
  RoutePlanRecord,
  StoredApproval,
  StoredOverride
} from './types';

const incidents = new Map<string, IncidentRecord>();
const approvals = new Map<string, StoredApproval>();
const overrides = new Map<string, StoredOverride>();
const sessions = new Map<string, unknown>();
const auditEntries: AuditEntry[] = [];
const entities = new Map<string, GraphEntity>();
const relationships = new Map<string, GraphRelationship>();
const graphEvents: GraphEvent[] = [];
const idempotencyMap = new Map<string, IdempotencyRecord>();
const devices = new Map<string, DeviceRecord>();
const bridges = new Map<string, BridgeRecord>();
const infrastructure = new Map<string, InfrastructureRecord>();
const autonomousLogs: AutonomousActionLog[] = [];
const inventoryAlerts = new Map<string, InventoryAlert>();
const routePlans = new Map<string, RoutePlanRecord>();
const aiOperations = new Map<string, AiOperationRecord>();
const aiApprovals = new Map<string, AiApprovalRecord>();
const aiLogs = new Map<string, AiLogRecord>();
const dataDir = path.join(process.cwd(), 'data');
const filePaths = {
  incidents: path.join(dataDir, 'incidents.json'),
  approvals: path.join(dataDir, 'approvals.json'),
  overrides: path.join(dataDir, 'overrides.json'),
  sessions: path.join(dataDir, 'sessions.json'),
  auditLog: path.join(dataDir, 'audit-log.jsonl'),
  entities: path.join(dataDir, 'entities.json'),
  relationships: path.join(dataDir, 'relationships.json'),
  graphEvents: path.join(dataDir, 'graph-events.json'),
  idempotency: path.join(dataDir, 'idempotency.json'),
  devices: path.join(dataDir, 'devices.json'),
  bridges: path.join(dataDir, 'bridges.json'),
  infrastructure: path.join(dataDir, 'infrastructure.json'),
  autonomousLogs: path.join(dataDir, 'autonomous-logs.json'),
  inventoryAlerts: path.join(dataDir, 'inventory-alerts.json'),
  routePlans: path.join(dataDir, 'route-plans.json'),
  aiOperations: path.join(dataDir, 'ai-operations.json'),
  aiApprovals: path.join(dataDir, 'ai-approvals.json'),
  aiLogs: path.join(dataDir, 'ai-logs.json')
};

function ensureParent(filePath: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function readJsonFile<T>(filePath: string, fallback: T): T {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw.trim()) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function writeJsonFile(filePath: string, value: unknown): void {
  ensureParent(filePath);
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function deliverGraphEvent(event: GraphEvent): Promise<void> {
  const targets = config.relationshipWebhookUrls || [];
  if (!targets.length) return;
  const payload = JSON.stringify({
    event_id: event.id,
    event_type: event.event_type,
    timestamp: event.created_at,
    org_id: event.org_id,
    entity_id: event.entity_id,
    relationship_id: event.relationship_id,
    correlation_id: event.correlation_id,
    payload: event.payload
  });
  const signature = config.webHookSecret
    ? crypto.createHmac('sha256', config.webHookSecret).update(payload).digest('hex')
    : '';
  for (const target of targets) {
    try {
      await fetch(target, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(signature ? { 'X-Webhook-Signature': signature } : {}),
          'X-Event-Id': event.id,
          'X-Event-Type': event.event_type,
          'X-Org-Id': event.org_id,
          'X-Request-Id': event.correlation_id || event.id
        },
        body: payload
      });
    } catch {
      // Best effort delivery.
    }
  }
}

function readJsonLines(filePath: string): any[] {
  try {
    if (!fs.existsSync(filePath)) return [];
    const raw = fs.readFileSync(filePath, 'utf8');
    return raw
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

function appendJsonLine(filePath: string, value: unknown): void {
  ensureParent(filePath);
  fs.appendFileSync(filePath, `${JSON.stringify(value)}\n`, 'utf8');
}

function persistMap<T extends { [key: string]: any }>(map: Map<string, T>, filePath: string): void {
  writeJsonFile(filePath, [...map.values()]);
}

function persistArray<T>(value: T[], filePath: string): void {
  writeJsonFile(filePath, value);
}

function loadMap<T extends { [key: string]: any }>(filePath: string, key: keyof T): Map<string, T> {
  const items = readJsonFile<T[]>(filePath, []);
  return new Map(items.map((item) => [String(item[key]), item]));
}

function loadArray<T>(filePath: string): T[] {
  return readJsonFile<T[]>(filePath, []);
}

function loadObject<T extends Record<string, unknown>>(filePath: string): T {
  return readJsonFile<T>(filePath, {} as T);
}

function hydrateStores(): void {
  const hydration = [
    [incidents, filePaths.incidents, 'id'],
    [approvals, filePaths.approvals, 'request_id'],
    [overrides, filePaths.overrides, 'override_id'],
    [entities, filePaths.entities, 'id'],
    [relationships, filePaths.relationships, 'id'],
    [devices, filePaths.devices, 'id'],
    [bridges, filePaths.bridges, 'id'],
    [infrastructure, filePaths.infrastructure, 'id'],
    [inventoryAlerts, filePaths.inventoryAlerts, 'alert_id'],
    [routePlans, filePaths.routePlans, 'route_id'],
    [aiOperations, filePaths.aiOperations, 'operation_id'],
    [aiApprovals, filePaths.aiApprovals, 'approval_id'],
    [aiLogs, filePaths.aiLogs, 'id']
  ] as const;

  for (const [map, filePath, key] of hydration) {
    const items = readJsonFile<Record<string, any>[]>(filePath, []);
    map.clear();
    for (const item of items) {
      if (item && item[key]) map.set(String(item[key]), item as any);
    }
  }

  for (const log of readArrayOrEmpty<AutonomousActionLog>(filePaths.autonomousLogs)) {
    autonomousLogs.push(log);
  }

  for (const entry of readJsonLines(filePaths.auditLog)) {
    auditEntries.push(entry as AuditEntry);
  }

  const loadedSessions = readJsonFile<Record<string, unknown>>(filePaths.sessions, {});
  for (const [requestId, payload] of Object.entries(loadedSessions)) {
    sessions.set(requestId, payload);
  }

  const loadedIdempotency = readJsonFile<Record<string, IdempotencyRecord>>(filePaths.idempotency, {});
  for (const [key, value] of Object.entries(loadedIdempotency)) {
    idempotencyMap.set(key, value);
  }
}

function readArrayOrEmpty<T>(filePath: string): T[] {
  return readJsonFile<T[]>(filePath, []);
}

hydrateStores();

export function saveIncident(record: IncidentRecord): IncidentRecord {
  incidents.set(record.id, record);
  persistMap(incidents, filePaths.incidents);
  syncSupabaseRecord('incidents', record);
  return record;
}

export function getIncident(id: string): IncidentRecord | undefined {
  return incidents.get(id);
}

export function listIncidents(): IncidentRecord[] {
  return [...incidents.values()];
}

export function updateIncident(id: string, patch: Partial<IncidentRecord>): IncidentRecord | undefined {
  const current = incidents.get(id);
  if (!current) return undefined;
  const next = { ...current, ...patch, updated_at: new Date().toISOString() };
  incidents.set(id, next);
  persistMap(incidents, filePaths.incidents);
  return next;
}

export function saveApproval(record: StoredApproval): StoredApproval {
  approvals.set(record.request_id, record);
  persistMap(approvals, filePaths.approvals);
  syncSupabaseRecord('approvals', record);
  return record;
}

export function getApproval(request_id: string): StoredApproval | undefined {
  return approvals.get(request_id);
}

export function saveOverride(record: StoredOverride): StoredOverride {
  overrides.set(record.override_id, record);
  persistMap(overrides, filePaths.overrides);
  syncSupabaseRecord('overrides', record);
  return record;
}

export function getOverride(override_id: string): StoredOverride | undefined {
  return overrides.get(override_id);
}

export function listOverrides(): StoredOverride[] {
  return [...overrides.values()];
}

export function saveSession(request_id: string, payload: unknown): void {
  sessions.set(request_id, payload);
  writeJsonFile(filePaths.sessions, Object.fromEntries(sessions.entries()));
}

export function getSession(request_id: string): unknown | undefined {
  return sessions.get(request_id);
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isUuid(str: any): boolean {
  return typeof str === 'string' && UUID_REGEX.test(str);
}

export function pushAudit(entry: AuditEntry, auditLogPath: string): void {
  auditEntries.push(entry);
  try {
    ensureParent(auditLogPath);
    fs.appendFileSync(auditLogPath, `${JSON.stringify(entry)}\n`, 'utf8');
    appendJsonLine(filePaths.auditLog, entry);
  } catch (err) {
    console.error('Local audit file write failed:', err);
  }

  const actorIdVal = isUuid(entry.actor_id) ? entry.actor_id : (isUuid(entry.sub) ? entry.sub : '00000000-0000-0000-0000-000000000000');
  const orgIdVal = isUuid(entry.org_id) ? entry.org_id : null;
  const entityIdVal = isUuid(entry.ai_operation_id) ? entry.ai_operation_id : null;

  const dbRecord = {
    id: entry.id,
    actor_id: actorIdVal,
    actor_name: entry.client_name || entry.sub || 'System',
    entity: entry.path.split('/').filter(Boolean)[2] || 'gateway',
    entity_id: entityIdVal,
    action: `${entry.method} ${entry.path.split('?')[0]}`,
    details: entry,
    organisation_id: orgIdVal,
    created_at: entry.timestamp
  };

  syncSupabaseRecord('audit_log', dbRecord);
}

export function queryAudit(limit = 100): AuditEntry[] {
  return auditEntries.slice(-Math.max(1, limit));
}

export function saveAiOperation(operation: AiOperationRecord): AiOperationRecord {
  aiOperations.set(operation.operation_id, operation);
  persistMap(aiOperations, filePaths.aiOperations);
  syncSupabaseRecord('ai_operations', operation);
  return operation;
}

export function getAiOperation(operationId: string): AiOperationRecord | undefined {
  return aiOperations.get(operationId);
}

export function listAiOperations(limit = 100): AiOperationRecord[] {
  return [...aiOperations.values()].slice(-Math.max(1, limit));
}

export function saveAiApproval(record: AiApprovalRecord): AiApprovalRecord {
  aiApprovals.set(record.approval_id, record);
  persistMap(aiApprovals, filePaths.aiApprovals);
  syncSupabaseRecord('ai_approvals', record);
  return record;
}

export function getAiApproval(approvalId: string): AiApprovalRecord | undefined {
  return aiApprovals.get(approvalId);
}

export function listAiApprovals(limit = 100): AiApprovalRecord[] {
  return [...aiApprovals.values()].slice(-Math.max(1, limit));
}

export function saveAiLog(record: AiLogRecord): AiLogRecord {
  aiLogs.set(record.id, record);
  persistMap(aiLogs, filePaths.aiLogs);
  syncSupabaseRecord('ai_logs', record);
  return record;
}

export function listAiLogs(limit = 100): AiLogRecord[] {
  return [...aiLogs.values()].slice(-Math.max(1, limit));
}

export function getAiLog(id: string): AiLogRecord | undefined {
  return aiLogs.get(id);
}

export function saveEntity(entity: GraphEntity): GraphEntity {
  entities.set(entity.id, entity);
  persistMap(entities, filePaths.entities);
  syncSupabaseRecord('entities', entity);
  return entity;
}

export function getEntity(id: string): GraphEntity | undefined {
  return entities.get(id);
}

export function listEntities(): GraphEntity[] {
  return [...entities.values()];
}

export function saveRelationship(relationship: GraphRelationship): GraphRelationship {
  relationships.set(relationship.id, relationship);
  persistMap(relationships, filePaths.relationships);
  syncSupabaseRecord('relationships', relationship);
  return relationship;
}

export function getRelationship(id: string): GraphRelationship | undefined {
  return relationships.get(id);
}

export function listRelationships(): GraphRelationship[] {
  return [...relationships.values()];
}

export function findRelationshipsByEntity(entityId: string): GraphRelationship[] {
  return listRelationships().filter((relationship) =>
    relationship.source_entity_id === entityId ||
    relationship.target_entity_id === entityId
  );
}

export function saveGraphEvent(event: GraphEvent): GraphEvent {
  graphEvents.push(event);
  persistArray(graphEvents, filePaths.graphEvents);
  syncSupabaseRecord('relationship_events', event);
  void deliverGraphEvent(event);
  return event;
}

export function listGraphEvents(limit = 100): GraphEvent[] {
  return graphEvents.slice(-Math.max(1, limit));
}

export function getIdempotentResponse(key: string): string | undefined {
  return idempotencyMap.get(key)?.responseId;
}

export function getIdempotentRecord(key: string): IdempotencyRecord | undefined {
  return idempotencyMap.get(key);
}

export function setIdempotentResponse(key: string, responseId: string, payloadHash = ''): void {
  idempotencyMap.set(key, {
    responseId,
    payloadHash,
    createdAt: new Date().toISOString()
  });
  writeJsonFile(filePaths.idempotency, Object.fromEntries(idempotencyMap.entries()));
}

export function saveDevice(device: DeviceRecord): DeviceRecord {
  devices.set(device.id, device);
  persistMap(devices, filePaths.devices);
  syncSupabaseRecord('devices', device);
  return device;
}

export function getDevice(id: string): DeviceRecord | undefined {
  return devices.get(id);
}

export function listDevices(): DeviceRecord[] {
  return [...devices.values()];
}

export function saveBridge(bridge: BridgeRecord): BridgeRecord {
  bridges.set(bridge.id, bridge);
  persistMap(bridges, filePaths.bridges);
  syncSupabaseRecord('bridges', bridge);
  return bridge;
}

export function getBridge(id: string): BridgeRecord | undefined {
  return bridges.get(id);
}

export function listBridges(): BridgeRecord[] {
  return [...bridges.values()];
}

export function saveInfrastructure(record: InfrastructureRecord): InfrastructureRecord {
  infrastructure.set(record.id, record);
  persistMap(infrastructure, filePaths.infrastructure);
  syncSupabaseRecord('infrastructure', record);
  return record;
}

export function getInfrastructure(id: string): InfrastructureRecord | undefined {
  return infrastructure.get(id);
}

export function listInfrastructure(orgId?: string): InfrastructureRecord[] {
  return [...infrastructure.values()].filter((record) => !orgId || record.org_id === orgId);
}

export function saveAutonomousLog(log: AutonomousActionLog): AutonomousActionLog {
  autonomousLogs.push(log);
  persistArray(autonomousLogs, filePaths.autonomousLogs);
  syncSupabaseRecord('autonomous_logs', log);
  return log;
}

export function listAutonomousLogs(limit = 100): AutonomousActionLog[] {
  return autonomousLogs.slice(-Math.max(1, limit));
}

export function findAutonomousLog(actionLogId: string): AutonomousActionLog | undefined {
  return autonomousLogs.find((entry) => entry.action_log_id === actionLogId);
}

export function saveInventoryAlert(alert: InventoryAlert): InventoryAlert {
  inventoryAlerts.set(alert.alert_id, alert);
  persistMap(inventoryAlerts, filePaths.inventoryAlerts);
  syncSupabaseRecord('inventory_alerts', alert);
  return alert;
}

export function getInventoryAlert(alertId: string): InventoryAlert | undefined {
  return inventoryAlerts.get(alertId);
}

export function listInventoryAlerts(orgId?: string): InventoryAlert[] {
  return [...inventoryAlerts.values()].filter((alert) => !orgId || alert.org_id === orgId);
}

export function saveRoutePlan(route: RoutePlanRecord): RoutePlanRecord {
  routePlans.set(route.route_id, route);
  persistMap(routePlans, filePaths.routePlans);
  syncSupabaseRecord('graph_snapshots', route);
  return route;
}

export function getRoutePlan(routeId: string): RoutePlanRecord | undefined {
  return routePlans.get(routeId);
}

export function listRoutePlans(orgId?: string): RoutePlanRecord[] {
  return [...routePlans.values()].filter((route) => !orgId || route.org_id === orgId);
}
