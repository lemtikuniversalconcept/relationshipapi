# Relationship API Integration Guide

This document explains how the Relationship API fits into the Lemtik Security platform, how other applications or APIs can connect to it, and how data should flow in and out of it without hardcoding assumptions into clients.

The goal is to make the service:

- Easy to call from other backend services
- Safe to call from the web app through server-side code
- Flexible enough to support Supabase, Redis, blob storage, and future services
- Clear about query, write, and sync patterns

## 1. What The Relationship API Is

The Relationship API is the platform service responsible for relationship-centric data:

- People to locations
- People to incidents
- Devices to zones
- Organizations to assets
- Incidents to incidents
- Users to assignments, approvals, and evidence
- Any other graph-like or linked operational data

Think of it as the graph and linkage service for the platform. It should answer questions like:

- Which officers are related to this incident?
- What zones are connected to this location?
- What incidents are linked by time, place, or pattern?
- Which assets are associated with this organization?
- What entities should be traversed when building an OSINT or operational view?

It should be used as a data service, not as a UI service.

## 2. How It Fits Into The Platform

The platform has three broad caller types:

1. The browser app
2. Platform backend/server functions
3. External apps or third-party APIs

The browser app should not call the Relationship API directly unless the API is explicitly public and safe for browser use. In this codebase, the preferred path is:

- Browser UI
- TanStack server function or backend route
- Relationship API

That pattern keeps service credentials off the client, enforces RBAC centrally, and lets the backend normalize payloads before they reach the Relationship API.

### Recommended Flow

- UI gathers user intent
- UI sends data to a server function
- Server function validates input and checks RBAC
- Server function forwards the request to the Relationship API
- Relationship API stores or returns graph data
- Server function returns a safe response to the UI

## 3. Connection Models

There are two valid connection models.

### A. Internal Service-To-Service

Use this when the caller is another Lemtik service or backend route.

Example:

- Incident service asks for linked incidents
- Patrol service asks for officer-to-zone mappings
- Admin service asks for organization relationships

The caller should use:

- A service token or signed JWT
- A tenant or organization identifier
- A request ID for traceability

### B. External Application Integration

Use this when another platform or customer system wants to query or send relationship data.

Example:

- A hotel security system wants to push room-to-incident mappings
- A bank SIEM wants to query asset relationships
- A partner app wants to synchronize officer assignment data

The external app should use:

- A dedicated API key, OAuth token, or signed service JWT
- A fixed base URL from configuration
- Explicit tenant scoping
- Idempotency keys for write operations

## 4. Base URL And Environment Configuration

Do not hardcode the Relationship API URL in clients.

Use configuration:

- `RELATIONSHIP_API_URL`
- `RELATIONSHIP_API_KEY`
- `RELATIONSHIP_API_TIMEOUT_MS`
- `RELATIONSHIP_API_RETRY_COUNT`

In production, the value should point to the Render-hosted service or whichever environment is active.

Example:

```bash
RELATIONSHIP_API_URL=https://relationship-api.example.com
RELATIONSHIP_API_KEY=service_xxx
RELATIONSHIP_API_TIMEOUT_MS=8000
RELATIONSHIP_API_RETRY_COUNT=2
```

## 5. Authentication

Every request should be authenticated.

Preferred authentication options:

- Bearer service token
- Signed JWT with organization claims
- OAuth2 client credentials for partner integrations
- Supabase-auth-backed server-to-server session if the caller is an internal platform function

### Required Claims

For any non-public route, the token should identify:

- Caller type
- Caller organization
- Permission scope
- Expiration time
- Optional user ID if the request is acting on behalf of a person

Example claims:

```json
{
  "sub": "service-incident-api",
  "org_id": "org_123",
  "scope": ["relationships:read", "relationships:write"],
  "aud": "relationship-api",
  "exp": 1760000000
}
```

## 6. Authorization

Authentication proves who is calling. Authorization proves what they can access.

The Relationship API should enforce:

- Tenant isolation
- Resource ownership
- Role-based constraints
- Read/write separation where required

Examples:

- A `client_admin` can query their organization relationships
- A `security_manager` can read and write operational links
- An external partner can only access the organization and scopes explicitly granted
- A browser user should only see relationships allowed by the current active organization and role

The API must never trust a client-supplied `organization_id` unless the token is allowed to act for that organization.

## 7. Core Data Concepts

The API should revolve around a small set of stable concepts.

### Entity

An entity is anything that can be linked:

- Person
- User
- Officer
- Incident
- Location
- Zone
- Asset
- Device
- Vehicle
- Organization
- Contact
- Evidence item

### Relationship

A relationship is a typed link between two entities.

Examples:

- `assigned_to`
- `reported_at`
- `located_in`
- `linked_to`
- `owns`
- `monitors`
- `responding_to`
- `near`
- `member_of`

### Graph Query

Graph query means asking for:

- Immediate links
- Multi-hop links
- Reverse links
- Related entity summaries
- Path traversal results

### Relationship Event

A relationship event is a change that should be stored and optionally emitted to subscribers.

Examples:

- Link created
- Link removed
- Entity updated
- Entity merged
- Relationship confidence changed
- External sync accepted

## 8. Suggested Endpoint Pattern

The exact route names can vary, but the API should be organized consistently.

### Health

- `GET /health`
- `GET /ready`

### Entities

- `GET /v1/entities`
- `GET /v1/entities/:id`
- `POST /v1/entities`
- `PATCH /v1/entities/:id`

### Relationships

- `GET /v1/relationships`
- `GET /v1/relationships/:id`
- `POST /v1/relationships`
- `PATCH /v1/relationships/:id`
- `DELETE /v1/relationships/:id`

### Graph Queries

- `POST /v1/graph/query`
- `GET /v1/entities/:id/graph`
- `GET /v1/entities/:id/relationships`

### Sync And Ingestion

- `POST /v1/ingest`
- `POST /v1/events`
- `POST /v1/webhooks`

### Metadata

- `GET /v1/schema`
- `GET /v1/relationship-types`
- `GET /v1/entity-types`

## 9. Request Headers

Every caller should send a small standard header set.

```http
Authorization: Bearer <token>
Content-Type: application/json
X-Request-Id: <uuid>
X-Org-Id: <organisation_id>
X-Client-Name: <service-or-app-name>
X-Idempotency-Key: <uuid-for-write-requests>
```

If the request is made on behalf of a user, include:

```http
X-Actor-Id: <user_id>
X-Actor-Role: <role>
```

## 10. Query Patterns

The Relationship API should support several query styles.

### A. Direct Lookup

Use direct lookup when you know the entity ID.

Example:

```http
GET /v1/entities/ent_123
```

Use this for:

- Opening a detail page
- Looking up a linked object
- Building a drill-down panel

### B. Filtered Search

Use filtered search when you want to find entities or relationships by attributes.

Example:

```http
GET /v1/relationships?org_id=org_123&type=assigned_to&entity_id=ent_123
```

Use this for:

- Tables
- Search bars
- Admin screens
- Embedded widgets

### C. Graph Traversal

Use graph traversal when the caller needs context, not just one object.

Example:

```http
POST /v1/graph/query
```

Payload:

```json
{
  "root_entity_id": "inc_123",
  "depth": 2,
  "direction": "both",
  "relationship_types": ["linked_to", "assigned_to", "located_in"]
}
```

Use this for:

- Incident context panels
- OSINT correlation
- Command dashboards
- Threat triage

## 11. Write Patterns

When sending data to the Relationship API, the caller should be explicit and idempotent.

### Create Relationship

```http
POST /v1/relationships
```

Payload:

```json
{
  "source_entity_id": "inc_123",
  "target_entity_id": "officer_456",
  "relationship_type": "assigned_to",
  "confidence": 1,
  "metadata": {
    "assigned_by": "user_789",
    "reason": "Proximity response"
  }
}
```

### Update Relationship

```http
PATCH /v1/relationships/rel_123
```

Use this for:

- Confidence changes
- Metadata changes
- Soft corrections
- Status changes

### Delete Relationship

Use delete only when the relationship is truly invalid or must be removed from the active graph.

For audit-heavy systems, consider soft deletion:

- `status = inactive`
- `ended_at`
- `ended_reason`

## 12. How Another API Should Send Data To It

This is the basic integration flow for an external API or service.

### Step 1: Collect The Event

The caller receives an event or user action, such as:

- Incident created
- Officer assigned
- Location added
- Evidence attached
- Asset status changed

### Step 2: Normalize The Payload

Convert the local data model into the Relationship API schema.

Example:

- Local incident record
- Local officer record
- Local organization ID
- Local location ID

Becomes:

- Source entity ID
- Target entity ID
- Relationship type
- Metadata
- Tenant scope

### Step 3: Authenticate

Attach the service token or signed JWT.

### Step 4: Send The Request

Use HTTPS `POST`, `PATCH`, or `DELETE` depending on the action.

### Step 5: Handle Response

The API should return:

- A success flag
- The created or updated record
- A canonical relationship ID
- Optional downstream sync information

### Step 6: Emit Or Consume Follow-Up Events

If the Relationship API publishes a webhook or event, the caller should:

- Acknowledge receipt
- Deduplicate by event ID
- Retry safely on failure

## 13. Example External Integration

### Example: Incident Service Sends A New Link

Request:

```bash
curl -X POST "$RELATIONSHIP_API_URL/v1/relationships" \
  -H "Authorization: Bearer $RELATIONSHIP_API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-Org-Id: org_123" \
  -H "X-Request-Id: 9f3c0e1d-7f33-4d7f-9b2d-9bc57a6a6c91" \
  -H "X-Idempotency-Key: b0e6f76f-3cf4-4d28-8a2a-93ae1c7d9fcb" \
  -d '{
    "source_entity_id": "inc_123",
    "target_entity_id": "officer_456",
    "relationship_type": "assigned_to",
    "confidence": 1,
    "metadata": {
      "reason": "operator assignment",
      "source": "command-dashboard"
    }
  }'
```

### Example Response

```json
{
  "ok": true,
  "relationship": {
    "id": "rel_789",
    "source_entity_id": "inc_123",
    "target_entity_id": "officer_456",
    "relationship_type": "assigned_to",
    "confidence": 1,
    "created_at": "2026-06-18T10:15:00Z"
  }
}
```

## 14. Example Query From Another Application

### Fetch Relationships For A Location

```bash
curl "$RELATIONSHIP_API_URL/v1/entities/loc_123/relationships?depth=2" \
  -H "Authorization: Bearer $RELATIONSHIP_API_KEY" \
  -H "X-Org-Id: org_123"
```

### Search For Related Incidents

```bash
curl -X POST "$RELATIONSHIP_API_URL/v1/graph/query" \
  -H "Authorization: Bearer $RELATIONSHIP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "root_entity_id": "inc_123",
    "depth": 2,
    "relationship_types": ["linked_to", "located_in", "assigned_to"]
  }'
```

## 15. How The Web App Should Use It

The web app should not directly embed Relationship API secrets.

Recommended flow:

- User opens the dashboard
- UI requests a TanStack server function
- Server function checks Supabase auth and RBAC
- Server function calls the Relationship API using private credentials
- Server function returns safe, filtered data to the UI

This keeps the browser thin and secure.

For example:

- `/app/incidents/:id` can ask the backend for linked incidents
- `/app/map` can ask for relationship-enriched entity clusters
- `/app/admin/organisations/:id` can ask for organization graph context

## 16. Webhooks And Event Delivery

The Relationship API should support outbound webhooks or event delivery when relationships change.

Typical event types:

- `relationship.created`
- `relationship.updated`
- `relationship.deleted`
- `entity.created`
- `entity.updated`
- `entity.merged`

Webhook payload should include:

- Event ID
- Event type
- Timestamp
- Organization ID
- Entity IDs
- Changed fields
- Correlation ID

Consumers should:

- Verify signatures
- Reject duplicates
- Retry safely
- Store the last processed event ID

## 17. Caching Strategy

Relationship queries can become expensive because graph traversal can fan out quickly.

Suggested caching layers:

- Redis for hot graph reads
- Short-lived API response cache for repeated lookups
- Client-side cache only for non-sensitive read data

Cache keys should include:

- Organization ID
- Entity ID
- Query depth
- Relationship types
- Permission scope

Example:

```text
relationships:org_123:entity_inc_123:depth_2:assigned_to,located_in
```

## 18. Supabase, SQL, And Storage

If the Relationship API uses Supabase as its system of record, the data model should be normalized and queryable.

Suggested storage split:

- Supabase tables for canonical entities and relationships
- Redis for hot caches and query acceleration
- Blob storage for attachments, snapshots, or exported graph bundles

Typical tables:

- `entities`
- `relationships`
- `relationship_events`
- `entity_aliases`
- `entity_attributes`
- `graph_snapshots`

If large JSON snapshots or precomputed graphs are needed, store them in blob storage and keep only metadata and pointers in SQL.

## 19. Idempotency And Retries

All write endpoints should support idempotency.

Why this matters:

- Mobile and flaky network clients may resend the same request
- Webhooks may retry
- Background jobs may replay an event

Recommended behavior:

- Same idempotency key + same payload = same result
- Same idempotency key + different payload = reject with conflict
- Safe retry on 5xx or timeout

## 20. Error Handling

The API should return structured errors.

Example:

```json
{
  "ok": false,
  "error": {
    "code": "RELATIONSHIP_NOT_FOUND",
    "message": "The requested relationship does not exist.",
    "request_id": "9f3c0e1d-7f33-4d7f-9b2d-9bc57a6a6c91"
  }
}
```

Suggested codes:

- `UNAUTHORIZED`
- `FORBIDDEN`
- `NOT_FOUND`
- `VALIDATION_ERROR`
- `CONFLICT`
- `RATE_LIMITED`
- `UPSTREAM_ERROR`
- `RELATIONSHIP_NOT_FOUND`
- `ENTITY_NOT_FOUND`

## 21. Pagination And Filtering

Large graph APIs should never return everything by default.

Support:

- Cursor pagination
- Limit/offset for simple screens
- Sort order
- Type filters
- Status filters
- Confidence filters
- Time range filters

Example:

```http
GET /v1/relationships?org_id=org_123&entity_id=inc_123&limit=50&cursor=eyJvZmZzZXQiOjUwfQ==
```

## 22. Security Rules

The Relationship API should apply these rules consistently:

- Never leak cross-organization data
- Never trust client-side role claims alone
- Require explicit scope for sensitive relationship types
- Sanitize metadata before persistence
- Audit every write
- Preserve request correlation IDs
- Sign webhooks

## 23. Operational Observability

Every request should be observable.

Track:

- Request ID
- Caller identity
- Organization ID
- Query depth
- Response time
- Error rate
- Cache hit rate
- Retry count

This is especially important for graph queries because they can become slow as data grows.

## 24. How To Use This Smoothly In Practice

If you are building a new app or API on top of the Relationship API:

1. Define the entity types you will use
2. Define the relationship types you need
3. Choose the source of truth for each entity
4. Decide which changes will be pushed immediately
5. Decide which changes will be synced in the background
6. Put service credentials only on the backend
7. Use idempotency keys for all writes
8. Cache reads that are expensive or frequently repeated
9. Emit events when graph state changes
10. Keep browser code on the read-only, permission-filtered path

## 25. Recommended Integration Pattern For Lemtik

The cleanest architecture for this platform is:

- TanStack React UI
- TanStack server functions for browser requests
- Supabase auth and database for identity and core records
- Relationship API for graph and link operations
- Redis for hot graph cache
- Blob storage for large relationship snapshots and attachments

This gives you:

- Dynamic data
- Lower coupling
- Easier RBAC enforcement
- Better caching
- Clear service boundaries

## 26. Short Version

If another API or application needs to use the Relationship API:

- Authenticate with a service token or signed JWT
- Send requests over HTTPS
- Scope every request to an organization
- Use `POST` or `PATCH` for graph changes
- Use `GET` or query endpoints for lookups
- Cache read-heavy results in Redis where appropriate
- Store large artifacts in blob storage
- Keep browser clients behind backend validation

