# Master AI API

This document explains how the Lemtik Security Relationship API, or any other internal application, can connect to the Master AI service and use it safely.

## Purpose

Master AI is the orchestration brain for incident handling.
It does not replace the other services. It decides what data is needed, reasons over the collected data, and returns a structured recommendation panel.

Typical flow:

1. An application receives or creates an incident.
2. It sends the incident to `POST /triage`.
3. Master AI returns a job manifest describing which services to call.
4. The caller executes those jobs against the relevant services.
5. The caller sends the combined results to `POST /synthesise`.
6. Master AI returns a recommendation panel.
7. The caller presents the panel to an operator or pushes selected actions onward.

The combined one-shot alternative is `POST /process`.

---

## Base URL

In production, the service is exposed as a normal HTTP API:

```text
http(s)://<host>:<port>
```

The Render deployment uses `uvicorn app:app --host 0.0.0.0 --port $PORT`.

For local development, the default port is `8000`.

---

## Authentication

All write and session-read endpoints require the internal API key.

Send:

```http
X-Internal-Key: <INTERNAL_API_KEY>
```

If the key is missing or wrong, the service returns `401`.

The health endpoint does not require authentication.

---

## Endpoints

### `GET /health`

Returns service health, database status, and Groq/Relationship API connectivity checks.

Use this to verify the service is alive before wiring it into a Relationship API or dashboard.

Example:

```bash
curl -s http://localhost:8000/health
```

Example response:

```json
{
  "status": "success",
  "service": "masterai",
  "environment": "production",
  "groq": {
    "configured": false,
    "reachable": false,
    "model": "llama-3.3-70b-versatile"
  },
  "relationship_api": {
    "configured": false,
    "reachable": false
  },
  "database": {
    "status": "success",
    "database": "sqlite",
    "path": "/Users/abdulsemiuamisu/Desktop/Lemtik Security/Internalservices/masterai/masterai.db"
  }
}
```

---

### `POST /triage`

Use this endpoint for the first pass over a raw incident.

It converts unstructured incident text into:

- incident type
- urgency
- severity
- confidence
- job manifest
- whether human verification is required

#### Request

```http
POST /triage
Content-Type: application/json
X-Internal-Key: <INTERNAL_API_KEY>
```

```json
{
  "request_type": "agent_triage",
  "request_id": "req_agent_001",
  "org_id": "org_abc123",
  "incident_raw": {
    "description": "Customer called in. Man being stabbed in the toilet. North West Wing Floor 3. Suspect still on premises. One victim down.",
    "reported_by": "Front Desk Operator",
    "location_stated": "North West Wing Floor 3",
    "building": "Eko Hotel",
    "floor": 3,
    "zone": "north_west_wing",
    "lat": 6.4281,
    "lng": 3.4219,
    "timestamp": "2026-06-17T12:00:00Z",
    "source": "operator_log"
  },
  "org_context": {
    "org_type": "hotel",
    "location_name": "Eko Hotel",
    "area": "Victoria Island"
  }
}
```

#### Response

```json
{
  "request_id": "req_agent_001",
  "status": "success",
  "step": "triage",
  "triage": {
    "incident_type": "assault_with_weapon",
    "severity": 4,
    "urgency": "immediate",
    "armed_threat": true,
    "suspect_on_premises": true,
    "victim_count": 1,
    "victim_status": "injured",
    "location_confirmed": true,
    "location_indoor": true,
    "confidence": 91,
    "flags": ["weapon_involved", "suspect_contained", "medical_needed"]
  },
  "jobs_needed": [
    {
      "service": "osint_brain",
      "priority": 1,
      "parameters": { }
    }
  ],
  "confidence": 91,
  "requires_human_verification": false
}
```

The exact job parameters are generated dynamically from the incident context.

#### What callers should do next

After `/triage`, the caller should:

1. Read `jobs_needed`
2. Call the listed downstream services in parallel
3. Collect their results
4. Send the combined package to `POST /synthesise`

---

### `POST /synthesise`

Use this endpoint after upstream service calls have completed.

It combines:

- OSINT results
- proximity results
- inventory status
- route calculator results
- autonomous scan results

and returns a commander-ready panel.

#### Request

```http
POST /synthesise
Content-Type: application/json
X-Internal-Key: <INTERNAL_API_KEY>
```

```json
{
  "request_type": "agent_synthesise",
  "request_id": "req_agent_001",
  "org_id": "org_abc123",
  "incident": {
    "id": "INC-2024-001",
    "type": "assault_with_weapon",
    "severity": 4,
    "description": "Man being stabbed in the toilet. North West Wing Floor 3. Suspect still on premises.",
    "location": "North West Wing Floor 3, Eko Hotel",
    "triage": {
      "incident_type": "assault_with_weapon",
      "severity": 4,
      "urgency": "immediate",
      "armed_threat": true,
      "suspect_on_premises": true,
      "victim_count": 1,
      "victim_status": "injured",
      "location_confirmed": true,
      "location_indoor": true,
      "confidence": 91,
      "flags": ["weapon_involved", "suspect_contained", "medical_needed"]
    }
  },
  "service_results": {
    "osint_brain": { "status": "success", "data": {} },
    "proximity_finder": { "status": "success", "data": {} },
    "inventory_check": { "status": "success", "data": {} },
    "route_calculator": { "status": "success", "data": {} },
    "autonomous_scan": { "status": "success", "data": {} }
  }
}
```

#### Response

```json
{
  "request_id": "req_agent_001",
  "status": "success",
  "step": "synthesis",
  "panel": {
    "panel_type": "incident_response",
    "incident_id": "INC-2024-001",
    "generated_at": "2026-06-17T12:00:01Z",
    "confidence": 89,
    "situation_summary": "Active assault with weapon on Floor 3 North West Wing.",
    "threat_assessment": { }
  },
  "tokens_used": 1840,
  "model": "llama-3.3-70b-versatile",
  "latency_ms": 1200
}
```

---

### `POST /process`

Use this when the caller wants a single endpoint.

This endpoint supports three modes:

1. incident triage only
2. synthesis only
3. custom non-incident processing

If `incident_raw` and `org_context` are present, the service performs triage.
If `incident` and `service_results` are present, it performs synthesis.
If the payload describes a routine report, OSINT alert, or inventory alert, the service returns the appropriate structured panel directly.

#### Example

```http
POST /process
Content-Type: application/json
X-Internal-Key: <INTERNAL_API_KEY>
```

```json
{
  "request_type": "osint_alert",
  "request_id": "req_agent_005",
  "org_id": "org_abc123",
  "alert_type": "osint",
  "message": "High confidence signals of planned protest near Lekki Phase 1 in next 48 hours."
}
```

---

### `GET /session/{id}`

Returns the stored session record for a request.

Useful for:

- retries
- audit trails
- debugging
- replaying a decision

Example:

```bash
curl -s \
  -H "X-Internal-Key: $INTERNAL_API_KEY" \
  http://localhost:8000/session/req_agent_001
```

---

## How Relationship API Should Use It

This is the normal operational sequence.

### 1. Receive an incident

Relationship API gets the incident from:

- dashboard input
- officer report
- sensor event
- OSINT feed
- inventory alert

### 2. Call triage

Relationship API sends the raw incident to `POST /triage`.

### 3. Execute jobs in parallel

Relationship API reads `jobs_needed` and fans out calls to:

- OSINT Brain
- Proximity Finder
- Inventory Service
- Route Calculator
- Autonomous Control

### 4. Synthesize

Relationship API sends the combined response package to `POST /synthesise`.

### 5. Return to operator

Relationship API returns the panel to the dashboard.

### 6. Optional follow-up

If the operator approves actions, Relationship API or its downstream services can execute them.

---

## How This Service Can Send to Relationship API

The core design is Relationship API -> Master AI -> downstream services -> Master AI.

However, this service also includes a lightweight client in [`relationship_client.py`](./relationship_client.py) for cases where Master AI needs to call a deployed Relationship API instance directly.

That client uses:

- `RELATIONSHIP_API_URL`
- `RELATIONSHIP_API_KEY`

It can:

- check Relationship API health
- POST payloads to `/triage`
- POST payloads to `/synthesise`
- POST payloads to `/process`

Example usage:

```python
from relationship_client import RelationshipAPIClient, RelationshipAPISettings

client = RelationshipAPIClient(
    RelationshipAPISettings(
        base_url="https://relationship.example.com",
        api_key="secret-key",
        timeout_seconds=5.0,
    )
)

status = client.health()
result = client.submit_triage(payload)
```

Important:

- The client is optional.
- The service does not require it for normal operation.
- It is there so the integration can be automated when needed.

---

## Error Handling

Expected failure modes:

- `400` invalid JSON or invalid payload shape
- `401` missing or invalid internal key
- `404` unknown endpoint or missing session
- `500` unexpected internal error

For model-backed requests, if Groq is unavailable, the service falls back to heuristic reasoning rather than failing hard.

---

## Local Testing

Run the local test suite from the `masterai` directory:

```bash
python3 -m unittest discover -s . -p 'test_*.py'
```

The tests cover:

- health
- triage
- synthesis
- low-confidence triage
- routine reports
- OSINT alerts
- inventory alerts
- threat-report-only OSINT behavior
- route calculation request generation

---

## Notes For Integrators

- Always send `X-Internal-Key`.
- Use `/triage` first unless you already have a full service result bundle.
- Prefer `/process` only when one-call orchestration is simpler for your application.
- Keep payloads JSON-only.
- Do not assume the model will invent missing fields.
- Treat `confidence < 60` as a partial answer.
- Treat `confidence < 30` as a rejection and ask the operator to restate the incident.

