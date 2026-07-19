# Lemtik Security — Relationship API Specification
### Central Nervous System of the C4I Platform
**Classification:** Internal Engineering
**Version:** 1.0
**Status:** Pre-Build Specification

---

## 1. What This Service Is

The Relationship API is the single communication layer that sits
between every internal Lemtik service and the outside world.
No service talks directly to another service. Every request,
every data exchange, every command goes through here.

It does not store intelligence. It does not run AI models.
It does not scrape anything. It does not control hardware.

It does one thing — route the right data to the right service
at the right time, with the right authentication, in the right format.

Think of it as the human dispatcher in a control room. It knows
every officer, every resource, every open channel. When something
happens it knows exactly who to call and what to tell them.

---

## 2. Position in the Full Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    EXTERNAL FACING                          │
│           SOD / C4I Dashboard (frontend)                    │
│           Mobile Officer App                                │
│           Partner Integrations                              │
└──────────────────────────┬──────────────────────────────────┘
                           │ all external requests
┌──────────────────────────▼──────────────────────────────────┐
│              RELATIONSHIP API (this service)                │
│                                                             │
│  — Authentication & authorisation gateway                   │
│  — Service registry (knows every internal service)          │
│  — Request routing (knows where to send what)               │
│  — Data contract enforcement (validates all I/O)            │
│  — Response assembly (combines outputs from multiple        │
│    services into one response)                              │
│  — Audit logging (every request logged permanently)         │
│  — Rate limiting and abuse prevention                       │
└───┬──────────────┬──────────────┬──────────┬───────────────┘
    │              │              │          │              
┌───▼───┐    ┌─────▼────┐  ┌─────▼───┐ ┌───▼──────────────┐
│ OSINT │    │    AI    │  │  MAIN   │ │   AUTONOMOUS     │
│ BRAIN │    │ ANALYSIS │  │  AGENT  │ │   CONTROL        │
│       │    │ ENGINE   │  │         │ │   LAYER          │
│Render │    │ Render   │  │ Render  │ │   Render         │
└───────┘    └──────────┘  └─────────┘ └──────────────────┘
    │              │              │          │
└───┴──────────────┴──────────────┴──────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│              SHARED DATA LAYER (Supabase)                   │
│   Intelligence DB │ Operational DB │ Inventory DB           │
│   Officer DB      │ Audit Logs     │ Decision Logs          │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Core Responsibilities

### 3.1 Authentication Gateway
Every request that enters the Relationship API must be authenticated.
The API issues and validates tokens. Internal services never handle
auth themselves — they trust that if the Relationship API forwarded
a request, it has already been authenticated.

Authentication methods supported:
- JWT bearer tokens (SOD dashboard users)
- API keys (service-to-service communication)
- Webhook signatures (incoming partner integrations)

What the Relationship API does NOT do:
- Store user passwords (those live in Supabase Auth)
- Handle registration or login UI (that is the SOD's job)
- Manage sessions (stateless JWT only)

### 3.2 Service Registry
The Relationship API maintains a registry of every internal service:
where it lives, what it accepts, what it returns, and whether it
is currently healthy.

```
Service Registry (environment config):

OSINT_BRAIN_URL         = https://lemtik-osint-brain.onrender.com
AI_ANALYSIS_URL         = https://lemtik-ai-analysis.onrender.com
MAIN_AGENT_URL          = https://lemtik-main-agent.onrender.com
AUTONOMOUS_CONTROL_URL  = https://lemtik-autonomous.onrender.com
inventory services url = https://lemtik-inventory.onrender.com
proximity url = https://lemtik-proximity.onrender.com
route calculator url = https://lemtik-routecalculator.onrender.com

```

If a service is down, the Relationship API handles the failure
gracefully — returns partial data, queues the request, or returns
a clear error. The SOD never crashes because one internal service
is unavailable.

### 3.3 Request Routing
The Relationship API knows what data each request needs and which
service or services can provide it. A single request from the SOD
may trigger calls to multiple internal services, with the
Relationship API assembling the combined response.

### 3.4 Data Contract Enforcement
Every service has a defined input schema and output schema.
The Relationship API validates that data going into a service
matches its expected input, and that data coming out matches
its expected output. If a service returns malformed data,
the Relationship API catches it before it reaches the SOD.

### 3.5 Audit Logging
Every request logged permanently:
- Who made the request (user ID, org ID, role)
- What was requested (endpoint, parameters)
- Which internal services were called
- What was returned
- Timestamp, latency, success or failure

This is non-negotiable for a security platform. Every action
must be traceable.

---

## 4. Service Contracts

These are the agreed data formats between the Relationship API
and each internal service. These are defined here and never
changed without updating this document first.

IMPORTANT: The internal implementation of each service is
not defined here. How the OSINT brain stores data, how it
scrapes, how it classifies — that is the OSINT brain's
internal concern. What IS defined here is exactly what the
Relationship API sends to it and exactly what it expects back.

---

### 4.1 OSINT Brain Contract

What the Relationship API sends to OSINT Brain:

```json
{
  "request_type": "intelligence_query",
  "request_id": "req_abc123",
  "query": {
    "area": "Lekki Phase 1",
    "radius_km": 5,
    "days_back": 30,
    "categories": ["Physical", "Cyber", "Political", "Macro"],
    "severity_min": 1,
    "limit": 50,
    "include_heatmap": true,
    "incident_context": {
      "type": "robbery",
      "keywords": ["armed", "robbery", "bikes"]
    }
  }
}
```

What the Relationship API expects back from OSINT Brain:

```json
{
  "request_id": "req_abc123",
  "status": "success",
  "data": {
    "intelligence_items": [
      {
        "id": "LEM-OSINT-0001",
        "summary": "string",
        "category": "Physical",
        "severity": 4,
        "confidence": 92,
        "location": "Lekki Phase 1",
        "lat": 6.4281,
        "lng": 3.4219,
        "source": "Channels TV",
        "collected_at": "ISO8601 timestamp",
        "verified": "Partial",
        "matched_keywords": ["robbery", "gunmen"],
        "entities": {
          "locations": [],
          "weapons": [],
          "vehicles": []
        }
      }
    ],
    "heatmap": {
      "area": "Lekki Phase 1",
      "incident_density": 0.87,
      "hotspots": [
        {
          "zone": "string",
          "lat": 0.0,
          "lng": 0.0,
          "incident_count": 0,
          "dominant_type": "string"
        }
      ],
      "historical_pattern": {
        "robbery_frequency": "high",
        "typical_time": "evening",
        "typical_weapons": ["guns", "knives"],
        "escape_routes_used": ["Lekki-Epe Expressway"]
      }
    },
    "area_risk_score": 78,
    "risk_trend": "increasing"
  },
  "meta": {
    "total_items": 50,
    "query_time_ms": 120
  }
}
```

---

### 4.2 AI Analysis Engine Contract

What the Relationship API sends to AI Analysis Engine:

```json
{
  "request_type": "incident_analysis",
  "request_id": "req_def456",
  "incident": {
    "id": "INC-2024-001",
    "type": "robbery",
    "severity": 4,
    "description": "3 armed robbers, 2 motorbikes, 1 shot fired, 1 injured",
    "location": {
      "name": "Lekki Phase 1",
      "lat": 6.4281,
      "lng": 3.4219,
      "address": "string"
    },
    "reported_at": "ISO8601 timestamp",
    "reporter_id": "string"
  },
  "context": {
    "osint_data": {},
    "inventory": {},
    "available_officers": [],
    "client_type": "estate"
  }
}
```

What the Relationship API expects back from AI Analysis Engine:

```json
{
  "request_id": "req_def456",
  "status": "success",
  "analysis": {
    "threat_assessment": {
      "threat_level": "high",
      "confidence": 91,
      "reasoning": "string",
      "armed": true,
      "estimated_suspects": 3,
      "escape_likelihood": "high",
      "similar_past_incidents": 7
    },
    "response_recommendation": {
      "officers_needed": 6,
      "armed_required": true,
      "vehicles_needed": 2,
      "response_urgency": "immediate",
      "estimated_response_time_minutes": 8,
      "special_instructions": "string"
    },
    "resource_requirements": {
      "officers": {
        "count": 6,
        "armed": true,
        "recommended_ids": []
      },
      "vehicles": {
        "count": 2,
        "type": "patrol_car",
        "recommended_ids": []
      },
      "weapons": {
        "type": "standard_firearms",
        "heavy_required": false
      },
      "fuel_check_required": true
    },
    "autonomous_actions_recommended": [
      {
        "action": "traffic_light_override",
        "reason": "Clear route for response vehicles",
        "requires_approval": true,
        "approval_level": "supervisor"
      },
      {
        "action": "cctv_activate",
        "zone": "Lekki Phase 1 perimeter",
        "reason": "Track escape route",
        "requires_approval": false
      }
    ]
  }
}
```

---

### 4.3 Main AI Agent Contract

What the Relationship API sends to Main AI Agent:

```json
{
  "request_type": "agent_task",
  "request_id": "req_ghi789",
  "task_type": "incident_dispatch",
  "raw_input": {
    "source": "distress_call",
    "content": "Robbery at Lekki Phase 1 Gate A, 3 armed men, 2 bikes, shot fired",
    "caller_id": "string",
    "location_confirmed": true,
    "location": {
      "name": "string",
      "lat": 0.0,
      "lng": 0.0
    }
  },
  "available_services": [
    "osint_brain",
    "ai_analysis",
    "autonomous_control"
  ],
  "constraints": {
    "autonomous_actions_require_approval": true,
    "max_response_time_seconds": 30,
    "approval_officer_id": "string"
  }
}
```

What the Relationship API expects back from Main AI Agent:

```json
{
  "request_id": "req_ghi789",
  "status": "success",
  "agent_output": {
    "jobs_executed": [
      {
        "job": "osint_query",
        "status": "complete",
        "result_summary": "string"
      },
      {
        "job": "inventory_check",
        "status": "complete",
        "result_summary": "string"
      },
      {
        "job": "officer_positioning",
        "status": "complete",
        "result_summary": "string"
      },
      {
        "job": "route_calculation",
        "status": "complete",
        "result_summary": "string"
      }
    ],
    "dispatch_plan": {
      "incident_id": "string",
      "officers_dispatched": [],
      "vehicles_assigned": [],
      "route": {},
      "eta_minutes": 0,
      "autonomous_actions_pending_approval": []
    },
    "summary_for_commander": "string",
    "confidence": 0,
    "requires_human_approval": true,
    "approval_items": []
  }
}
```

---

### 4.4 Autonomous Control Layer Contract

What the Relationship API sends to Autonomous Control:

```json
{
  "request_type": "autonomous_action",
  "request_id": "req_jkl012",
  "action": {
    "type": "traffic_light_override",
    "target_id": "TL-LEKKI-042",
    "command": "green_corridor",
    "route_ids": ["ROUTE-001"],
    "duration_seconds": 300,
    "reason": "Emergency response vehicle corridor",
    "incident_id": "INC-2024-001"
  },
  "authorisation": {
    "approved_by": "officer_id",
    "approval_timestamp": "ISO8601",
    "approval_level": "supervisor"
  },
  "constraints": {
    "auto_revert_after_seconds": 300,
    "revert_on_incident_resolved": true,
    "max_override_duration_seconds": 600
  }
}
```

What the Relationship API expects back:

```json
{
  "request_id": "req_jkl012",
  "status": "executed",
  "action_result": {
    "target_id": "TL-LEKKI-042",
    "command_sent": true,
    "confirmed": true,
    "executed_at": "ISO8601",
    "revert_scheduled_at": "ISO8601",
    "confirmation_source": "device_ack"
  }
}
```

---

## 5. API Endpoints

All endpoints prefixed: /api/v1/
Auth header required: Authorization: Bearer {jwt_token}

### 5.1 Intelligence
```
GET  /intelligence              — Query OSINT brain for items
GET  /intelligence/heatmap      — Heatmap for an area
GET  /intelligence/risk-score   — Risk score for an area
GET  /intelligence/brief/:org   — Latest generated brief
```

### 5.2 Incidents
```
POST  /incidents                — Log new incident + trigger AI
GET   /incidents/:id            — Full incident + analysis + plan
PATCH /incidents/:id/status     — Update status
POST  /incidents/:id/analyse    — Trigger AI analysis
POST  /incidents/:id/dispatch   — Execute approved dispatch plan
```

### 5.3 Agent
```
POST /agent/process             — Send raw input to main agent
GET  /agent/jobs/:request_id    — Check in-progress job status
POST /agent/approve/:request_id — Human approval for pending actions
```

### 5.4 Inventory
```
GET /inventory/officers         — Available officers + positions
GET /inventory/vehicles         — Vehicles + fuel + availability
GET /inventory/weapons          — Weapons inventory (supervisor+)
GET /inventory/summary          — Quick resource summary
```

### 5.5 Autonomous Control
```
POST /autonomous/action         — Execute autonomous action (supervisor+)
GET  /autonomous/status/:id     — Current device status
POST /autonomous/revert/:id     — Manual revert (supervisor+)
GET  /autonomous/active         — All active overrides
```

### 5.6 System
```
GET /health                     — All services health
GET /health/:service            — Single service health
GET /audit-log                  — Query audit log (admin only)
```

---

## 6. Parallel Service Calls

When a full incident dispatch is triggered, all data services
are called simultaneously to minimise response time.

```python
async def handle_incident_dispatch(incident, request_id):

    osint_task = asyncio.create_task(
        call_osint_brain({"area": incident["location"]["name"],
                          "incident_context": incident}, request_id)
    )

    inventory_task = asyncio.create_task(
        call_inventory({"area": incident["location"]["name"]}, request_id)
    )

    osint_result, inventory_result = await asyncio.gather(
        osint_task, inventory_task, return_exceptions=True
    )

    analysis = await call_ai_analysis({
        "incident": incident,
        "context": {
            "osint_data": osint_result.get("data"),
            "inventory": inventory_result.get("data")
        }
    }, request_id)

    return analysis
```

Total response time = slowest single service, not sum of all.

---

## 7. Failure Handling

```
OSINT Brain down
→ Continue with inventory + officer data only
→ Flag: "Intelligence unavailable — reduced confidence"

AI Analysis Engine down
→ Return raw data to SOD
→ Flag: "AI offline — manual dispatch required"

Autonomous Control down
→ Queue autonomous actions
→ Alert supervisor: manual override required

Main Agent down
→ Fall back to direct service calls
→ SOD presents raw panels to human commander
```

---

## 8. Autonomous Action Constraints

Every autonomous action passes a constraint check before execution.
No action executes without passing all constraints.

```
traffic_light_override  → supervisor approval + active incident + max 600s
smart_gate_lock         → manager approval + active incident + max 1800s
elevator_hold           → supervisor approval + active incident + max 300s
cctv_activate           → no approval needed + active incident + max 3600s
cctv_track              → supervisor approval + active incident + logged critical
```

All autonomous actions:
- Auto-revert when incident resolved
- Permanently logged with who authorised and why
- Cannot be executed without a linked active incident ID

---

## 9. Tech Stack

```
Runtime:    Node.js 20+ TypeScript
Framework:  Fastify
Validation: Zod
HTTP:       Axios with retry
Auth:       jsonwebtoken
Logging:    Winston → Supabase audit table
Cache:      Upstash Redis
Hosting:    Railway or Render
Cost:       $5–$7/month
```

---

## 10. Environment Variables

```env
OSINT_BRAIN_URL=
AI_ANALYSIS_URL=
MAIN_AGENT_URL=
AUTONOMOUS_CONTROL_URL=

OSINT_BRAIN_INTERNAL_KEY=
AI_ANALYSIS_INTERNAL_KEY=
MAIN_AGENT_INTERNAL_KEY=
AUTONOMOUS_CONTROL_INTERNAL_KEY=

SUPABASE_URL=
SUPABASE_SERVICE_KEY=
JWT_SECRET=
JWT_EXPIRY=15m
REDIS_URL=
ALLOWED_ORIGINS=
NODE_ENV=production
PORT=3000
```

---

## 11. What This Document Does Not Define

Intentionally left open for each service team:
- How OSINT brain scrapes or classifies internally
- How AI engine runs its models internally
- How autonomous layer communicates with hardware
- How SOD structures its UI
- Internal schemas of each service

Only the boundary contract is defined here.
Everything inside each service is that service's own concern.

---

*Version 1.0 — Lemtik Security Engineering*
*Central nervous system. Get this right before building anything else.*
*All service contracts are living agreements. Update this doc when any contract changes.*