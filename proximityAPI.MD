# Proximity & Officer Finder API

This document explains how another API or application connects to the Proximity & Officer Finder service, how the endpoints work, and how the Relationship API should use the output.

The short version:

- The Relationship API calls `POST /find`
- The service returns ranked responders as JSON
- The Relationship API consumes that JSON and forwards it to the Master Agent or dashboard layer
- Optional query logging is available through `GET /queries`

## Service Purpose

Proximity is an on-demand dispatch service.
It does not run continuously and it does not track resources by itself outside incident flow.

Its job is to answer a single operational question:

> Given an incident, which officers and vehicles are closest, available, and best fit to respond?

It returns:

- Ranked officers
- Ranked vehicles when requested
- Exclusion reasons
- Summary metadata
- Query timing metadata

## How It Connects To Relationship API

The Relationship API is the primary consumer.
It should act as the orchestration layer that decides when proximity scoring is needed.

### Normal request flow

1. An incident is logged in the dashboard or another upstream system.
2. The Relationship API receives or creates the incident context.
3. The Relationship API sends a `POST /find` request to Proximity.
4. Proximity calculates candidates and returns JSON.
5. The Relationship API reads the result and attaches it to the incident workflow.
6. The Relationship API returns the final operator-facing payload to the dashboard or forwards the result to the Master Agent.

### Important point

In the current implementation, Proximity does not push results to Relationship API by itself.
It returns the response to the caller.

That means:

- Relationship API initiates the call
- Relationship API receives the response
- Relationship API decides what to do next

This keeps the service simple, fast, and easy to orchestrate.

## Authentication

The service expects an internal service key.

Use this header on server-to-server calls:

```http
X-Internal-Key: <INTERNAL_API_KEY>
```

The same key should be configured in both services.

This is not end-user authentication.
It is internal trust between services.

## Base URL

When deployed, the API is available at the host you configure, for example:

```text
https://your-proximity-service.onrender.com
```

Local development usually uses:

```text
http://localhost:8000
```

## Endpoints

### `POST /find`

Main endpoint.
It finds and ranks responders for an incident.

Use this from Relationship API when an incident needs responders.

#### Request shape

```json
{
  "request_type": "find_responders",
  "request_id": "req_prox_001",
  "org_id": "org_abc123",
  "incident": {
    "id": "INC-2024-001",
    "type": "assault",
    "severity": 4,
    "description": "Man being stabbed, North West Wing Floor 3",
    "location": {
      "name": "North West Wing, Floor 3, Eko Hotel",
      "lat": 6.4281,
      "lng": 3.4219,
      "building_id": "BLDG-EKO-HOTEL",
      "floor": 3,
      "indoor": true
    },
    "requirements": {
      "officers_needed": 3,
      "armed_required": false,
      "certifications_preferred": ["first_aid", "tactical"],
      "vehicles_needed": 0,
      "priority": "immediate"
    }
  },
  "options": {
    "search_radius_km": 5,
    "max_candidates": 10,
    "include_vehicles": false,
    "request_eta_from_route_calculator": true
  }
}
```

#### What the caller should send

- `request_type`: must be `find_responders`
- `request_id`: unique request ID for tracing
- `org_id`: organisation scope
- `incident.id`: incident identifier
- `incident.location.lat` and `incident.location.lng`: required coordinates
- `incident.requirements`: dispatch requirements
- `options.search_radius_km`: optional search radius
- `options.max_candidates`: optional candidate cap
- `options.include_vehicles`: whether vehicles should be considered
- `options.request_eta_from_route_calculator`: whether to ask the route calculator for ETA refinement

#### What the service does

- Loads all on-shift officers for the organisation
- Filters out stale or unavailable resources
- Excludes officers already assigned to active incidents
- Filters candidates by bounding box and Haversine distance
- Scores candidates by distance and fit
- Optionally requests ETA data from the Route Calculator service
- Returns ranked responders

#### Example response

```json
{
  "request_id": "req_prox_001",
  "status": "success",
  "data": {
    "incident_id": "INC-2024-001",
    "search_radius_km": 5,
    "total_on_shift": 12,
    "total_candidates_found": 7,
    "recommended_officers": [
      {
        "rank": 1,
        "officer_id": "OFF-001",
        "name": "Ahmed Bello",
        "badge": "LG-0042",
        "contact": "+234XXXXXXXXXX",
        "status": "available",
        "armed": true,
        "weapon": "pistol",
        "certifications": ["armed_response", "first_aid"],
        "current_location": {
          "lat": 6.429,
          "lng": 3.423,
          "description": "Hotel Lobby",
          "last_updated": "ISO8601",
          "seconds_since_update": 45
        },
        "distance_metres": 180,
        "haversine_distance_metres": 165,
        "eta_seconds": 81,
        "eta_display": "1 min 21 sec",
        "route_type": "foot",
        "fit_score": 94,
        "fit_breakdown": {
          "distance_score": 100,
          "armed_match": true,
          "certifications_matched": ["first_aid"],
          "certifications_missing": [],
          "fatigue_flag": false,
          "hours_on_shift": 4.5
        },
        "recommendation_reason": "Closest officer, first aid certified, armed, 81s ETA"
      }
    ],
    "recommended_vehicles": [],
    "excluded_officers": [],
    "summary": {
      "fastest_responder": "OFF-001",
      "fastest_eta_seconds": 81,
      "officers_available_in_area": 7,
      "officers_recommended": 3,
      "all_requirements_met": true,
      "warnings": []
    }
  },
  "meta": {
    "query_time_ms": 210,
    "route_calculator_called": true,
    "candidates_sent_to_route_calculator": 5
  }
}
```

#### How Relationship API should use the response

The Relationship API should:

- Pick the officers and vehicles it wants to display or dispatch
- Use `recommended_officers` to populate the recommendation panel
- Use `excluded_officers` to explain why resources were not selected
- Use `summary.fastest_responder` and `summary.fastest_eta_seconds` for the top-line dispatch decision
- Use `meta.query_time_ms` for telemetry

If the Relationship API has a downstream workflow, it can forward the same JSON to the Master Agent or the dashboard layer.

### `GET /health`

Health check endpoint.

Use this for:

- Container readiness
- Dependency checks
- Monitoring dashboards

Example response:

```json
{
  "status": "ok",
  "service": "proximity",
  "environment": "production",
  "dependencies": {
    "database": {
      "status": "ok",
      "backend": "postgres",
      "database_connected": true
    },
    "route_calculator": true
  },
  "timestamp": "2026-06-18T10:00:00+00:00"
}
```

### `GET /queries`

Recent query log.

Use this for admin visibility and debugging.

It requires the same internal key.

Example:

```http
GET /queries?limit=20
X-Internal-Key: <INTERNAL_API_KEY>
```

The response returns recent request logs, including:

- Request ID
- Incident ID
- Search radius
- Candidate counts
- ETA availability
- Query time

## How Another API Or Application Connects

Any trusted internal service can use Proximity the same way Relationship API does.

### Minimal integration steps

1. Set `X-Internal-Key` in the request header.
2. Send a `POST /find` request with the incident payload.
3. Parse the JSON response.
4. Use the ranked list to drive UI, dispatch, or orchestration.

### Example `curl`

```bash
curl -X POST https://your-proximity-service.onrender.com/find \
  -H "Content-Type: application/json" \
  -H "X-Internal-Key: your-secret-key" \
  -d '{
    "request_type": "find_responders",
    "request_id": "req_001",
    "org_id": "org_abc123",
    "incident": {
      "id": "INC-2024-001",
      "location": {
        "lat": 6.4281,
        "lng": 3.4219,
        "indoor": true,
        "building_id": "BLDG-EKO-HOTEL",
        "floor": 3
      },
      "requirements": {
        "officers_needed": 3,
        "armed_required": false,
        "certifications_preferred": ["first_aid", "tactical"],
        "vehicles_needed": 0,
        "priority": "immediate"
      }
    },
    "options": {
      "search_radius_km": 5,
      "max_candidates": 10,
      "include_vehicles": false,
      "request_eta_from_route_calculator": false
    }
  }'
```

## How The Response Reaches Relationship API

This is the key integration pattern.

### Synchronous model

The Relationship API sends the request and waits for the response.

That means:

- Proximity does the ranking work
- Proximity returns JSON immediately
- Relationship API receives it in the same request cycle
- Relationship API uses that output to build the final operator experience

This is the simplest and most reliable pattern for the current build.

### Optional fan-out model

If you later want a push model, Relationship API can:

- Call `POST /find`
- Store the returned result
- Forward selected fields to other internal services
- Push the final response to the dashboard

That approach keeps Proximity unchanged.
The orchestration stays in Relationship API.

## Route Calculator Interaction

Proximity can optionally ask the Route Calculator for ETA refinement.

That happens internally when:

- `options.request_eta_from_route_calculator` is true
- `ROUTE_CALCULATOR_URL` is configured
- The service has candidates to enrich

Flow:

1. Proximity filters candidates locally
2. Proximity sends the top candidates to Route Calculator
3. Route Calculator returns ETAs and route distances
4. Proximity merges those values into the response
5. Relationship API receives the final ranked JSON

If Route Calculator is unavailable:

- Proximity still returns ranked results
- ETA values may be approximate or missing
- The response includes a warning

## Data Contract Notes

Relationship API should not assume every field is always present.

Recommended handling:

- Treat `eta_seconds` as optional
- Treat `recommended_vehicles` as optional unless `vehicles_needed > 0`
- Expect `excluded_officers` to contain operational reasons such as `location_stale` or `already_responding`
- Use `fit_score` for ordering, not as an absolute truth

## Operational Rules

- Only on-shift officers are considered
- Stale locations are excluded
- Officers already assigned to active incidents are excluded
- Indoor incidents prioritize officers already in the same building
- Proximity does not mutate incident state
- Relationship API remains the orchestrator

## Error Handling

Typical error responses are standard JSON errors.

Examples:

- `400` for malformed input
- `401` for invalid internal key
- `404` for unknown endpoints
- `500` for unexpected runtime failures

The caller should:

- Retry only transient failures
- Avoid retry storms
- Log `request_id` and `incident.id` for tracing

## Recommended Relationship API Pattern

The most stable integration is:

1. Receive incident
2. Build proximity payload
3. Call `POST /find`
4. Attach returned officers and vehicles to the dispatch record
5. Forward the result to the Master Agent or dashboard
6. Use `GET /queries` only for admin/debug views

## Summary

Proximity is a ranked responder lookup service.
Relationship API is the orchestrator that calls it.

So the integration is:

- Relationship API -> Proximity `/find`
- Proximity -> JSON response
- Relationship API -> Master Agent / dashboard / dispatch flow

That is the intended contract.
