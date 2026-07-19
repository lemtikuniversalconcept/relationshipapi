# Lemtik OSINT API

This service is the OSINT layer only. It collects, filters, classifies, summarizes, queues work, and returns intelligence to another application.

Use `baseapiurl` as the deployed Render URL, for example:

```text
baseapiurl=https://your-render-service.onrender.com
```

## Authentication

API auth is optional in local mode, but for Render you should set `LEMTIK_API_KEYS`.

Send:

```text
X-API-Key: your-long-random-key
```

If you do not set keys, the service stays open.

## Required Render Env

Set these in Render:

```bash
LEMTIK_STORAGE=supabase
SUPABASE_DB_URL=postgresql://postgres:<password>@db.<project-ref>.supabase.co:5432/postgres
SUPABASE_SSLMODE=require
POSTGRES_CONNECT_TIMEOUT=8
POSTGRES_POOL_MIN=1
POSTGRES_POOL_MAX=5
LEMTIK_DEFAULT_ORG_ID=default
LEMTIK_API_KEYS=your-long-random-key:default:admin:local-admin
RESEND_API_KEY=re_your_resend_api_key
LEMTIK_BRIEF_EMAIL_FROM=briefs@your-domain.com
LEMTIK_BRIEF_EMAIL_TO=client@example.com
LEMTIK_ALERT_EMAIL_FROM=alerts@your-domain.com
LEMTIK_ALERT_EMAIL_TO=security-manager@example.com
LEMTIK_ALERT_WORKER_INTERVAL_SECONDS=60
LEMTIK_ALERT_RETRY_MINUTES=15
LEMTIK_DASHBOARD_CACHE_SECONDS=30
```

Optional NLP toggles if you do not install the heavier NLP packages on Render:

```bash
LEMTIK_ENABLE_SPACY=0
LEMTIK_ENABLE_TRANSFORMERS=0
```

## Core Endpoints

Health:

```bash
GET baseapiurl/health
GET baseapiurl/nlp/status
GET baseapiurl/brain/diagnostics
GET baseapiurl/brain/source-plan
```

OSINT query:

```bash
POST baseapiurl/brain/query
POST baseapiurl/intel/packet
POST baseapiurl/tasking/resolve
```

Collection:

```bash
POST baseapiurl/collect
POST baseapiurl/sources/{id}/collect
GET  baseapiurl/sources
```

Briefs and alerts:

```bash
GET  baseapiurl/briefs?org_id=default&days=7
POST baseapiurl/briefs/generate
POST baseapiurl/alerts/dispatch
GET  baseapiurl/alerts/worker
POST baseapiurl/alerts/worker/start
POST baseapiurl/alerts/worker/stop
```

Queued work:

```bash
POST baseapiurl/brain/tasks
GET  baseapiurl/brain/tasks
GET  baseapiurl/brain/tasks/item/{task_id}
GET  baseapiurl/brain/tasks/worker
POST baseapiurl/brain/tasks/worker/start
POST baseapiurl/brain/tasks/worker/stop
```

## Example Requests

Brain query:

```bash
curl -s "$baseapiurl/brain/query" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-long-random-key" \
  -d '{
    "org_id": "default",
    "question": "What do you know about robbery around Lekki Phase 1?",
    "location": "Lekki Phase 1",
    "lookback_days": 180,
    "recent_limit": 10
  }'
```

Queue a repair collection task:

```bash
curl -s "$baseapiurl/brain/tasks" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-long-random-key" \
  -d '{
    "org_id": "default",
    "task_type": "repair",
    "extra_keywords": "",
    "priority": 8
  }'
```

Collect from a single source:

```bash
curl -s "$baseapiurl/sources/1/collect" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-long-random-key" \
  -d '{"org_id":"default","extra_keywords":"lagos"}'
```

## Typical Responses

`/brain/query` returns:

```json
{
  "query": "What do you know about robbery around Lekki Phase 1?",
  "intent": "intel",
  "classification": {},
  "entities": {},
  "packet": {},
  "source_health": {},
  "operations": {},
  "source_rollup": [],
  "latest_brief": {},
  "dashboard": {},
  "recommended_action": "monitor",
  "risk_rating": "Green"
}
```

`/brain/tasks` returns a queued task object with `status` set to `Pending`, `Running`, `Completed`, or `Failed`.

## Call Pattern

1. Your other application calls `baseapiurl/brain/query` or `baseapiurl/brain/tasks`.
2. The OSINT service returns a structured packet.
3. Your other application decides what to do with that response.
4. The OSINT service does not own inventory, officers, traffic control, or command authorization.
