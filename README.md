# Relationship API

Dispatcher service for Lemtik Security.

## Run

```bash
npm install
npm run build
npm start
```

## Main env

- `PORT`
- `NODE_ENV`
- `JWT_SECRET`
- `DATABASE_URL`
- `RELATIONSHIP_API_KEYS`
- `RELATIONSHIP_ALLOW_DEV_AUTH`
- `WEBHOOK_SECRET`
- `RELATIONSHIP_WEBHOOK_URLS`
- `AUDIT_LOG_PATH`
- `OSINT_BRAIN_URL`
- `AI_ANALYSIS_URL`
- `QWEN_URL`
- `QWEN_API_URL`
- `MAIN_AGENT_URL`
- `AUTONOMOUS_CONTROL_URL`
- `INVENTORY_SERVICE_URL`
- `PROXIMITY_URL`
- `ROUTE_CALCULATOR_URL`
- `SUPABASE_URL`
- `SUPABASE_SERVICE_KEY`
- `REDIS_URL`
- `BLOB_STORAGE_URL`
- `BLOB_STORAGE_KEY`
- `BLOB_STORAGE_CONTAINER`
- `RESEND_API_KEY`

## Notes

- Public readiness endpoints: `/health` and `/api/v1/health`
- Primary API prefix: `/api/v1`
- Audit events are appended to `data/audit-log.jsonl`
- Upstream service failures fall back to degraded local responses
- `/ai/analyze-incident`, `/ai/process-radio`, and `/ai/recommend-response` proxy to Qwen when configured and fall back to heuristics when it is not
- Graph endpoints live under `/v1/entities`, `/v1/relationships`, and `/v1/graph/query`
- Internal inventory alerts can be posted to `/internal/inventory-alert`
