# Autonomous Control Layer API

This document explains how the Relationship API, or any other approved application, connects to the Autonomous Control Layer, calls its endpoints, and receives results back.

The Autonomous Control Layer is the execution layer only.
It does not decide actions.
It receives approved commands, validates them, executes them against connected devices, records the audit trail, and returns structured results to the caller.

---

## 1. Who This API Is For

Primary caller:
- Relationship API

Secondary callers:
- Internal admin tools
- Device registry tooling
- Monitoring or audit systems

The service is protected.
It is not intended for public access.

---

## 2. Connection Model

The Relationship API connects over HTTPS to the deployed service base URL.

Example:

```text
https://<your-render-service>.onrender.com
```

All requests are JSON over HTTP.

Typical flow:

1. Relationship API receives an AI-approved action.
2. It formats the request to `/execute`.
3. It includes the approval context and the incident ID.
4. The Autonomous Control Layer validates the request.
5. The service executes the device command through the correct adapter.
6. The service returns success, failure, or unconfirmed status.
7. The Relationship API stores or forwards the result to the rest of the system.

---

## 3. Authentication

Every request must include the internal API key header:

```http
X-Internal-API-Key: <INTERNAL_API_KEY>
```

The service rejects requests without the correct key.

Optional network restriction:
- If `RELATIONSHIP_API_IPS` is configured, the service only accepts requests from those source IP addresses.

Example environment configuration:

```env
INTERNAL_API_KEY=your-secret-key
RELATIONSHIP_API_IPS=10.0.0.10,10.0.0.11
```

---

## 4. Main Request Flow

The Relationship API should use this sequence:

1. Create or identify the incident.
2. Confirm the operator approval level.
3. Call `POST /execute`.
4. Read the response.
5. If the response contains `auto_revert_scheduled`, track the override ID and expiry.
6. If the action needs manual rollback, call `POST /revert/{override_id}`.
7. Query `GET /overrides/active` or `GET /log` when needed.

The service returns a complete execution record every time.

---

## 5. Execute Action

### Endpoint

```http
POST /execute
```

### Purpose

Executes an approved autonomous action against a specific device.

### Request Body

```json
{
  "request_type": "execute_action",
  "request_id": "req_auto_001",
  "org_id": "org_abc123",
  "action": {
    "action_key": "elevator_hold",
    "device_id": "ELEV-EKO-002",
    "parameters": {
      "floor": 0,
      "duration_seconds": 300,
      "reason": "Officer dispatch to Floor 3 incident"
    }
  },
  "authorisation": {
    "approved_by": "user_supervisor_001",
    "approval_timestamp": "2026-06-18T12:00:00Z",
    "approval_level": "supervisor",
    "incident_id": "INC-2024-001"
  }
}
```

### Fields

- `request_type`
  - Should usually be `execute_action`.
- `request_id`
  - Unique ID for correlation and audit.
- `org_id`
  - Tenant or organization identifier.
- `action.action_key`
  - Logical action name such as `open`, `elevator_hold`, `green_corridor`.
- `action.device_id`
  - Device registry ID.
- `action.parameters`
  - Action-specific parameters.
- `authorisation.approved_by`
  - Identity of the approving user.
- `authorisation.approval_level`
  - `supervisor` or `manager` depending on the action.
- `authorisation.approval_timestamp`
  - ISO 8601 timestamp of approval.
- `authorisation.incident_id`
  - Required for autonomous actions.

### Success Response

```json
{
  "request_id": "req_auto_001",
  "status": "success",
  "data": {
    "action_log_id": "uuid",
    "device_id": "ELEV-EKO-002",
    "device_name": "Main Elevator Block B",
    "action_key": "elevator_hold",
    "execution_result": "success",
    "adapter_used": "REST_API",
    "executed_at": "2026-06-18T12:00:01Z",
    "confirmed": true,
    "auto_revert_scheduled": true,
    "revert_at": "2026-06-18T12:05:01Z",
    "revert_action": "release",
    "warnings": [],
    "active_override_id": "uuid"
  }
}
```

### Failure Response

```json
{
  "request_id": "req_auto_001",
  "status": "failed",
  "error": "Approval required from: supervisor",
  "data": {
    "approval_required": true,
    "approval_level": "supervisor",
    "pending": true
  }
}
```

### Execution Notes

- The service validates incident linkage before execution.
- Approval is checked against the constraint registry.
- If the device does not support the action, the request is rejected.
- If the adapter fails, the response includes the adapter error.
- If the command is queued or unconfirmed, the caller should not assume the physical action completed until the service confirms it.

---

## 6. Revert Active Override

### Endpoint

```http
POST /revert/{override_id}
```

### Purpose

Manually reverts an active override before its scheduled expiry.

### Example

```http
POST /revert/3f1fd7a3-2c19-4a4b-9e6a-4fa3f4c49c55
```

### Response

```json
{
  "override_id": "3f1fd7a3-2c19-4a4b-9e6a-4fa3f4c49c55",
  "status": "success",
  "data": {
    "success": true,
    "adapter": "REST_API",
    "response": {
      "result": "ok"
    }
  }
}
```

Use this when:
- An incident is resolved early.
- The operator wants immediate rollback.
- A supervisor wants to cancel a temporary override.

---

## 7. Active Overrides

### Endpoint

```http
GET /overrides/active
```

### Purpose

Returns all currently active or unconfirmed overrides.

### Use Cases

- Relationship API dashboard view
- Monitoring
- Cleanup workflows
- Manual review of still-active actions

### Optional Query

```http
GET /overrides/active?org_id=org_abc123
```

---

## 8. Devices

### List Devices

```http
GET /devices
```

Returns all registered devices visible to the service.

### Get One Device

```http
GET /devices/{device_id}
```

Returns a single device record.

### Register Device

```http
POST /devices
```

Use this to add a device to the registry.

### Update Device

```http
PUT /devices/{device_id}
```

Use this to update connection details, supported actions, or metadata.

### Device Status

```http
GET /devices/{device_id}/status
```

Returns the current stored status and latest known command state.

### Device Record Shape

```json
{
  "id": "ELEV-EKO-002",
  "org_id": "org_abc123",
  "name": "Main Elevator Block B",
  "type": "smart_elevator",
  "connection_type": "REST_API",
  "supported_actions": ["hold_at_floor", "release", "get_status"],
  "status": "online"
}
```

Connection details are redacted in API responses.
Secrets are stored encrypted at rest and never returned in full.

---

## 9. Hardware Bridges

### List Bridges

```http
GET /bridges
```

### Register Bridge

```http
POST /bridges
```

### Get Bridge

```http
GET /bridges/{bridge_id}
```

### Update Bridge

```http
PUT /bridges/{bridge_id}
```

Bridge registry is used for legacy and on-site gateway infrastructure.

---

## 10. Logs

### Endpoint

```http
GET /log
```

### Purpose

Returns the action audit log.

### What the Relationship API Gets

- Action log ID
- Device ID
- Incident ID
- Approval information
- Adapter used
- Result
- Error data if any
- Auto-revert timestamps

This log is the canonical execution record for the service.

---

## 11. Incident Resolve Flow

### Endpoint

```http
POST /incident/resolved
```

### Purpose

Signals that an incident is resolved so all active overrides linked to it can be reverted.

### Example

```json
{
  "incident_id": "INC-2024-001"
}
```

### Behavior

1. The service finds all active overrides for that incident.
2. It sends revert commands.
3. It updates the override status.
4. It returns a summary of the results.

The Relationship API should call this when the incident lifecycle ends.

---

## 12. Health Endpoints

### Service Health

```http
GET /health
```

Use this for readiness and monitoring.

Response includes:
- Service status
- Environment
- Device count
- Adapter connectivity status

### Bridge Health

```http
GET /health/bridges
```

Use this for bridge queue status and bridge connection visibility.

---

## 13. Error Handling

Always treat non-`success` responses as actionable errors.

Common classes of errors:

- Missing approval
- Invalid approval level
- No incident ID supplied
- Device not found
- Action not supported by device
- Adapter failure
- Device acknowledgement timeout
- Revert failure

Recommended handling:

1. Log the full response.
2. Surface the failure reason to the operator.
3. Do not assume the device changed state unless `confirmed` is true.
4. If `requires_manual_verification` is true, have a human verify the physical device.

---

## 14. How Another API Can Integrate

Any application can integrate with this service the same way the Relationship API does:

1. Obtain the internal API key.
2. Create or receive the incident ID.
3. Determine the device ID and action key.
4. Build the JSON payload.
5. Send `POST /execute`.
6. Parse the response.
7. Store `action_log_id` and `active_override_id` for later correlation.
8. Poll `GET /overrides/active`, `GET /devices/{id}/status`, or `GET /log` as needed.

This allows external orchestration tools, admin portals, or internal dashboards to use the same service safely.

---

## 15. Example Integration Pattern

### Relationship API to Autonomous Control Layer

```text
AI decision approved -> Relationship API
Relationship API validates request context
Relationship API calls POST /execute
Autonomous Control Layer executes device action
Autonomous Control Layer returns execution result
Relationship API stores result and continues workflow
```

### Manual Rollback

```text
Operator requests rollback
Relationship API calls POST /revert/{override_id}
Autonomous Control Layer executes revert action
Relationship API confirms rollback success
```

### Incident Resolution

```text
Incident closed
Relationship API calls POST /incident/resolved
Autonomous Control Layer reverts all active overrides for that incident
```

---

## 16. Important Rules for Callers

- Always send a valid `incident_id` for autonomous actions.
- Always send the correct approval level.
- Never send a command without an internal API key.
- Store the returned log and override IDs.
- Check `confirmed` before assuming hardware state changed.
- Use `revert` and `incident/resolved` to clean up active overrides.
- Do not expose this service publicly.

---

## 17. Base URLs and Deployment

If deployed on Render, the base URL is typically the Render web service URL.

Example:

```text
https://autonomouscontroller.onrender.com
```

The service should be configured with:

- `INTERNAL_API_KEY`
- `DATABASE_URL`
- `ENVIRONMENT=production`
- `RELATIONSHIP_API_IPS` if IP allowlisting is used

---

## 18. Summary

The Relationship API should treat the Autonomous Control Layer as the execution backend for approved physical actions.

It connects by:

- Authenticating with `X-Internal-API-Key`
- Sending JSON commands to `/execute`
- Reading back structured results
- Tracking overrides and logs
- Calling `/revert/{override_id}` or `/incident/resolved` when needed

That is the intended integration model for smooth, auditable, and repeatable use.

