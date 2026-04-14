# NARIP: Frontend ↔ Backend integration (REST only)

NARIP exposes **HTTP/JSON REST** and **OpenAPI** only (no GraphQL, no WebSockets). Poll or batch where you previously might have streamed.

## 1. Base URL and OpenAPI

- Run the API: set `PYTHONPATH` to the `backend` folder, then `uvicorn narip.main:app --port 8080`.
- **OpenAPI:** `GET http://localhost:8080/openapi.json`
- **Swagger UI:** `http://localhost:8080/docs`
- CORS is open in development; tighten `allow_origins` in `narip/main.py` for production.

```text
VITE_NARIP_API_URL=http://localhost:8080
```

## 2. Risk scoring (enterprise 0–100)

**Single event:**

```http
POST /v1/risk/score
Content-Type: application/json
```

Body: `UnifiedScoreRequest` (optional `email`, `transaction`, `flows`, `otp`, `account`, `supply`).

**Many events in one request (dashboard / batch jobs):**

```http
POST /v1/risk/score/batch
Content-Type: application/json
```

```json
{
  "items": [
    { "email": { "message_id": "1", "sender": "a@b.com", "subject": "", "body_text": "" } },
    {}
  ]
}
```

Returns an array of `UnifiedRiskResponse` in the same order.

**Default snapshot (no body — good for home widgets):**

```http
GET /v1/risk/snapshot
```

## 3. Incidents & pub/sub history (REST polling)

Whenever the API publishes (e.g. high-risk score, workforce assessment), messages are kept in a ring buffer.

```http
GET /v1/incidents/recent?limit=50
GET /v1/incidents/recent?limit=100&topic_prefix=workforce.
GET /v1/incidents/recent?topic_prefix=incident.
```

Response: `[{ "topic": "...", "payload": { ... } }, ...]` newest first.

**Workforce-only shortcut:**

```http
GET /v1/workforce/events/recent?limit=50
```

## 4. Phishing module (content-only)

```http
POST /v1/detect/phishing
```

Body: `EmailEvent`.

## 5. Role-aware phishing & training gap

- `POST /v1/workforce/profiles` — upsert employee (department + title → role cluster).
- `GET /v1/workforce/profiles/{employee_id}`
- `POST /v1/workforce/phishing/assess` — personalized risk + training gap.
- `POST /v1/workforce/phishing/simulation` — simulation outcomes.
- `GET /v1/workforce/dashboard/summary`
- `GET /v1/workforce/roles/taxonomy`
- `GET /v1/workforce/audit/logs?limit=100&category=phishing`

Taxonomy file: `backend/narip/data/roles/taxonomy.yaml`.

## 6. SIEM / EDR ingest

- `POST /v1/ingest/falcon/event`
- `POST /v1/ingest/splunk/hec` (optional `Authorization: Splunk <token>` if `NARIP_SPLUNK_HEC_TOKEN` is set)
- `GET /v1/automation/cases`

## 7. Suggested UI architecture

| Screen | REST endpoints |
|--------|----------------|
| Executive risk | `GET /v1/risk/snapshot` or `POST /v1/risk/score` |
| High-volume tiles | `POST /v1/risk/score/batch` |
| Live-ish feed | Poll `GET /v1/incidents/recent` (or `GET /v1/workforce/events/recent`) every few seconds |
| Phishing queue | `POST /v1/workforce/phishing/assess`, `POST /v1/detect/phishing` |
| Training planner | `GET /v1/workforce/dashboard/summary`, `GET /v1/workforce/roles/taxonomy` |
| Employee 360 | `GET /v1/workforce/profiles/{id}`, `GET /v1/workforce/audit/logs` |

## 8. Auth and production

- Add **API gateway** or **reverse proxy** auth in front of the service.
- Use **HTTPS** everywhere.
- Forward `audit_reference` and incident payloads to Splunk/Elastic with a small forwarder calling `GET /v1/incidents/recent` on an interval or after POSTs.
