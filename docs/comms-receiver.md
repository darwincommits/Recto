# Receiving Recto's lifecycle events

Recto's `comms` dispatcher POSTs lifecycle events (`child.spawn`,
`child.exit`, `restart.attempt`, `max_attempts_reached`,
`run.final_exit`) to whatever URL the YAML's `comms[].url` names.
Most consumer services don't already have a "receive Recto events"
endpoint; they'll need to add one. This doc spells out the
convention so every service does it the same way.

## Convention

**Endpoint.** `POST /api/recto/events` on the consumer service.

**Method.** POST with `Content-Type: application/json`.

**Body.** The full JSON record Recto emits to stdout for every
lifecycle event:

```json
{
  "ts": "2026-04-26T10:00:00+00:00",
  "service": "myservice",
  "kind": "child.exit",
  "ctx": {
    "returncode": 0,
    "healthz_signaled": false
  }
}
```

`ts` is ISO-8601 UTC; `service` is the YAML's `metadata.name`; `kind`
is one of the lifecycle event names; `ctx` is event-specific context
(see ARCHITECTURE.md or the launcher source for the full set).

**Headers.** Whatever auth the consumer's other internal endpoints
already use. The Recto YAML's `comms[].headers` block is
template-interpolated at dispatch time, so secrets sit in
Credential Manager and only the rendered headers ever travel:

```yaml
comms:
  - type: webhook
    url: https://myservice.example.com/api/recto/events
    headers:
      X-Auth-Token: "${env:WEBHOOK_TOKEN}"
      CF-Access-Client-Id: "${env:CF_ACCESS_CLIENT_ID}"
      CF-Access-Client-Secret: "${env:CF_ACCESS_CLIENT_SECRET}"
```

`WEBHOOK_TOKEN` etc. live in `spec.secrets:` and are fetched from
CredMan at every spawn.

**Response.** Recto's dispatcher doesn't care -- any 2xx is "ok",
anything else gets logged as `comms.dispatch_failed` and the
launcher keeps running. The consumer SHOULD return 204 (no content)
to signal "received, nothing to say" or 200 with an empty JSON body.

**Idempotency.** Recto does not retry failed POSTs. If the
consumer needs at-least-once semantics, it can deduplicate on
`(service, kind, ts)` -- those three together are unique per event
within a single launcher run.

## Reference handler (Python stdlib)

Drop into the consumer's repo as e.g. `recto_events_handler.py`.
Wire into your existing HTTP routing layer however you do it
(here shown as a standalone `http.server` for clarity).

```python
"""Minimal /api/recto/events receiver. Validates auth + appends to a log."""

from __future__ import annotations

import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logger = logging.getLogger("recto-events")

# Token shared with Recto via spec.comms[].headers.X-Auth-Token.
# In production, read from a vault or env var the consumer trusts.
EXPECTED_TOKEN = os.environ["RECTO_WEBHOOK_TOKEN"]


class RectoEventsHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/api/recto/events":
            self.send_error(404)
            return
        # Auth.
        if self.headers.get("X-Auth-Token") != EXPECTED_TOKEN:
            self.send_error(403, "invalid X-Auth-Token")
            return
        # Body.
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 64 * 1024:
            self.send_error(400, "missing or oversized body")
            return
        try:
            event = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError):
            self.send_error(400, "malformed JSON")
            return
        # Validate the shape.
        for required in ("ts", "service", "kind", "ctx"):
            if required not in event:
                self.send_error(400, f"missing field: {required!r}")
                return
        # Process. Replace this with whatever your service needs:
        # write to DB, push to Slack, fan out to other consumers, etc.
        logger.info(
            "recto event service=%s kind=%s ts=%s ctx=%s",
            event["service"], event["kind"], event["ts"], event["ctx"],
        )
        # 204 No Content -- recto's dispatcher doesn't care about the body.
        self.send_response(204)
        self.end_headers()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    srv = ThreadingHTTPServer(("127.0.0.1", 8000), RectoEventsHandler)
    logger.info("listening on 127.0.0.1:8000")
    srv.serve_forever()
```

## nginx + Cloudflare Access

If you front the consumer with nginx + Cloudflare Tunnel + CF Access
(the recommended pattern for the operator's stack), add the
endpoint as a location block and let CF Access enforce the auth
layer Recto can't see:

```nginx
location /api/recto/events {
    # CF Access service-token validation happens upstream of nginx.
    # Inside this block we trust the request was authenticated.
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header X-Real-IP $remote_addr;
    # POST body forwarded as-is.
    proxy_pass_request_body on;
    proxy_set_header X-Auth-Token $http_x_auth_token;
}
```

In Recto's YAML, the `comms[].headers` block then sets the CF
Access service-token headers Recto needs to traverse the tunnel:

```yaml
comms:
  - type: webhook
    url: https://myservice.example.com/api/recto/events
    headers:
      CF-Access-Client-Id: "${env:CF_ACCESS_CLIENT_ID}"
      CF-Access-Client-Secret: "${env:CF_ACCESS_CLIENT_SECRET}"
      X-Auth-Token: "${env:WEBHOOK_TOKEN}"
```

## Caddy variant

Same idea, simpler config:

```caddy
myservice.example.com {
    @recto path /api/recto/events
    reverse_proxy @recto 127.0.0.1:8000
}
```

If Caddy is also doing auth (basic auth, JWT validation, etc.),
configure it on the `@recto` matcher.

## What NOT to do

- **Don't echo the request body back in the response.** Recto's
  dispatcher reads the response only to determine the HTTP status;
  the body is discarded. But your nginx access log probably captures
  it, and event ctx may contain values you'd rather not log
  (returncodes are fine, but custom ctx keys could be sensitive).
- **Don't block on slow downstream work.** If `/api/recto/events`
  takes longer than a few seconds, Recto's dispatcher will time out
  the POST and log `comms.dispatch_failed`. The launcher keeps
  running, but you've lost that event. Push slow work to a queue
  and respond fast.
- **Don't ignore `kind`.** Treat unknown kinds gracefully (log and
  204) rather than 400'ing -- Recto may add new kinds in future
  versions and you don't want a forward-compat hazard.
- **Don't auto-reply with email/Slack/PagerDuty from inside the
  handler synchronously.** Same reason as above. Queue and ack.
