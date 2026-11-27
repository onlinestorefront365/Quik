# agent-tool-middleware

Security middleware that sits between an LLM agent and its tools. Every tool call the model emits is treated as untrusted and passes through a fixed pipeline:

1. **Audit and budget**: per-session tool-call cap (circuit breaker) and an audit log line per call.
2. **Schema validation**: unknown tools rejected; arguments parsed with strict Pydantic models (`extra="forbid"` stops injected fields like `tenant_id`).
3. **RBAC**: role to `resource:action` permission check.
4. **ABAC ownership**: row-level tenant and owner check against your database, before any approval ticket is created.
5. **Risk gate**: static plus per-call dynamic risk tiers; HIGH and CRITICAL calls pause for human approval. Approvals are bound to a hash of tenant, user, tool and exact arguments, and are single-use.

## Quickstart

```bash
pip install -e ".[dev]"
pytest
python examples/demo.py
```

## Production notes

- `InMemoryApprovalStore` is for local development only. Use `RedisApprovalStore` (TTL-bound, atomic single-use consumption via Lua) for anything multi-process.
- `webhooks.build_approval_router` exposes an HMAC-SHA256-signed endpoint for approval decisions. It refuses to start without `APPROVAL_WEBHOOK_SECRET` (or an explicit `webhook_secret`).
- Copy `.env.example` and set real values.

## Approval semantics

- Approval hash covers tenant, user, tool and exact arguments (not session). The requesting `session_id` is stored on the ticket and enforced atomically when the grant is consumed, so another session cannot claim it.
- Grants are single-use. Create, decide and consume are each one Lua script on Redis (`RedisApprovalStore`).
- A rejected ticket keeps blocking the identical payload until the TTL expires; changing any argument creates a new ticket.
- `allow_self_approval=False` (default) refuses a reviewer who is the requesting user. The reviewer ID comes from the HMAC-authenticated approval app, so this does not protect against a compromised approval service.
- Scripts need single-node Redis or Sentinel (not Cluster without shared hash tags).
- Tests run on `fakeredis[lua]`; set `REDIS_URL` to run the same suite against a real Redis.
