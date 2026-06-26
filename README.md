# raphael-admin

User/policy/billing/security/compliance administration

## API

- Prefix: `/v1/admin`
- Port: `8104`
- Health: `GET /health`

## Events

_Published and consumed events documented in `openapi.yaml` and raphael-contracts._

## Development

```bash
uv sync
uv run uvicorn raphael_admin.app:app --reload --port 8104
```

Part of the [Raphael Platform](https://github.com/hummingbird-labs) by HummingBird Labs.
