# Controlled Application

This is the minimal application used by the controlled comparative
experiment. It has no production purpose and contains no real credentials.

The application exposes a health endpoint and reads its configuration from
environment variables. The clean control and F01 fixture intentionally differ
by one source-level change so that the pipeline comparison remains controlled.

## Run locally

```bash
cd clean
node src/server.js
```

Then check:

```bash
curl http://127.0.0.1:3000/health
```

Expected response:

```json
{"status":"ok"}
```

## Fixture layout

- `clean/` is a complete secure-control checkout.
- `F01-secret/` is a complete checkout containing the synthetic
  detector-compatible secret fixture.

The value in the F01 fixture is deliberately fake and must never be replaced
with a real credential.
