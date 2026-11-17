# Safely capturing a legacy workflow

This software is for requests you are already authorized to make. It does not grant permission to access a system.

## Before capture

1. Confirm that the system owner permits automation and that your account may perform the workflow.
2. Use a dedicated test account and non-production records when possible.
3. Open browser developer tools, select the Network panel, clear existing traffic, and enable HAR recording only for the shortest necessary workflow.
4. Do not capture login, password entry, MFA, account recovery, payment, administration or unrelated browsing.

## Export and import

Export the network log as HAR, then import it from your backend:

```bash
curl http://localhost:4242/v1/workflows/import-har \
  -H 'Authorization: Bearer your-server-key' \
  -H 'Content-Type: application/json' \
  --data-binary @<(jq -n --arg name 'Create test record' --slurpfile har capture.har '{name:$name,har:$har[0]}')
```

The importer removes authorization/cookie headers, user info in URLs, sensitive query parameters, sensitive JSON keys and hop-by-hop headers. It rejects multi-origin captures and captures longer than 50 requests. This is defense in depth, not a guarantee: inspect the original and generated definition yourself, then securely delete the HAR because browser exports commonly contain secrets.

## Parameterize and review

Publish a reviewed definition with placeholders such as `{{inputs.record_id}}` or `{{steps.step_1.extracted.csrf}}`. Each step contains:

```json
{
  "id": "step_1",
  "request": { "method": "GET", "path": "records/{{inputs.record_id}}" },
  "assert": { "status": [200] },
  "extract": { "record_name": "data.name" }
}
```

Review write methods especially carefully. The runtime does not automatically retry writes. Keep workflows small, deterministic and idempotent where possible.

## Session connection

Prefer an official OAuth/API integration whenever available. For a legacy portal, the user can manually enter a session cookie through a short-lived connect page. The project does not collect usernames, passwords or MFA codes and does not refresh legacy sessions automatically. When the session expires, reconnect manually.
