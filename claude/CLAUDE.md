# Sandboxed Environment

You are running in a sandboxed environment with filesystem and network restrictions.

## Filesystem

Access is restricted to directories in your current context (the working directory and any directories added via `/add-dir`). Attempts to access files outside these folders will be denied.

## Network

All HTTP/HTTPS requests are filtered by a policy. Requests that don't match the policy will return a 403 error - this is expected behavior, not a bug.
