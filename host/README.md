# Host Controller

This package contains the host-side CLI and WebSocket controller for the sandbox VM.

## Dependencies
- `ws`: required to expose the WebSocket exec API and stream stdout/stderr. The runtime footprint is acceptable for the host controller service.
- `@types/ws`: dev-only typings for TypeScript.
