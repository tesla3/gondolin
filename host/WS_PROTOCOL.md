# WebSocket Exec Protocol (POC)

The host controller exposes a WebSocket API for streaming exec requests to the sandbox VM.

## Transport
- **WebSocket:** text frames carry JSON control messages.
- **Binary frames:** carry stdout/stderr output.

## JSON control messages

### Client → Server

#### `exec`
```json
{
  "type": "exec",
  "id": 1,
  "cmd": "echo",
  "argv": ["hello"],
  "env": ["KEY=VALUE"],
  "cwd": "/",
  "stdin": false
}
```

#### `stdin`
```json
{
  "type": "stdin",
  "id": 1,
  "data": "base64-encoded-bytes",
  "eof": true
}
```

#### `lifecycle`
```json
{
  "type": "lifecycle",
  "action": "restart"
}
```

### Server → Client

#### `status`
```json
{ "type": "status", "state": "running" }
```

#### `exec_response`
```json
{ "type": "exec_response", "id": 1, "exit_code": 0 }
```

#### `error`
```json
{ "type": "error", "id": 1, "code": "duplicate_id", "message": "request id already in use" }
```

## Binary output frames

Binary frames carry stdout/stderr chunks.

```
+---------+-----------+-------------------+
| u8 tag  | u32 id    | data bytes        |
+---------+-----------+-------------------+
```

- `tag = 1` for stdout
- `tag = 2` for stderr
- `id` is the request id in big-endian order
