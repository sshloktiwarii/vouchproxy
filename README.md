# VouchProxy

VouchProxy is a loopback proxy that injects host-scoped credentials and scrubs sensitive identifiers from outbound HTTP and HTTPS traffic emitted by AI coding agents, subprocesses, and Model Context Protocol (MCP) servers.

Instead of granting agent processes access to plaintext API keys or `.env` files, VouchProxy runs the agent in an environment containing only dummy tokens (such as `VP_OPENAI_API_KEY_DUMMY_8f9a2b`). When the agent issues an outbound request, VouchProxy intercepts the traffic, validates the destination host against a local policy, swaps the dummy token for the real secret in memory, redacts configured PII patterns, and forwards the request to the upstream API.

---

## How It Works

```
+-----------------------------------------------------------------------------------+
| Host Workstation                                                                  |
|                                                                                   |
|  [Child Agent Process]                          [VouchProxy Loopback Daemon]      |
|  - Injected env:                                - Listen on 127.0.0.1:<port>      |
|    HTTP_PROXY=http://session:<token>@127.0.0.1  - Validate Proxy-Authorization    |
|    OPENAI_API_KEY=VP_OPENAI_KEY_DUMMY_...       - Mint leaf cert via local CA     |
|                                                                                   |
|         |                                                      |                  |
|         | 1. HTTP/HTTPS request with dummy token               |                  |
|         +----------------------------------------------------->|                  |
|                                                                |                  |
|                                                    2. Inspect request             |
|                                                       - Check session token (407) |
|                                                       - Check SNI == Host header  |
|                                                       - Match host in vouch.yaml  |
|                                                       - Swap dummy -> real secret |
|                                                       - Redact emails/usernames   |
|                                                                |                  |
|                                                    3. Egress to upstream          |
|                                                       +--------+                  |
+-------------------------------------------------------|--------|------------------+
                                                        |        v
                                                        |  [Upstream API]
                                                        |  api.openai.com
                                                        v
                                          [Local Storage (0600)]
                                          - vault.enc (Argon2id + AES-256-GCM)
                                          - audit.jsonl / SQLite ledger
```

1. **Process Supervision**: VouchProxy spawns the agent as a child process inside a dedicated process group (POSIX) or Job Object (Windows). It injects proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`), the custom root CA certificate path (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`), and dummy tokens mapped from the vault.
2. **Session Authentication**: The proxy binds strictly to `127.0.0.1` on an ephemeral port. Each run generates a random 32-byte secret required in the `Proxy-Authorization` header. Requests lacking this credential receive `HTTP 407 Proxy Authentication Required`.
3. **TLS Interception**: For HTTPS connections, VouchProxy handles the HTTP `CONNECT` tunnel and mints on-the-fly leaf certificates signed by a local Root CA generated during `init`. Leaf certificates use ECDSA P-256 and are cached in memory.
4. **Host-Scoped Credential Swap**: When a request matches a configured rule in `vouch.yaml`, VouchProxy retrieves the real secret from the encrypted in-memory vault and substitutes the dummy token in the designated header or payload.
5. **Leak Prevention**: If an agent transmits a dummy token to an unauthorized host or unmapped endpoint, VouchProxy aborts the request with `HTTP 403 Forbidden` and logs the event. Real secrets are never transmitted to unauthorized destinations.
6. **PII and Identifier Scrubbing**: Configured request headers, URL parameters, and request bodies are filtered against regex rules to remove workstation usernames, system hostnames, and email addresses before network egress.
7. **SSRF Defense**: Outbound dialers resolve upstream hosts and reject destinations pointing to private IPv4/IPv6 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback addresses (`127.0.0.0/8`), link-local blocks, and cloud metadata endpoints (`169.254.169.254`).
8. **Memory Management**: Secret bytes are decrypted only when needed for upstream dispatch, stored in dedicated byte slices, and wiped using explicit memory zeroing loops (`crypto/subtle` and byte clearing) to prevent plaintext secrets from remaining in runtime memory.

---

## Security Invariants

| Invariant | Implementation | Enforcement Action |
|:---|:---|:---|
| **Loopback Binding** | Proxy listens exclusively on `127.0.0.1` with dynamic port assignment. | Abort startup if interface is non-loopback. |
| **Session Isolation** | Cryptographically random 32-byte token per supervisor execution. | Return `HTTP 407` on missing or invalid proxy auth. |
| **Leak Mitigation** | Scans request headers, query strings, and bodies for dummy tokens. | Return `HTTP 403` if token target is not in policy allowlist. |
| **Host Header Integrity** | Verifies matching between `CONNECT` host, TLS SNI, and `Host` header. | Terminate connection on mismatch to prevent DNS rebinding. |
| **Storage Security** | Local files (`ca.key`, `vault.enc`) require strict `0600` permissions. | Refuse startup if permissions permit group or world access. |
| **Process Tree Cleanup** | Monitors parent process and binds children to OS process groups. | Terminate all descendant processes when supervisor exits. |
| **Sanitized Audit Log** | Audit system writes only hashes, domain names, and scrub counts. | Strict typing prevents raw secret values from reaching loggers. |

---

## Installation

### Prerequisites
- Go 1.23 or newer
- Operating system: Linux (`amd64`, `arm64`), macOS (`amd64`, `arm64`), or Windows (`amd64`)

### Build from Source
```bash
git clone https://github.com/sshloktiwarii/vouchproxy.git
cd vouchproxy
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o bin/vouchproxy ./cmd/vouchproxy
```

Copy the compiled binary into your system `PATH`:
```bash
sudo install -m 0755 bin/vouchproxy /usr/local/bin/vouchproxy
```

---

## Configuration

VouchProxy reads its configuration from `~/.vouchproxy/vouch.yaml` (or `./vouch.yaml`).

```yaml
version: "1.0"

settings:
  strict_mode: false            # Reject unconfigured outbound hosts with HTTP 502
  proxy_auth_required: true     # Require per-session Proxy-Authorization token
  mitm_cache_size: 256          # Maximum cached leaf certificates
  connect_timeout_seconds: 15
  request_timeout_seconds: 60

scrubbing:
  emails: true                  # Redact RFC 5322 email addresses
  usernames:                    # Redact local system identifiers
    - "$USER"
    - "$HOSTNAME"
  custom_regex:
    - name: "Internal-IPv4"
      pattern: '\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b'
      replacement: "[INTERNAL_IP_REDACTED]"

rules:
  - name: "OpenAI API"
    host: "api.openai.com"
    match_type: "exact"
    headers:
      - name: "Authorization"
        format: "Bearer {{secret}}"
        secret: "OPENAI_API_KEY"
        dummy_match: "VP_OPENAI_API_KEY_DUMMY_*"
    allowed_methods: ["POST", "GET"]

  - name: "Anthropic API"
    host: "api.anthropic.com"
    match_type: "exact"
    headers:
      - name: "x-api-key"
        format: "{{secret}}"
        secret: "ANTHROPIC_API_KEY"
        dummy_match: "VP_ANTHROPIC_API_KEY_DUMMY_*"
    allowed_methods: ["POST", "GET"]

  - name: "GitHub API"
    host: "api.github.com"
    match_type: "exact"
    headers:
      - name: "Authorization"
        format: "Bearer {{secret}}"
        secret: "GITHUB_TOKEN"
        dummy_match: "VP_GITHUB_TOKEN_DUMMY_*"
    allowed_methods: ["GET", "POST", "PUT", "DELETE", "PATCH"]
```

---

## Usage

### 1. Initialize Enclave
Generate the Root CA key pair, set up the master passphrase, and create the configuration directory:
```bash
vouchproxy init
```
This creates:
- `~/.vouchproxy/ca.crt` and `~/.vouchproxy/ca.key` (`0600` permissions)
- `~/.vouchproxy/vault.enc` (encrypted with Argon2id and AES-256-GCM)
- `~/.vouchproxy/vouch.yaml`

### 2. Manage Credentials
Add secrets to the encrypted vault:
```bash
vouchproxy secret set OPENAI_API_KEY
vouchproxy secret set ANTHROPIC_API_KEY
vouchproxy secret set GITHUB_TOKEN
```

List registered keys and their associated dummy tokens:
```bash
vouchproxy secret list
```

### 3. Run Commands Under the Proxy
Execute commands with automatic proxy injection and dummy environment variables:
```bash
vouchproxy run -- aider --model sonnet
```

Run test requests with curl:
```bash
vouchproxy run -- curl -i -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
```

### 4. Audit Log Inspection
View outbound requests, dummy substitutions, and scrubbing actions:
```bash
# View the latest entries in real time
vouchproxy audit --tail

# Filter audit entries by host
vouchproxy audit --tail --host api.openai.com

# Emit JSON records for ingestion
vouchproxy audit --json --limit 50
```

### 5. Canary Leak Detection
Generate canary tokens to detect context prompt leakage or model exfiltration attempts:
```bash
# Generate a tracked canary token for a session
vouchproxy canary generate --prompt-id "prompt-refactor-auth"

# List active canaries
vouchproxy canary list

# Inspect canary trigger logs
vouchproxy canary audit
```

### 6. Model Context Protocol (MCP) Wrapper
Wrap standalone MCP servers (over stdio or HTTP-SSE) to sanitize tool calls and prevent credentials from entering context logs:
```bash
vouchproxy mcp wrap -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

---

## Testing

Run unit and integration tests with the race detector enabled:
```bash
go test -v -race ./...
```

Run package-specific tests:
```bash
go test -v ./internal/vault
go test -v ./internal/proxy
go test -v ./internal/policy
go test -v ./internal/certs
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
