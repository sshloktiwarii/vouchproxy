# VouchProxy

A lightweight local proxy that stops AI coding agents from seeing or leaking your real API keys.

Instead of putting live API keys in `.env` files or terminal environments where agents can read them, VouchProxy runs the agent with non-functional dummy tokens (e.g. `VP_OPENAI_KEY_DUMMY_...`). When the agent calls an authorized API, VouchProxy intercepts the request on loopback, swaps the dummy token for your real key in memory, and forwards the call. If the agent tries to send the token anywhere else, the request is blocked.

---

## Who Needs This

- **Developers using autonomous coding agents** (`claude-code`, `aider`, `cursor`, `gemini-cli`) that run terminal commands and inspect project files.
- **Engineers running MCP servers** where tool parameters or context logs could expose bearer tokens.
- **Teams preventing prompt injection exfiltration**, ensuring compromised agent instructions cannot send API credentials to third-party endpoints.

---

## Benchmarks & Numbers

Measured on Apple M-series (`darwin/arm64`):

| Metric | Measured Value |
|:---|:---|
| **Binary Size** | 7.7 MB (single static executable, zero CGO dependencies) |
| **Hot-Path Added Latency** | 0.039 ms (~40 microseconds per request) |
| **Idle Memory Usage** | < 12 MB RSS |
| **Throughput & Concurrency** | 500+ parallel requests tested with zero data races |
| **Startup Overhead** | < 15 ms to bind loopback, load vault, and launch child process |

---

## Quickstart

### 1. Install
```bash
git clone https://github.com/sshloktiwarii/vouchproxy.git
cd vouchproxy
go build -ldflags="-s -w" -trimpath -o vouchproxy ./cmd/vouchproxy
sudo install -m 0755 vouchproxy /usr/local/bin/
```

### 2. Set Up Your Vault
```bash
# Initialize local Root CA and encrypted vault (~/.vouchproxy)
vouchproxy init

# Store your real API keys in the local encrypted vault
vouchproxy secret set OPENAI_API_KEY
vouchproxy secret set ANTHROPIC_API_KEY
vouchproxy secret set GITHUB_TOKEN
```

### 3. Run Any Agent Under VouchProxy
```bash
# Run your coding agent — real keys are kept out of the agent's environment
vouchproxy run -- aider --model sonnet

# Or test with curl
vouchproxy run -- curl -i -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
```

### 4. Audit Traffic
```bash
# View intercepted requests and substitutions in real time
vouchproxy audit --tail
```

---

## Configuration (`vouch.yaml`)

Configuration resides at `~/.vouchproxy/vouch.yaml`.

```yaml
version: "1.0"

settings:
  strict_mode: false            # Block egress to hosts not defined in rules
  proxy_auth_required: true     # Require per-session bearer token from child
  mitm_cache_size: 500          # Number of generated TLS certs kept in memory
  connect_timeout_seconds: 15
  request_timeout_seconds: 60

canary:
  enabled: true                 # Detect decoy canary tokens in outbound payloads
  default_ttl: "24h"            # Expiry duration for minted tokens
  block_on_detect: true         # Block egress immediately when canary is detected

keyring:
  enabled: true                 # Secure vault master passphrase in OS keychain
  service: "vouchproxy"

system_trust:
  enabled: false                # Temporarily register Root CA into OS trust store

mcp:
  enabled: true                 # Filter stdio JSON-RPC tool calls and scrub arguments
  blocked_paths:
    - "/etc/shadow"
    - "~/.ssh"
    - "~/.aws"

scrubbing:
  emails: true                  # Redact email addresses from outbound requests
  usernames:                    # Redact local system identities
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
    allowed_methods: ["POST", "GET"]
    headers:
      - name: "Authorization"
        format: "Bearer {{secret}}"
        secret: "OPENAI_API_KEY"
        dummy_match: "VP_OPENAI_API_KEY_DUMMY_*"
```

---

## License

MIT
