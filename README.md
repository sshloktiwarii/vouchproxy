# VouchProxy

> **Host-Scoped Credential Injection & PII-Scrubbing Local MITM Proxy for AI Coding Agents and MCP Servers**

[![Build & Test](https://github.com/sshloktiwarii/vouchproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/sshloktiwarii/vouchproxy)
[![Go Version](https://img.shields.io/badge/go-1.23%2B-blue.svg)](https://golang.org)
[![Security Standard](https://img.shields.io/badge/security-Zero--Trust%20Loopback-brightgreen.svg)](#security-invariants)
[![Binary Size](https://img.shields.io/badge/binary%20size-7.7%20MB-blueviolet.svg)](#performance-benchmarks)
[![Hot-Path Latency](https://img.shields.io/badge/latency-0.039%20ms-success.svg)](#performance-benchmarks)

---

## 1. Problem & Value Proposition

Modern autonomous AI coding agents (`claude-code`, `aider`, `gemini-cli`, `cursor`) and Model Context Protocol (MCP) servers create serious security risks:
- **Plaintext `.env` Exposure:** Agents read local `.env` files into prompt contexts, write them into public Git commits, or leak them in debug traces.
- **Subprocess Identity Leaks:** Outbound calls from `curl`, `python`, `npm`, and `git` broadcast your workstation username, local hostname, and personal email in `User-Agent` and `From` headers.
- **Confused Deputy & Issuer Confusion:** Prompt injection attacks can trick an agent into sending bearer tokens to adversary-controlled webhook endpoints.

**VouchProxy** solves this by enforcing **host-scoped sovereign zero-trust**:
1. **Dummy Token Substitution:** The child agent runs in an environment populated solely with non-functional placeholder dummy tokens (e.g. `VP_GITHUB_TOKEN_DUMMY_8f9a2b`).
2. **Transparent Local MITM Proxy:** VouchProxy listens on an ephemeral loopback port (`127.0.0.1:<random>`) and validates a per-session random bearer token.
3. **Fail-Closed Secret Swap:** Outbound requests are intercepted. If and only if the destination host and target header match an authorized rule in `vouch.yaml`, VouchProxy swaps the dummy token with the real secret from an Argon2id + AES-256-GCM encrypted local vault (`vault.enc`).
4. **Exfiltration Trap:** If an agent attempts to send a dummy token to an unauthorized domain or endpoint, VouchProxy drops the request with `HTTP 403 Forbidden` and logs a security incident.
5. **Bi-Directional PII Scrubbing:** Outbound headers, URL query parameters, and JSON/form bodies are scrubbed to strip developer emails, hostnames, and system usernames before leaving your machine.
6. **Zero-Bloat Architecture:** Zero CGO, no heavy database runtimes. Standalone static binary ($7.7\text{ MB}$) with append-only buffered JSONL audit logging (`audit.jsonl`).

---

## 2. System Architecture & Floorplan

```
+==================================================================================================================+
|                                              LOCAL WORKSTATION HOST                                              |
+==================================================================================================================+
|                                                                                                                  |
|  [UNTRUSTED CHILD AGENT]                                             [VOUCHPROXY SOVEREIGN ENCLAVE]               |
|                                                                                                                  |
|  +-------------------------------------+                              +---------------------------------------+  |
|  | Autonomous Agent Process Tree       |                              | VouchProxy Core Supervisor            |  |
|  | - claude-code / aider / gemini-cli  |                              | - 127.0.0.1:<ephemeral-port>          |  |
|  | - Subprocesses: curl, python, git   |                              | - Session Auth Secret Validator       |  |
|  +-------------------------------------+                              +---------------------------------------+  |
|       |                                                                            |      |                      |
|       | 1. Injected Child Environment:                                             |      |                      |
|       |    - HTTP_PROXY/HTTPS_PROXY = http://session:<token>@127.0.0.1:<port>      |      |                      |
|       |    - SSL_CERT_FILE = ~/.vouchproxy/ca.crt                                  |      |                      |
|       |    - OPENAI_API_KEY = VP_OPENAI_KEY_DUMMY_123                              |      |                      |
|       v                                                                            |      |                      |
|  +-------------------------------------+                                           |      |                      |
|  | Outbound Request Emitted            |                                           |      |                      |
|  | Host: api.openai.com                |                                           |      |                      |
|  | Auth: Bearer VP_OPENAI_KEY_DUMMY... |                                           |      |                      |
|  +-------------------------------------+                                           |      |                      |
|       |                                                                            |      |                      |
|       +=====================> [LOOPBACK TRUST BOUNDARY (407)] =====================+      |                      |
|                                                                                           |                      |
|                               [INTERCEPTION & FILTERING PIPELINE]                         |                      |
|                               +-------------------------------------------------------+   |                      |
|                               | A. HTTP/HTTPS CONNECT Listener (127.0.0.1 only)       |   |                      |
|                               |    - Validates Proxy-Authorization Session Token      |   |                      |
|                               +-------------------------------------------------------+   |                      |
|                                                            |                              |                      |
|                                                            v                              |                      |
|                               +-------------------------------------------------------+   |                      |
|                               | B. Dynamic TLS MITM Engine (ECDSA P-256)              |   |                      |
|                               |    - Validates SNI == Host header (No DNS Rebind)     |   |                      |
|                               |    - Bounded 256-item LRU Certificate Cache           |   |                      |
|                               +-------------------------------------------------------+   |                      |
|                                                            |                              |                      |
|                                                            v                              |                      |
|                               +-------------------------------------------------------+   |                      |
|                               | C. Policy Matcher & Dummy Leak Trap                   |   |                      |
|                               |    - Match host against vouch.yaml                    |   |                      |
|                               |    - If dummy token on unauthorized host -> HTTP 403   |   |                      |
|                               +-------------------------------------------------------+   |                      |
|                                      |                                   |                |                      |
|                   (If Authorized)    |                                   | (If Scrubbing  |                      |
|                                      v                                   v  Configured)   |                      |
|               +-------------------------------+      +-------------------------+          |                      |
|               | D. Vault Module               |      | E. PII Scrubber         |          |                      |
|               |    - Memory-zeroed key fetch  |      |    - Redacts email,     |          |                      |
|               |    - Swaps dummy with real    |      |      hostname, username |          |                      |
|               +-------------------------------+      +-------------------------+          |                      |
|                                      |                                   |                |                      |
|                                      +-----------------+-----------------+                |                      |
|                                                        |                                  |                      |
|                                                        v                                  |                      |
|                               +-------------------------------------------------------+   |                      |
|                               | F. Upstream Streaming Dialer (sync.Pool 32KB Buffers) |   |                      |
|                               |    - Zero response buffering                          |   |                      |
|                               +-------------------------------------------------------+   |                      |
|                                                        |                                  |                      |
|       +================================================+                                  |                      |
|       |                                                                                   |                      |
|       v                                                                                   v                      |
|  [PERSISTENT VAULT (0600)]                                              [APPEND-ONLY AUDIT (0600)]                |
|  +--------------------------------+                                     +-------------------------------------+  |
|  | ~/.vouchproxy/vault.enc        |                                     | ~/.vouchproxy/audit.jsonl           |  |
|  | - Argon2id + AES-256-GCM       |                                     | - Fast reverse-seek tailing         |  |
|  | - Plaintext never on disk      |                                     | - ZERO raw secrets logged           |  |
|  +--------------------------------+                                     +-------------------------------------+  |
+==================================================================================================================+
                                        | (Encrypted Outbound Egress)
                                        v
                        +===============================+
                        | Authorized Upstream APIs      |
                        | - api.openai.com              |
                        | - api.anthropic.com           |
                        | - api.github.com              |
                        +===============================+
```

---

## 3. Quickstart & CLI Reference

### 3.1 Installation
```bash
# Clone and build
git clone https://github.com/sshloktiwarii/vouchproxy.git
cd vouchproxy
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o bin/vouchproxy cmd/vouchproxy/main.go
sudo cp bin/vouchproxy /usr/local/bin/
```

### 3.2 Initialize Security Enclave
```bash
vouchproxy init
```
- Creates `~/.vouchproxy/` with `0700` permissions.
- Generates local Root CA (`ca.crt` and `ca.key` with `0600` permissions).
- Sets master vault passphrase and creates encrypted `vault.enc`.
- Scaffolds starter `vouch.yaml` policy.

### 3.3 Store Encrypted Credentials
```bash
# Prompted for passphrase & secret value with masked echo
vouchproxy secret set OPENAI_API_KEY
vouchproxy secret set ANTHROPIC_API_KEY
vouchproxy secret set GITHUB_TOKEN

# List registered keys and their bound dummy tokens (never displays secret values)
vouchproxy secret list
```

### 3.4 Execute Sandboxed Agent
```bash
# Run any agent command behind VouchProxy
vouchproxy run -- aider --model sonnet

# Or run standard developer CLI tools
vouchproxy run -- curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
```

### 3.5 Inspect Audit Ledger
```bash
# Tail latest 20 events in reverse chronological order
vouchproxy audit --tail

# Filter by host or action
vouchproxy audit --tail --host api.openai.com --action INJECT_SECRET

# Output structured JSON for SIEM ingestion
vouchproxy audit --json --limit 50
```

---

## 4. Policy Configuration (`vouch.yaml`)

```yaml
version: "1.0"

settings:
  strict_mode: false            # If true, block all unmapped outbound hosts with HTTP 502
  proxy_auth_required: true     # Enforce per-session Proxy-Authorization token
  mitm_cache_size: 256          # Bounded LRU leaf certificate cache
  connect_timeout_seconds: 15
  request_timeout_seconds: 60

scrubbing:
  emails: true                  # Redacts RFC 5322 email patterns
  usernames:                    # Redacts specified system usernames and hostnames
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

## 5. Security Invariants

| ID | Invariant | Specification | Failure Action |
|:---|:---|:---|:---|
| **INV-01** | **Loopback Only** | Proxy binds strictly to `127.0.0.1` ephemeral port. | Panic on startup if non-loopback. |
| **INV-02** | **Session Auth** | Every run generates an unguessable 32-byte secret. | Return HTTP 407 Proxy Authentication Required. |
| **INV-03** | **Dummy Exfiltration Trap** | Dummy token detected for unauthorized destination host. | Drop connection with HTTP 403 Forbidden; log alert. |
| **INV-04** | **Zero Secret Logging** | `internal/audit` never receives raw secret values. | Enforced by type-safe `SecretBytes` wrapper. |
| **INV-05** | **Memory Zeroing** | Decrypted secret buffers wiped with zeros (`ZeroBytes()`). | Eliminates plaintexts lingering in Go heap GC cycles. |
| **INV-06** | **DNS Rebind Defense** | Enforces $\text{CONNECT Host} == \text{TLS SNI} == \text{HTTP Host}$. | Terminate connection on divergence. |
| **INV-07** | **Strict File Permissions** | `vault.enc` and `ca.key` require `0600` permissions. | Refuse startup if group/world readable. |
| **INV-08** | **Process Isolation** | POSIX process group / Windows Job Object supervisor. | Clean teardown; zero orphan/zombie child processes. |

---

## 6. Performance Benchmarks

Measured on Apple M5 (`darwin/arm64`):

```
pkg: github.com/sshloktiwarii/vouchproxy/internal/proxy
BenchmarkProxyPipeline-10    29954    39666 ns/op (0.039 ms)    12382 B/op    152 allocs/op
```

- **Binary Size:** **7.7 MB** (`CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath`)
- **Added Hot-Path Latency:** **0.039 ms** (Target was < 1.0 ms)
- **Idle Memory:** **< 12 MB RSS**
- **Concurrency Test:** **500 parallel requests** with zero data races (`go test -race`).

---

## 7. Roadmap

- **v2.0:** Native MCP `stdio` and Streamable-HTTP JSON-RPC parser enforcing RFC 8707 resource indicators.
- **v3.0:** Interactive Bubble Tea TUI approval for first-time outbound domains.
- **v4.0:** OS-native keychain backends (macOS Keychain, Windows Credential Manager, Linux Secret Service).

---

## 8. License

MIT License. Designed with zero-trust systems engineering discipline.
