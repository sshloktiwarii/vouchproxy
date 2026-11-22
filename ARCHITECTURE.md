# Architecture Specification: VouchProxy

**Document Version:** 1.0.0  
**Status:** Approved for Implementation  
**Standard:** Zero-Trust Systems Engineering & Cryptographic Rigor  
**Target:** Go 1.23+ (`CGO_ENABLED=0`, Darwin, Linux, Windows)  

---

## 1. Architectural Philosophy & Core Tenets

VouchProxy operates under the principle of **host-scoped sovereign zero-trust**:
1. **Never Give the Child Process the Real Secret:** The child agent executes in an environment populated solely with non-functional placeholder dummy tokens. It never possesses the cryptographic material or credentials needed to access production systems directly.
2. **Fail-Closed by Design:** If a policy rule does not explicitly permit secret injection for a specific `(host, header, method)` tuple, credentials are never injected. If an unknown domain receives a dummy token, the request is terminated immediately with HTTP 403.
3. **Defense in Depth across System Boundaries:** Security is enforced at five distinct boundaries:
   - *Filesystem Boundary:* `0600` permissions on Unix, user-exclusive DACLs on Windows.
   - *Network Loopback Boundary:* Strict IPv4 `127.0.0.1` binding + dynamic per-session bearer token.
   - *Transport Layer Boundary:* Dynamic TLS MITM with strict SNI vs. HTTP `Host` parity checks.
   - *Application Layer Boundary:* Declarative rule matchers and PII regex sanitization pipelines.
   - *Runtime Memory Boundary:* Explicit byte zeroing and GC pin barriers (`runtime.KeepAlive`) preventing memory dumping of plaintexts.
4. **Zero Cloud Residue & Zero External Dependencies:** Standalone single-binary distribution with embedded pure-Go SQLite WAL persistence. No external telemetry, phone-home, or third-party cloud services.

---

## 2. Go Package Layout

```
vouchproxy/
├── cmd/
│   └── vouchproxy/
│       └── main.go                 # Entrypoint, CLI routing, OS signal dispatch
├── internal/
│   ├── audit/
│   │   ├── db.go                   # Pure Go modernc.org/sqlite database manager (WAL mode)
│   │   ├── schema.sql              # Embedded SQLite schema definition
│   │   ├── recorder.go             # High-throughput asynchronous event recorder
│   │   ├── query.go                # Audit querying, filtering, and export
│   │   └── types.go                # Audit event data contracts
│   ├── certs/
│   │   ├── ca.go                   # Root CA generator, storage, and validation
│   │   ├── mint.go                 # Dynamic on-the-fly leaf certificate generator
│   │   ├── cache.go                # Thread-safe LRU leaf certificate cache
│   │   └── trust.go                # Cross-platform trust store paths and env resolvers
│   ├── crypto/
│   │   ├── argon2.go               # Argon2id key derivation implementation
│   │   ├── gcm.go                  # AES-256-GCM encryption/decryption envelope
│   │   ├── zero.go                 # Secure byte zeroization & runtime memory barriers
│   │   └── random.go               # Cryptographically secure random entropy helpers
│   ├── policy/
│   │   ├── config.go               # vouch.yaml parsing and schema validation
│   │   ├── engine.go               # Host/header matching and policy evaluation engine
│   │   ├── scrubber.go             # PII extraction and regex redaction pipeline
│   │   └── matcher.go              # Exact, wildcard, and CIDR host matchers
│   ├── proxy/
│   │   ├── server.go               # Localhost HTTP/HTTPS CONNECT listener
│   │   ├── auth.go                 # Per-session proxy authentication validator
│   │   ├── mitm.go                 # TLS interceptor, SNI validator, and certificate server
│   │   ├── handler.go              # Request pipeline, dummy token blocker, secret injector
│   │   └── transport.go            # Upstream dialer with DNS rebinding defenses
│   ├── runner/
│   │   ├── supervisor.go           # Child process launcher, env injector, signal forwarder
│   │   ├── supervisor_darwin.go    # POSIX process group tree lifecycle implementation
│   │   ├── supervisor_linux.go     # Linux prctl(PR_SET_PDEATHSIG) + cgroups/pgid
│   │   └── supervisor_windows.go   # Win32 Job Object (KILL_ON_JOB_CLOSE) implementation
│   └── vault/
│       ├── vault.go                # High-level vault operations (Get, Set, List, Delete)
│       ├── storage.go              # Encrypted file IO with atomic rename and 0600 permissions
│       ├── model.go                # Vault internal representation
│       └── types.go                # Strongly-typed SecretBytes wrappers
├── pkg/
│   └── version/
│       └── version.go              # Build-time version metadata
├── .gitignore                      # Hardened repository exclusions
├── go.mod                          # Module definition
├── go.sum                          # Cryptographic checksums
├── ARCHITECTURE.md                 # System architecture specification
├── FLOORPLAN.md                    # Visual system flow & component floorplan
├── PRD.md                          # Product requirements document
└── THREAT_MODEL.md                 # Pre-code STRIDE threat model
```

---

## 3. Cryptographic Envelope Specification (`vault.enc`)

Credentials stored inside `vault.enc` are sealed using authenticated envelope encryption with **Argon2id** (key derivation) and **AES-256-GCM** (symmetric authenticated encryption).

### 3.1 Binary Envelope Layout
```
+--------------------------------------------------------------------------+
| Magic Bytes: "VOUCH_VAULT_V1" (14 bytes)                                 |
+--------------------------------------------------------------------------+
| Argon2id Salt (32 bytes, cryptographically random)                       |
+--------------------------------------------------------------------------+
| Argon2id Parameters: Time (4B) | Memory (4B) | Threads (1B)              |
+--------------------------------------------------------------------------+
| AES-GCM Nonce (12 bytes, unique per write)                               |
+--------------------------------------------------------------------------+
| Ciphertext Payload (Variable length)                                     |
| Encrypted JSON map: {"KEY_NAME": {"value": "...", "created_at": 170000}} |
+--------------------------------------------------------------------------+
| AES-GCM Authentication Tag (16 bytes, Poly1305/GHASH)                    |
+--------------------------------------------------------------------------+
```

### 3.2 Key Derivation & Encryption Parameters
- **Argon2id Parameters:**
  - Salt: 32 bytes from `crypto/rand`.
  - Memory: $64\text{ MB}$ ($65,536\text{ KiB}$).
  - Iterations (Time): 3 passes.
  - Parallelism: 4 threads.
  - Key Length: 32 bytes ($256\text{ bits}$).
- **AES-256-GCM Parameters:**
  - Nonce: 12 bytes generated freshly via `crypto/rand.Read` on every atomic flush.
  - Additional Authenticated Data (AAD): Bound to the header magic string `"VOUCH_VAULT_V1"`.
- **Atomic Persistence:**
  Writes are committed to `vault.enc.tmp` with `0600` permissions and then moved to `vault.enc` using an atomic OS rename (`os.Rename`), preventing file corruption on unexpected crashes.

---

## 4. Storage Architecture (SQLite WAL Audit Ledger)

VouchProxy uses `modernc.org/sqlite`—a 100% pure-Go CGO-free SQLite implementation that compiles statically across all operating systems.

### 4.1 SQLite Configuration & Invariants
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA wal_autocheckpoint = 1000;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;
```

### 4.2 Database Schema (`internal/audit/schema.sql`)
```sql
CREATE TABLE IF NOT EXISTS audit_sessions (
    session_id TEXT PRIMARY KEY,
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP,
    command TEXT NOT NULL,
    exit_code INTEGER
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    http_method TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    path_sanitized TEXT NOT NULL,
    action TEXT NOT NULL,           -- 'INJECT_SECRET', 'SCRUB_PII', 'BLOCK_LEAK', 'PASSTHROUGH', 'REJECT'
    injected_key_name TEXT,         -- e.g. 'OPENAI_API_KEY' (NEVER the raw secret value)
    scrub_count INTEGER NOT NULL DEFAULT 0,
    http_status INTEGER NOT NULL,
    latency_ms REAL NOT NULL,
    details TEXT,                   -- Sanitized structured JSON (e.g. matched policy name)
    FOREIGN KEY(session_id) REFERENCES audit_sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_audit_events_session ON audit_events(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_host ON audit_events(host);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
```

---

## 5. Dynamic TLS MITM Engine & Certificate Lifecycle

To inspect and rewrite HTTPS request headers, VouchProxy operates as an active TLS terminating forward proxy.

```
+----------------+      CONNECT api.github.com:443      +------------------+
|                | -----------------------------------> |                  |
|  Child Agent   |                                      |    VouchProxy    |
| (curl, python) | <----------------------------------- |    MITM Engine   |
|                |      200 Connection Established      |                  |
+----------------+                                      +------------------+
        |                                                        |
        | TLS ClientHello (SNI: api.github.com)                  | Upstream TLS Handshake
        +------------------------------------------------------> | (Verify Real Public Cert)
                                                                 |
                                                                 v
                                                        +------------------+
                                                        | Real Upstream API|
                                                        | (api.github.com) |
                                                        +------------------+
```

### 5.1 Root CA Authority (`ca.key` / `ca.crt`)
- **Key Algorithm:** ECDSA P-256 (preferred for signature speed and compact footprint) or RSA 3072.
- **Validity:** 10 years, generated during `vouchproxy init`.
- **Key Usage:** `KeyUsageCertSign | KeyUsageCRLSign`.
- **Basic Constraints:** `IsCA: true`, `MaxPathLenZero: true`.
- **File Permissions:** `0600` (`-rw-------`) for `ca.key`.

### 5.2 Dynamic Leaf Certificate Minting
1. During the HTTPS CONNECT tunnel establishment, VouchProxy intercepts the initial TLS `ClientHello` and reads the Server Name Indication (SNI).
2. It verifies that the SNI strictly matches the host supplied in the HTTP `CONNECT` command.
3. The cache is queried for `api.github.com`. If present and valid (not expiring within 24 hours), the cached certificate is returned.
4. If missing, a dynamic leaf certificate is generated:
   - Serial number: 128-bit cryptographically secure integer.
   - Subject Common Name (CN): Target domain (e.g., `api.github.com`).
   - Subject Alternative Names (SAN): DNS Names and IP Addresses matching the target.
   - Validity: 7 days.
   - Key Usage: `KeyUsageDigitalSignature | KeyUsageKeyEncipherment`.
   - ExtKeyUsage: `ExtKeyUsageServerAuth`.
   - Signed by VouchProxy Root CA private key.
5. Cached in thread-safe in-memory LRU cache (`max_size: 500`).

---

## 6. Cross-Platform Process Supervision Engine

When `vouchproxy run -- <cmd>` is invoked, the proxy acts as a robust parent supervisor guaranteeing zero zombie processes and clean teardown.

### 6.1 POSIX Subprocess Lifecycle (`Darwin`, `Linux`)
- **Process Group Isolation:**
  The child process is launched with `SysProcAttr.Setpgid = true`. This sets the process group ID to the child PID, making all descendants part of the same process group.
- **Signal Forwarding & Teardown:**
  - VouchProxy registers OS signal handlers for `SIGINT` and `SIGTERM`.
  - Upon receiving a termination signal or when the child exits, VouchProxy broadcasts `SIGTERM` to the entire process group:
    ```go
    syscall.Kill(-childPid, syscall.SIGTERM)
    ```
  - A 2-second grace period timer starts. If descendants remain alive, VouchProxy issues `syscall.Kill(-childPid, syscall.SIGKILL)`.
- **Linux Parent-Death Signal:**
  On Linux, `SysProcAttr.Pdeathsig = syscall.SIGKILL` ensures the Linux kernel automatically terminates the child if VouchProxy terminates abruptly.

### 6.2 Windows Subprocess Lifecycle (`Windows 10/11, Server`)
- **Win32 Job Object Enclosure:**
  On Windows, process trees cannot be managed reliably with signals. VouchProxy utilizes Win32 Job Objects:
  1. `CreateJobObjectW(nil, nil)` creates an anonymous job object.
  2. `SetInformationJobObject` configures `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
  3. `AssignProcessToJobObject` binds the newly created child process handle to the job object.
  4. When VouchProxy exits (normally, by crash, or via `Ctrl+C`), the OS kernel automatically and synchronously terminates all child and grandchild processes bound to the job.

---

## 7. Cross-Compilation & Packaging Pipeline

VouchProxy is engineered for frictionless cross-platform distribution without external dynamic linking.

### 7.1 Cross-Compilation Matrix
- `darwin/arm64` (Apple Silicon M1/M2/M3/M4)
- `darwin/amd64` (Intel Mac)
- `linux/amd64` (Standard Linux x86_64 servers & workstations)
- `linux/arm64` (Raspberry Pi 4/5, AWS Graviton, Linux ARM servers)
- `windows/amd64` (Windows 10/11 x86_64)

### 7.2 Build Command Contract
```bash
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w -X 'vouchproxy/pkg/version.Version=1.0.0' -X 'vouchproxy/pkg/version.GitCommit=$(git rev-parse --short HEAD)'" -o bin/vouchproxy cmd/vouchproxy/main.go
```

---

## 8. Explainer & Architectural Walkthroughs

### 8.1 The Mental Model: The Diplomatic Pouch
Think of VouchProxy as a **Diplomatic Security Courier**:
- Inside your local embassy (the child agent's runtime process), everyone carries **blank dummy passports** (`VP_GITHUB_TOKEN_DUMMY_*`). If a burglar breaks into the embassy, sneaks into the terminal history, or photographs the agent's clipboard, they only see worthless dummy tokens.
- When the diplomat needs to send a message to the British Foreign Office (`api.github.com`), the message travels in a sealed diplomatic pouch to the embassy checkpoint (VouchProxy).
- At the checkpoint, the courier inspects the destination. Is it really `api.github.com`? If yes, the courier attaches the official diplomatic seal (the real secret) and dispatches it over the wire.
- If a rogue employee attempts to route the diplomatic pouch to an unapproved recipient (`malicious-webhook.com`), the checkpoint guard immediately seizes the pouch, shreds the communication, sounds the alarm, and logs the incident in the permanent station log.

### 8.2 The Request Journey: Step-by-Step State Flow

```
1. Child Process issues:
   curl -H "Authorization: Bearer VP_OPENAI_KEY_DUMMY_123" https://api.openai.com/v1/chat/completions

2. HTTP Client reads HTTPS_PROXY=http://127.0.0.1:54321
   Issues HTTP CONNECT api.openai.com:443
   Header: Proxy-Authorization: Bearer <session-token>

3. VouchProxy Server receives CONNECT:
   - Validates Proxy-Authorization against active in-memory session token. (Pass)
   - Checks if upstream port is 443. (Pass)
   - Responds: HTTP/200 Connection Established.

4. Client initiates TLS Handshake:
   - Client sends SNI "api.openai.com".
   - VouchProxy retrieves/mints leaf cert for "api.openai.com" signed by local CA.
   - Client verifies cert against SSL_CERT_FILE. Handshake succeeds.

5. Client transmits plaintext HTTP POST request over TLS:
   - Request Line: POST /v1/chat/completions HTTP/1.1
   - Host: api.openai.com
   - Authorization: Bearer VP_OPENAI_KEY_DUMMY_123
   - Body: {"model": "gpt-4", "messages": [{"role": "user", "content": "Email me at dev@company.com"}]}

6. VouchProxy Request Processing Pipeline:
   a. Check for Dummy Tokens:
      - Detected dummy token "VP_OPENAI_KEY_DUMMY_123" in Authorization header.
      - Evaluate Policy: Host "api.openai.com" allows secret "OPENAI_API_KEY".
      - Fetch real key from memory vault.
      - Rewrite header: Authorization: Bearer sk-live-REAL_OPENAI_KEY_abc123...
   b. PII Scrubber Pipeline:
      - Inspect Body: Matches email pattern "dev@company.com".
      - Redact: Replacement "[EMAIL_REDACTED]".
   c. Upstream Dispatch:
      - Dial real upstream "api.openai.com:443" using system root pool.
      - Forward rewritten request.

7. Upstream responds:
   - Receive HTTP 200 OK from OpenAI.
   - Relay HTTP 200 OK response back through local TLS tunnel to child process.

8. Asynchronous Audit Logging:
   - Emit audit event: {host: "api.openai.com", action: "INJECT_SECRET", key: "OPENAI_API_KEY", scrubs: 1, status: 200}.
   - Write to SQLite WAL ledger.
```

### 8.3 Memory Zeroization: Defeating the Go Garbage Collector
In Go, standard `string` values are immutable. Once a secret is allocated as a `string`, the runtime may duplicate it, place it in heap slabs, and keep it in dead memory indefinitely until the garbage collector runs a sweep. Even after a GC sweep, the underlying RAM memory is not zeroed until overwritten by another allocation.

**The VouchProxy Invariant:**
- Secrets are retrieved from `vault.enc` strictly into allocated byte slices: `type SecretBytes []byte`.
- A dedicated zeroization function utilizes pointer manipulation to overwrite every byte with `0x00`:
  ```go
  func ZeroBytes(b []byte) {
      for i := range b {
          b[i] = 0
      }
      runtime.KeepAlive(b)
  }
  ```
- Any string conversions are strictly forbidden inside the core proxy path. When injecting into the outgoing `net/http` request header, headers are written using byte buffers that are wiped immediately after the upstream connection completes.
