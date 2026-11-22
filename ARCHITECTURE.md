# Architecture Specification: VouchProxy (Zero-Bloat Edition)

**Document Version:** 1.1.0  
**Status:** Approved for Implementation  
**Standard:** Zero-Trust Systems Engineering, Cryptographic Rigor & Zero-Bloat Efficiency  
**Target:** Go 1.23+ (`CGO_ENABLED=0`, Darwin, Linux, Windows)  
**Binary Size Target:** < 10 MB (Hard limit: < 12 MB)  
**Memory Target:** < 15 MB RSS  
**Latency Target:** < 1 ms added proxy hot-path latency  

---

## 1. Architectural Philosophy & Core Tenets

VouchProxy operates under the principle of **host-scoped sovereign zero-trust with zero bloat**:
1. **Never Give the Child Process the Real Secret:** The child agent executes in an environment populated solely with non-functional placeholder dummy tokens. It never possesses the cryptographic material or credentials needed to access production systems directly.
2. **Fail-Closed by Design:** If a policy rule does not explicitly permit secret injection for a specific `(host, header, method)` tuple, credentials are never injected. If an unknown domain receives a dummy token, the request is terminated immediately with HTTP 403.
3. **Defense in Depth across System Boundaries:** Security is enforced at five distinct boundaries:
   - *Filesystem Boundary:* `0600` permissions on Unix, user-exclusive DACLs on Windows.
   - *Network Loopback Boundary:* Strict IPv4 `127.0.0.1` binding + dynamic per-session bearer token.
   - *Transport Layer Boundary:* Dynamic TLS MITM with strict SNI vs. HTTP `Host` parity checks.
   - *Application Layer Boundary:* Declarative rule matchers and PII regex sanitization pipelines.
   - *Runtime Memory Boundary:* Explicit byte zeroing and GC pin barriers (`runtime.KeepAlive`) preventing memory dumping of plaintexts.
4. **Minimal Dependency Footprint:** Zero bloated database or CLI framework runtimes. No `modernc.org/sqlite`, no `cobra`/`viper`. Exclusively utilizes Go standard library (`flag`, `net/http`, `crypto/tls`, `bufio`, `sync`) plus two audited foundational packages: `golang.org/x/crypto/argon2` and `gopkg.in/yaml.v3`.
5. **Zero Cloud Residue & Zero External Dependencies:** Standalone single-binary distribution with embedded append-only buffered `O_APPEND` JSONL audit logging (`audit.jsonl` with `0600` permissions). No external telemetry, phone-home, or third-party cloud services.

---

## 2. Go Package Layout

```
vouchproxy/
├── cmd/
│   └── vouchproxy/
│       └── main.go                 # Entrypoint, stdlib flag routing, OS signal dispatch
├── internal/
│   ├── audit/
│   │   ├── logger.go               # Append-only buffered O_APPEND JSONL audit logger (0600 perms)
│   │   ├── tail.go                 # High-performance reverse-seek file tailing for CLI
│   │   └── types.go                # Audit event data contracts
│   ├── certs/
│   │   ├── ca.go                   # Root CA generator, storage, and validation
│   │   ├── mint.go                 # Dynamic on-the-fly ECDSA P-256 leaf certificate generator
│   │   ├── cache.go                # Thread-safe bounded 256-item LRU leaf certificate cache
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
│   │   └── matcher.go              # Exact and wildcard host matchers
│   ├── proxy/
│   │   ├── server.go               # Localhost HTTP/HTTPS CONNECT listener
│   │   ├── auth.go                 # Per-session proxy authentication validator
│   │   ├── mitm.go                 # TLS interceptor, SNI validator, and certificate server
│   │   ├── handler.go              # Request pipeline, dummy token blocker, secret injector
│   │   ├── pool.go                 # sync.Pool for 32 KB I/O buffers & bytes.Buffer reuse
│   │   └── transport.go            # Upstream dialer with DNS rebinding defenses & streaming
│   ├── runner/
│   │   ├── supervisor.go           # Child process launcher, env injector, signal forwarder
│   │   ├── supervisor_darwin.go    # POSIX process group tree lifecycle implementation
│   │   ├── supervisor_linux.go     # Linux prctl(PR_SET_PDEATHSIG) + cgroups/pgid
│   │   └── supervisor_windows.go   # Win32 Job Object (KILL_ON_JOB_CLOSE) implementation
│   └── vault/
│       ├── vault.go                # High-level vault operations (Get, Set, List, Delete)
│       ├── storage.go              # Encrypted file IO with atomic rename and 0600 permissions
│       └── types.go                # Strongly-typed SecretBytes wrappers
├── pkg/
│   └── version/
│       └── version.go              # Build-time version metadata
├── .gitignore                      # Hardened repository exclusions
├── go.mod                          # Minimal module definition
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

## 4. Storage Architecture (Zero-Bloat JSONL Audit Ledger)

Rather than embedding a 5–10 MB SQLite CGO/pure-Go runtime engine, VouchProxy utilizes an ultra-lightweight, append-only buffered **JSONL** (JSON Lines) ledger (`audit.jsonl`).

### 4.1 Invariants & Performance Design
- **Append-Only Mode:** Opened with `os.O_CREATE | os.O_WRONLY | os.O_APPEND` and strict `0600` file permissions.
- **Thread-Safe Buffered Writes:** A dedicated mutex synchronizes concurrent writes with a buffered `bufio.Writer` that flushes after every log entry, ensuring durability without database locking bottlenecks.
- **Fast Reverse-Seek Tailing:** The `vouchproxy audit --tail` command executes a reverse seek algorithm starting from the end of the file (`file.Seek(-chunkSize, io.SeekEnd)`), parsing lines backwards without ever loading the entire file into memory.
- **Zero Raw Secret Guarantee:** Enforced at the type level. The audit logger only accepts string key identifiers (`"OPENAI_API_KEY"`), never secret payloads or session secrets.

---

## 5. Dynamic TLS MITM Engine & Certificate Lifecycle

To inspect and rewrite HTTPS request headers, VouchProxy operates as an active TLS terminating forward proxy with sub-millisecond leaf certificate generation.

### 5.1 Root CA Authority (`ca.key` / `ca.crt`)
- **Key Algorithm:** ECDSA P-256 (`elliptic.P256()`). Mints certificates in microseconds compared to slow RSA 3072 key generation.
- **Validity:** 10 years, generated during `vouchproxy init`.
- **Key Usage:** `KeyUsageCertSign | KeyUsageCRLSign`.
- **Basic Constraints:** `IsCA: true`, `MaxPathLenZero: true`.
- **File Permissions:** `0600` (`-rw-------`) for `ca.key`.

### 5.2 Dynamic Leaf Certificate Minting & Bounded LRU Cache
1. Intercepts the TLS `ClientHello` and extracts the Server Name Indication (SNI).
2. Verifies that the SNI strictly matches the host supplied in the HTTP `CONNECT` command.
3. Consults an in-memory bounded **256-item LRU certificate cache**.
4. If missing, mints an on-the-fly leaf certificate using ECDSA P-256 with 7-day validity and SAN matching the target domain.
5. Cached certificates allow subsequent connections to complete in sub-millisecond handshake times.

---

## 6. Hot-Path Efficiency & Performance Contracts

To achieve $< 1\text{ ms}$ added proxy latency, $< 15\text{ MB}$ RSS, and $> 5,000\text{ req/sec}$ throughput:

1. **Buffer Pooling (`sync.Pool`):**
   - 32 KB I/O copy buffers are retrieved from a global `sync.Pool` during `io.CopyBuffer` streaming.
   - `bytes.Buffer` instances used for request header rewriting are pooled and zeroed/reset before returning to the pool, eliminating heap allocations and GC pauses.
2. **Immutable Policy Hot Path:**
   - Pre-compiled PII `regexp.Regexp` patterns.
   - `vouch.yaml` rules are loaded into an immutable lookup map at startup, enabling lock-free request matching on the hot path.
3. **Bounded Outbound Body Scanning:**
   - Outbound request body PII scanning is capped with `io.LimitReader(body, 1024*1024)` (1 MB limit).
   - Response streaming from upstream APIs is piped directly via `io.CopyBuffer` into the client connection without buffering responses in memory.

---

## 7. Cross-Platform Process Supervision Engine

When `vouchproxy run -- <cmd>` is invoked, the proxy acts as a robust parent supervisor guaranteeing zero zombie processes and clean teardown.

### 7.1 POSIX Subprocess Lifecycle (`Darwin`, `Linux`)
- Child process is launched with `SysProcAttr.Setpgid = true`.
- Upon `SIGINT`/`SIGTERM` or child exit, VouchProxy signals the process group (`syscall.Kill(-childPid, syscall.SIGTERM)`).
- Linux uses `SysProcAttr.Pdeathsig = syscall.SIGKILL` for kernel-level orphan termination.

### 7.2 Windows Subprocess Lifecycle (`Windows 10/11, Server`)
- Child process is assigned to a Win32 Job Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
- When VouchProxy exits, the Windows kernel automatically terminates all child processes.

---

## 8. Compiler & Benchmark Gate

- **Binary Size Gate:**
  `CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath`
  Binary must compile to $< 10\text{ MB}$ (hard ceiling $< 12\text{ MB}$).
- **Latency & Benchmark Gate:**
  `go test -bench=. -benchmem ./internal/proxy` must verify $< 1\text{ ms}$ added proxy latency and minimal allocations per operation.
