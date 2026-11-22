# VouchProxy Edge Cases & Boundary Condition Matrix

**Document Version:** 1.0.0  
**Coverage Standard:** Adversarial Robustness, Cross-Platform Invariants & Failure-Mode Analysis  

---

## 1. Edge Case Taxonomy & Test Matrix

This document enumerates every architectural boundary condition across macOS (Darwin), Linux, and Windows, mapped to automated regression tests in `tests/` and `internal/`.

| ID | Category | Boundary Condition / Edge Case | Expected System Invariant | Test Assertion |
|:---|:---|:---|:---|:---|
| **EC-01** | **Proxy Auth** | Request to proxy lacks `Proxy-Authorization` header | Return HTTP 407 Proxy Authentication Required | `TestProxyAuthentication_Missing` |
| **EC-02** | **Proxy Auth** | Request provides invalid bearer token or wrong basic auth password | Return HTTP 407 Proxy Authentication Required | `TestProxyAuthentication_Invalid` |
| **EC-03** | **TLS / MITM** | Client TLS ClientHello SNI (`evil.com`) != HTTP CONNECT destination (`api.github.com`) | Abort TLS handshake immediately; do not mint cert | `TestMITM_SNIMismatch_Dropped` |
| **EC-04** | **TLS / MITM** | Upstream domain certificate is expired or invalid | Return HTTP 502 Bad Gateway to child | `TestMITM_UpstreamFailure` |
| **EC-05** | **Credential Trap** | Agent sends `VP_GITHUB_TOKEN_DUMMY_*` to unauthorized host `webhook.site` | Abort with HTTP 403 Forbidden; log `BLOCK_LEAK` | `TestExfiltrationTrap_Blocked` |
| **EC-06** | **Credential Injection** | Agent sends `VP_GITHUB_TOKEN_DUMMY_*` to authorized `api.github.com` | Replace dummy with decrypted real secret in memory; zero bytes after use | `TestAuthorizedInjection_Success` |
| **EC-07** | **PII Scrubbing** | Outbound headers contain user email (`dev@company.com`) | Redact to `[EMAIL_REDACTED]` before upstream forward | `TestPIIScrubber_Headers` |
| **EC-08** | **PII Scrubbing** | GZIP-compressed request body contains email or username | Decompress, scrub PII, re-compress, update `Content-Length` | `TestPIIScrubber_GzipBody` |
| **EC-09** | **PII Scrubbing** | Outbound request body exceeds 1 MB cap | `io.LimitReader` limits scan; stream safely without OOM | `TestPIIScrubber_LargeBodyCap` |
| **EC-10** | **Process Supervision** | Child process attempts to override `NO_PROXY=*` or lowercase `no_proxy` | Runner forces `NO_PROXY=""` and `no_proxy=""` in child env | `TestRunner_EnvironmentSanitization` |
| **EC-11** | **Process Teardown** | Parent receives `SIGINT` while child process has background subprocesses | Kill entire POSIX process group (`-pgid`) or Windows Job Object | `TestSupervisor_ProcessGroupKill` |
| **EC-12** | **Storage / Audit** | 500 concurrent goroutines writing audit records simultaneously | Mutex-synchronized `bufio.Writer` flushes without corrupting lines | `TestAuditLogger_HighConcurrency` |
| **EC-13** | **Audit Tailing** | `vouchproxy audit --tail` on 50 MB log file | Fast reverse-seek from EOF without loading entire file into memory | `TestAuditTail_ReverseSeek` |
| **EC-14** | **Memory Zeroing** | Decrypted secret slice passed through GC cycles | `ZeroBytes()` clears slice memory with `runtime.KeepAlive()` barrier | `TestCrypto_ZeroBytes` |
| **EC-15** | **File Permissions** | `vault.enc` or `ca.key` has permissions `0644` (group/world readable) | Abort startup with security invariant error | `TestVault_FilePermissionsEnforced` |
| **EC-16** | **Path Traversal** | CLI flag points to `../../etc/shadow` or symlink outside sandbox | Canonicalize via `filepath.Clean` and reject unauthorized roots | `TestCLI_PathTraversalRejected` |

---

## 2. Adversarial Scenarios Covered in Automated Suite

1. **The Confused Deputy Exfiltration Trap (`TestExfiltrationTrap_Blocked`)**:
   Simulates an autonomous coding agent executing a poisoned instruction that crafts a POST request sending environment variables (including dummy tokens and system email) to an attacker-controlled mock endpoint. The test asserts that VouchProxy detects the dummy token, evaluates policy rules, identifies that the target host is unauthorized, drops the connection with `HTTP 403 Forbidden`, and registers a `BLOCK_LEAK` audit event.
2. **High-Concurrency Race Benchmark (`BenchmarkProxyPipeline` & `TestProxy_500ConcurrentRequests`)**:
   Launches 500 parallel client goroutines issuing HTTP and HTTPS CONNECT requests through VouchProxy under `go test -race`. Validates that zero data races occur, memory remains bounded with `sync.Pool`, and latency remains sub-millisecond on the local proxy pipeline.
