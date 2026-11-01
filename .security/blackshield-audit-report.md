# BlackShield Security Audit Report — `katzenpost/katzenpost`

- **Scanned Commit:** `8d6c64e0ca20a256d1fc581ee19149b0404f6508`
- **Actionable Findings:** `13` (`1 Critical`, `12 High`, `57 Medium`, `8 Low`)
- **BlackShield Platform & Continuous Zero-Cost PR Protection:** [https://blackshield.chaplau.com](https://blackshield.chaplau.com)

## Detailed Findings & Remediation Guide

### 1. [CRITICAL] `sec-insecure-tls` — sec-insecure-tls: Disabled TLS Certificate Verification

- **Category:** `sast`
- **Location:** `quic/common/quic.go:565`
- **Details:** Disabling TLS certificate verification permits Man-in-the-Middle (MitM) attacks. at quic/common/quic.go:565
- **Recommended Fix:** Ensure InsecureSkipVerify is false and use verified Certificate Authorities.

### 2. [HIGH] `CKV_DOCKER_11` — CKV_DOCKER_11: Unverified Script Piped Directly to Shell

- **Category:** `misconfiguration`
- **Location:** `.ci/Dockerfile:31`
- **Details:** Piping remote HTTP downloads directly into sh or bash executes unverified code without checksum verification.
- **Recommended Fix:** Download scripts first, verify their SHA-256 checksum against an expected digest, then execute.

### 3. [HIGH] `CKV_DOCKER_11` — CKV_DOCKER_11: Unverified Script Piped Directly to Shell

- **Category:** `misconfiguration`
- **Location:** `.ci/Dockerfile:44`
- **Details:** Piping remote HTTP downloads directly into sh or bash executes unverified code without checksum verification.
- **Recommended Fix:** Download scripts first, verify their SHA-256 checksum against an expected digest, then execute.

### 4. [HIGH] `CKV_DOCKER_1` — CKV_DOCKER_1: Container Runs as Root (Missing Non-Root USER)

- **Category:** `misconfiguration`
- **Location:** `.ci/Dockerfile:1`
- **Details:** Container does not specify a non-root USER, allowing processes to execute with root privileges.
- **Recommended Fix:** Add 'USER <non-root-uid>' instruction before container entrypoint.

### 5. [HIGH] `ci-github-script-injection-pr` — ci-github-script-injection-pr: GitHub Actions Script Injection via PR Title

- **Category:** `sast`
- **Location:** `.github/workflows/docker-interop-gate.yml:38`
- **Details:** CI/CD workflow or Dockerfile security vulnerability. at .github/workflows/docker-interop-gate.yml:38
- **Recommended Fix:** Pass untrusted GitHub context values via workflow environment variables instead of inline ${{ ... }} shell interpolation.

### 6. [HIGH] `ci-github-script-injection-pr` — ci-github-script-injection-pr: GitHub Actions Script Injection via PR Title

- **Category:** `sast`
- **Location:** `.github/workflows/docker-interop-gate.yml:39`
- **Details:** CI/CD workflow or Dockerfile security vulnerability. at .github/workflows/docker-interop-gate.yml:39
- **Recommended Fix:** Pass untrusted GitHub context values via workflow environment variables instead of inline ${{ ... }} shell interpolation.

### 7. [HIGH] `CKV_DOCKER_1` — CKV_DOCKER_1: Container Runs as Root (Missing Non-Root USER)

- **Category:** `misconfiguration`
- **Location:** `docker/Dockerfile.base.alpine:1`
- **Details:** Container does not specify a non-root USER, allowing processes to execute with root privileges.
- **Recommended Fix:** Add 'USER <non-root-uid>' instruction before container entrypoint.

### 8. [HIGH] `CKV_DOCKER_1` — CKV_DOCKER_1: Container Runs as Root (Missing Non-Root USER)

- **Category:** `misconfiguration`
- **Location:** `docker/Dockerfile.base.apt:1`
- **Details:** Container does not specify a non-root USER, allowing processes to execute with root privileges.
- **Recommended Fix:** Add 'USER <non-root-uid>' instruction before container entrypoint.

### 9. [HIGH] `CKV_DOCKER_11` — CKV_DOCKER_11: Unverified Script Piped Directly to Shell

- **Category:** `misconfiguration`
- **Location:** `docker/Dockerfile.rust:19`
- **Details:** Piping remote HTTP downloads directly into sh or bash executes unverified code without checksum verification.
- **Recommended Fix:** Download scripts first, verify their SHA-256 checksum against an expected digest, then execute.

### 10. [HIGH] `CKV_DOCKER_1` — CKV_DOCKER_1: Container Runs as Root (Missing Non-Root USER)

- **Category:** `misconfiguration`
- **Location:** `docker/Dockerfile.rust:1`
- **Details:** Container does not specify a non-root USER, allowing processes to execute with root privileges.
- **Recommended Fix:** Add 'USER <non-root-uid>' instruction before container entrypoint.

### 11. [HIGH] `go-cmdi-exec-combined` — go-cmdi-exec-combined: Command Execution via Dynamic exec.Command

- **Category:** `sast`
- **Location:** `pigeonhole/build.go:52`
- **Details:** Go application security vulnerability or insecure coding pattern. at pigeonhole/build.go:52
- **Recommended Fix:** Invoke the target binary directly with exec.Command(bin, args...) without sh -c shell evaluation.

### 12. [HIGH] `go-cmdi-exec-combined` — go-cmdi-exec-combined: Command Execution via Dynamic exec.Command

- **Category:** `sast`
- **Location:** `pigeonhole/build.go:170`
- **Details:** Go application security vulnerability or insecure coding pattern. at pigeonhole/build.go:170
- **Recommended Fix:** Invoke the target binary directly with exec.Command(bin, args...) without sh -c shell evaluation.

### 13. [HIGH] `go-cmdi-exec-combined` — go-cmdi-exec-combined: Command Execution via Dynamic exec.Command

- **Category:** `sast`
- **Location:** `server/cborplugin/client.go:336`
- **Details:** Go application security vulnerability or insecure coding pattern. at server/cborplugin/client.go:336
- **Recommended Fix:** Invoke the target binary directly with exec.Command(bin, args...) without sh -c shell evaluation.

