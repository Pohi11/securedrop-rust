# SecureDrop threat model

Method: STRIDE per component and trust boundary, then the residual risks we've accepted.

## Assets
1. **File contents**: confidentiality and integrity.
2. **Credentials**: passwords, refresh tokens, access tokens, share-link tokens, presigned URLs.
3. **Metadata**: who owns and shares what (filenames can be sensitive).
4. **Audit trail**: integrity, for incident response.
5. **Availability** of upload and download.

## Trust boundaries
```
[Internet clients] ──TB1──> [WAF/ALB] ──TB2──> [API tasks] ──TB3──> [RDS, Valkey]
        │                                          │
        └──────────────TB4 (presigned)──────> [S3] <──TB5── [API via VPC endpoint]
[GitHub Actions] ──TB6 (OIDC)──> [AWS deploy role]
```

## STRIDE analysis

### Spoofing
| Threat | Mitigation | Code / config |
|---|---|---|
| Password guessing / credential stuffing | Argon2id; per-IP GCRA limit (10/min) fail-closed; account lockout; WAF auth rate rule; zxcvbn policy | `auth/password.rs`, `middleware/rate_limit.rs`, `modules/waf` |
| Stolen access token | 15-min lifetime; session revocation via Redis; `iss`/`aud`/alg pinning | `auth/jwt.rs`, `auth/revocation.rs` |
| Stolen refresh token | Single-use rotation; reuse revokes the whole family *and* its live access tokens; CloudWatch alarm on reuse | `auth/service.rs::refresh`, `modules/observability` |
| JWT forgery (`alg: none`, key confusion) | Algorithm pinned to HS256; 256-bit+ secret enforced at boot | `auth/jwt.rs`, `config.rs::validate` |
| Spoofed client IP (`X-Forwarded-For`) | Only trusted behind the ALB; right-most entry used | `middleware/client_meta.rs` |
| CI impersonation | OIDC trust pinned to repo plus `production` environment | `modules/github_oidc` |

### Tampering
| Threat | Mitigation |
|---|---|
| Uploading different bytes than declared | SHA-256 and Content-Length signed into presigned URLs (S3 rejects); per-part checksums; composite checksum verified; client-side verification on download |
| Changing content type after validation (e.g. to `text/html`) | Content-Type is a signed header; downloads force signed `Content-Disposition: attachment` |
| Executables or type-spoofed files | Magic-byte sniff of the first 512 bytes at completion; GuardDuty Malware Protection gates downloads |
| Overwriting another user's object | Server-generated keys `u/{owner}/{file}`; task role limited to `u/*`; uploads only via URLs we signed |
| SQL injection | Compile-time-checked, parameterised `sqlx` queries only |
| Racing state transitions (double complete, over-redeeming links, quota races) | Compare-and-set UPDATEs, single-statement conditional counters, `FOR UPDATE` row locks |
| Request smuggling and malformed headers | ALB `drop_invalid_header_fields`; hyper's strict parser |
| Tampering with infrastructure | Terraform in git, reviewed; state bucket versioned and encrypted; provider checksums in the lock file |

### Repudiation
| Threat | Mitigation |
|---|---|
| "I didn't download/share/delete that" | `audit_events` (no FKs, survives deletion) plus structured audit logs in CloudWatch, both with request id, IP and user agent |
| Log forgery via request ids | Incoming `x-request-id` validated (≤64 chars, `[A-Za-z0-9_-]`) |
| Audit row tampering | Recommended: app DB role INSERT/SELECT only on `audit_events`; CloudWatch copy with 1-year retention |

### Information disclosure
| Threat | Mitigation |
|---|---|
| IDOR (`/files/<someone-else's-id>`) | Central `load_authorized`; strangers get 404, so there's no existence oracle |
| Enumerating accounts | Same body and *same timing* (dummy Argon2) for unknown user vs. wrong password; locked == wrong password. *Residual:* registration 409 and grant-by-email reveal existence (see accepted risks) |
| Data at rest exposure | SSE-KMS with CMK on S3; KMS on RDS, Valkey, Secrets, Logs, ECR, SNS |
| Data in transit | TLS everywhere: ALB TLS 1.2+, bucket policy denies non-TLS and TLS < 1.2, `rds.force_ssl`, `rediss://` |
| Secrets in logs | `SecretString`, redacted `Debug` on DTOs, Authorization marked sensitive, path-only URIs in spans |
| Secrets in Terraform state | Ephemeral values + write-only arguments |
| Presigned URL leakage | 60 s–5 min TTL; scoped to one object and method; never logged |
| Share-token leakage | 256-bit, hashed at rest, sent in POST bodies (not URLs), revocable, expiring, count-limited |
| Stored XSS via uploaded HTML/SVG | MIME allowlist excludes them; forced `attachment`; `nosniff` on API responses |
| DB leak exposes tokens | Only SHA-256 of refresh and share tokens stored |
| Metrics exposure | `/metrics` on a separate internal port, not routed by the ALB |

### Denial of service
| Threat | Mitigation |
|---|---|
| Request floods | WAF rate rules + IP reputation; app GCRA per user/IP; ECS autoscaling |
| Argon2 memory exhaustion | Semaphore caps concurrent hashes; 128-char password max |
| Large request bodies | 64 KiB body limit (the API never receives files) |
| Slow dependencies piling up requests | 15 s request timeout (503), bounded pool acquire timeout, readiness timeouts |
| Quota exhaustion via parallel pending uploads | Pending uploads count against the quota, under a row lock |
| Abandoned uploads consuming storage | Cleanup worker + S3 lifecycle `AbortIncompleteMultipartUpload` |
| Account lockout abuse | Temporary (15 min) lock; per-IP limits slow the attacker |

### Elevation of privilege
| Threat | Mitigation |
|---|---|
| Grantee escalating to owner actions | `decide()` policy table, exhaustively unit-tested |
| RCE in the API process | No shell or package manager (distroless), non-root, read-only rootfs, all capabilities dropped, no ECS Exec |
| Compromised task credentials | Task role limited to `bucket/u/*` object ops and KMS *via S3 only*; no IAM, no other buckets |
| Compromised CI | Deploy role can push one repo and update one service; `PassRole` restricted to two roles and the ECS service |
| Dependency compromise or vulnerabilities | cargo-deny (advisories, licenses, sources), Trivy, Dependabot, `--locked` builds |

## Accepted risks and future work
1. **Registration reveals whether an email exists** (409). Fix: email verification flow with an identical response either way.
2. **Share-link "downloads" count issued URLs, not completed downloads.** Bounded by a 60 s URL TTL.
3. **Whole-file SHA-256 of multipart uploads is verified by the downloading client, not the server.** Parts and the composite are server-verified. Fix: async verifier that streams the object once.
4. **Grant-by-email reveals account existence to authenticated users.** Fix: invite flow.
5. **HS256 shared secret.** Fine for one service; switch to EdDSA + JWKS if other services verify tokens.
6. **Auto-migrations on boot run with DDL privileges.** Fix: a separate migration task/role; the runtime role gets DML only.
7. **GitHub Actions pinned by tag, not SHA.** Fix: pin to SHAs and let Dependabot update them.
8. **No MFA.** Fix: TOTP/WebAuthn step-up, especially for sharing.
9. **Single region.** Fix: S3 CRR + multi-region KMS keys + RDS cross-region replicas, if RPO/RTO requires.
