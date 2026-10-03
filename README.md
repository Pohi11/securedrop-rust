# SecureDrop

A secure file-transfer service in **Rust** on **AWS**. Authenticated users upload and share files, and the bytes travel **directly between clients and S3** through short-lived presigned URLs. The API handles identity, policy, integrity and audit, and never touches file contents.

```
Client ──JSON──► ALB + WAF ──► Rust API (ECS Fargate) ──► RDS Postgres · ElastiCache Valkey
   │                                  │ presigns
   └═════════ file bytes (HTTPS, presigned PUT/GET) ═════════► S3 (SSE-KMS, GuardDuty-scanned)
```

## Highlights
- **Presigned uploads that S3 itself enforces.** The exact `Content-Length`, `Content-Type` and `x-amz-checksum-sha256` are signed into each URL, so S3 rejects a body of the wrong size or contents. Completion re-verifies with a HEAD request and a 512-byte magic-byte sniff.
- **Resumable multipart uploads.** Per-part SHA-256 checksums, parallel parts, resume via ListParts, composite-checksum verification, and a `FOR UPDATE SKIP LOCKED` cleanup worker for abandoned uploads.
- **Careful authentication.** Argon2id behind a concurrency limit, timing-equalised logins, 15-minute JWTs, and rotating refresh tokens with **family-wide reuse detection**. Sessions are revoked instantly through a Redis denylist.
- **Authorization as one pure function.** IDOR-proof, 404 for strangers (no existence oracle), read-only grants, and hashed, count-limited share links with an atomic counter (verified with a 25-way race).
- **Hardening.** Distributed GCRA rate limiting in Redis (Lua), security headers, strict CORS, body limits, timeouts, an append-only audit trail, request IDs, Prometheus metrics, and separate liveness and readiness probes.
- **Infrastructure as code.** A 3-tier VPC with endpoints, a customer-managed KMS key everywhere, a TLS-only and app-only bucket policy, GuardDuty malware gating, RDS and Valkey with **secrets that never enter Terraform state** (ephemeral values and write-only arguments), WAF, alarms, and keyless GitHub OIDC deploys. Checkov: 360 passed, 0 failed.
- **Supply chain.** cargo-deny, Trivy, gitleaks and Dependabot in CI. The first cargo-deny run found real advisories (a duplicate legacy TLS stack and an RSA timing attack pulled in by unused default features), which were fixed at the root rather than suppressed.

## Tech stack
Rust 2024 · Tokio · Axum 0.8 · tower-http · SQLx 0.9 (compile-time checked) · AWS SDK for Rust · jsonwebtoken · argon2 · redis · tracing · metrics/Prometheus · Docker (distroless) · Terraform (AWS provider 6) · GitHub Actions.

## Repository layout
```
crates/api/        Axum API: auth, files, shares, storage, middleware, telemetry, migrations, tests
crates/common/     wire types shared by the API and clients
crates/cli/        `securedrop` CLI and client library (resumable uploads, verified downloads)
deploy/docker/     multi-stage Dockerfile
infra/terraform/   bootstrap, envs/dev, modules (network, kms, s3, database, cache, ecs, waf, ...)
.github/workflows/ CI, CD (OIDC), scheduled security scans
docs/              architecture, threat model, API reference
```

## Quick start (local)
Prerequisites: Rust (stable) and Docker.
```bash
cp .env.example .env
docker compose up -d postgres redis s3 s3-init
cargo run -p securedrop-api                     # http://127.0.0.1:8080
# in another shell
cargo run -p securedrop-cli -- register me@example.com   # prompts for a password (12+ characters)
cargo run -p securedrop-cli -- login me@example.com
cargo run -p securedrop-cli -- upload ./some-file.pdf
cargo run -p securedrop-cli -- ls
cargo run -p securedrop-cli -- download <file-id> -o copy.pdf
cargo run -p securedrop-cli -- link <file-id> --max-downloads 1
```
Or run the API in its production container: `docker compose up -d --build api`.

## Tests
```bash
docker compose up -d postgres redis s3
cargo test --workspace          # 81 tests: unit + integration against real Postgres, Redis and an S3-compatible store
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
```

## Deployment on AWS
SecureDrop runs on AWS, with every resource defined in Terraform under `infra/terraform`:

| Layer | Choice |
|---|---|
| Compute | ECS Fargate (non-root, read-only root filesystem), autoscaling 2-6 tasks |
| Edge | ALB with TLS 1.3/1.2 and AWS WAF (managed rules + rate limits) |
| Storage | S3 with SSE-KMS, versioning, lifecycle rules and GuardDuty Malware Protection |
| Data | RDS PostgreSQL 17 (TLS enforced) and ElastiCache Valkey (TLS + AUTH), in private subnets with no internet route |
| Secrets | Secrets Manager, injected at task start; generated as ephemeral values so they never enter Terraform state |
| Network | 3-tier VPC across two AZs, with VPC endpoints for S3, ECR, Logs, Secrets Manager, KMS and STS |
| Observability | CloudWatch Logs, alarms (5xx, latency, unhealthy targets, refresh-token reuse) and an SNS alert topic |
| Delivery | GitHub Actions with OIDC: image scanned before push, immutable SHA tags, rolling ECS deploy with circuit-breaker rollback |

The `bootstrap` stack creates the remote-state bucket first; `envs/dev` then brings up the rest:
```bash
cd infra/terraform/bootstrap && terraform init && terraform apply
cd ../envs/dev
cp backend.hcl.example backend.hcl && cp terraform.tfvars.example terraform.tfvars
terraform init -backend-config=backend.hcl && terraform apply
```
Application releases go through [`.github/workflows/cd.yml`](.github/workflows/cd.yml). The stack is designed to be brought up and torn down between sessions rather than left running, since RDS, ElastiCache, the NAT gateway and the ALB bill by the hour.

## Documentation
- [Architecture](docs/architecture.md): diagrams, request flows, decisions and failure behaviour
- [Threat model](docs/threat-model.md): STRIDE analysis and accepted risks
- [API reference](docs/api.md)

## How I built this
I built SecureDrop using spec-driven development with Claude, which gave me a deliberate and repeatable process. I worked in phases, and each phase followed the same steps. For each part of the system, I first defined the requirement and shaped it into a spec that set out the behavior, the trade-offs, and the direction I wanted, and I refined that spec before any code was written. I then implemented against that spec with Claude, and I reviewed and tested each phase before moving on to the next. The commit history follows those phases, from the workspace and schema through authentication, transfers, sharing, hardening, observability, the CLI, the container image, Terraform and CI/CD.

## Known gaps and roadmap
These are deliberate and documented in the [threat model](docs/threat-model.md):
- Registration reveals whether an email is already registered; an email-verification flow would close it.
- Share-link download limits count issued URLs, bounded by a 60-second URL lifetime.
- For multipart uploads, S3 verifies every part and the composite checksum; the whole-file SHA-256 is verified by the downloading client.
- Access tokens use HS256; EdDSA with a JWKS endpoint is the next step if other services need to verify them.
- Migrations run on startup; a separate migration task with a DML-only runtime role is the stricter setup.
- Single region; cross-region replication and multi-region KMS keys are on the roadmap.

## License
MIT
