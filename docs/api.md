# SecureDrop API reference (v1)

Base path: `/api/v1`. JSON in and out. Authenticated endpoints need `Authorization: Bearer <access_token>`. Every response carries `x-request-id`.

## Errors
Every non-2xx response has the same shape:
```json
{ "error": { "code": "validation_error", "message": "password must be at least 12 characters" } }
```
| Status | `code` | Meaning |
|---|---|---|
| 400 | `bad_request` | Malformed JSON, wrong content type, malformed path id |
| 401 | `unauthorized` / `invalid_credentials` | Missing, invalid, expired or revoked token; wrong login |
| 403 | `forbidden` | You can see the file (grantee) but may not do this |
| 404 | `not_found` | Doesn't exist *or* you have no access (deliberately indistinguishable) |
| 409 | `conflict` | Wrong state (e.g. completing before uploading, sharing a pending file) |
| 413 | `payload_too_large` | File above the size limit, or request body > 64 KiB |
| 422 | `validation_error` / `integrity_check_failed` | Semantically invalid input; uploaded bytes failed verification |
| 429 | `rate_limited` | Slow down; see the `Retry-After` header |
| 503 | `unavailable` | A dependency is down (fail-closed security checks) or the request timed out |
| 507 | `quota_exceeded` | Storage quota would be exceeded |

## Auth
| Method & path | Auth | Body → Response |
|---|---|---|
| `POST /auth/register` | – | `{email, password}` → `201 UserResponse` |
| `POST /auth/login` | – | `{email, password}` → `TokenResponse` |
| `POST /auth/refresh` | – | `{refresh_token}` → `TokenResponse` (old refresh token is now spent) |
| `POST /auth/logout` | ✓ | → `204`, revokes this session |
| `POST /auth/logout-all` | ✓ | → `204`, revokes every session |
| `GET /me` | ✓ | → `UserResponse` (includes quota and usage) |

`TokenResponse`: `{access_token, token_type: "Bearer", expires_in, refresh_token, refresh_expires_at}`.

## Uploads
| Method & path | Body → Response |
|---|---|
| `POST /uploads` | `{filename, content_type, size_bytes, sha256}` → `201 {file_id, upload, upload_expires_at}` |
| `POST /uploads/{id}/parts` | `{parts: [{part_number, sha256}]}` (≤100) → `{parts: [{part_number, size_bytes, request}]}` |
| `GET /uploads/{id}/parts` | → `{part_size, part_count, uploaded_parts, missing_parts, ...}` (resume) |
| `POST /uploads/{id}/complete` | → `FileResponse` (idempotent) |
| `DELETE /uploads/{id}` | → `204`, abort and release quota |

`upload` is either `{"kind": "single", "request": PresignedRequest}` or `{"kind": "multipart", "part_size": n, "part_count": n}`.
`PresignedRequest`: `{method, url, headers, expires_at}`. Send **exactly** these headers; they are part of the signature.

## Files
| Method & path | Response |
|---|---|
| `GET /files?scope=owned\|shared&before=<id>&limit=<1..200>` | `{files: [FileResponse], next_cursor}` |
| `GET /files/{id}` | `FileResponse` |
| `GET /files/{id}/download` | `{file_id, filename, size_bytes, sha256, request}` (5-min presigned GET) |
| `DELETE /files/{id}` | `204` |

## Sharing
| Method & path | Body → Response |
|---|---|
| `POST /files/{id}/grants` | `{email}` → `201 {user_id, email, created_at}` |
| `GET /files/{id}/grants` | → `[GrantResponse]` |
| `DELETE /files/{id}/grants/{user_id}` | → `204` |
| `POST /files/{id}/share-links` | `{expires_in_secs?, max_downloads?}` → `201 {link, token}` (**token shown once**) |
| `GET /files/{id}/share-links` | → `[ShareLinkResponse]` (no tokens) |
| `DELETE /files/{id}/share-links/{link_id}` | → `204` |
| `POST /shared/download` (no auth) | `{token}` → download response (60-s presigned GET) |

## Operational endpoints
| Path | Port | Purpose |
|---|---|---|
| `GET /healthz` | 8080 | Liveness (no dependency checks) |
| `GET /readyz` | 8080 | Readiness: database, Redis, storage |
| `GET /metrics` | 9100 (internal) | Prometheus metrics |

## Limits (defaults; configurable)
Max file 5 GiB · single PUT ≤ 64 MiB · parts 16 MiB · quota 10 GiB/user · upload URL TTL 15 min · download URL TTL 5 min · share URL TTL 60 s · pending uploads expire after 24 h · auth rate 10/min (burst 5) per IP · API rate 300/min (burst 60) per user.
