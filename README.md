# goTurbo

**goTurbo** is a lightweight, on-premise remote cache server for [Vercel Turbo](https://turbo.build/). It is designed to run within your infrastructure (e.g., Kubernetes), allowing you to cache build artifacts securely and efficiently without relying on external services.

The Docker image is available at: `obegron/goturbo:latest`

## Quick Start

### 1. Run the Server

You can run `goturbo` using Docker. For this quick start, we will disable security. By default, it listens on port `8080` and stores artifacts in `/tmp/turbo-cache`.

```bash
docker run -d \
  -p 8080:8080 \
  -v /mnt/turbo-cache:/tmp/turbo-cache \
  -e NO_SECURITY=true \
  obegron/goturbo:latest
```

### 2. Configure the Client (Turbo Repo)

To use this cache with your Turborepo, you need to set the following environment variables in your CI/CD pipeline or local environment.

**Basic Usage:**

```bash
# Point to your goTurbo instance
export TURBO_API="http://localhost:8080"

# Set a Team Name (Acts as a namespace for cache)
export TURBO_TEAM="my-team"

# Run your build
turbo build
```

---

## Configuration

`goturbo` can be configured via command-line flags or environment variables.

| Flag                | Env Variable       | Default            | Description                                             |
| ------------------- | ------------------ | ------------------ | ------------------------------------------------------- |
| `-port`             | `PORT`             | `8080`             | HTTP server port.                                       |
| `-cache-dir`        | `CACHE_DIR`        | `/tmp/turbo-cache` | Directory for storing cache artifacts.                  |
| `-cache-max-age`    | `CACHE_MAX_AGE`    | `24h`              | Max age for cache retention.                            |
| `-no-security`      | `NO_SECURITY`      | `false`            | Disable all authentication. Open for read/write.        |
| `-no-security-read` | `NO_SECURITY_READ` | `false`            | Disable read authentication. Writes still require auth. |

### Security & Authentication

`goturbo` supports verifying JWT tokens from OIDC providers (like Kubernetes).

| Flag                    | Env Variable           | Description                                                                                                                                                                                 |
| ----------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-trusted-issuers`      | `TRUSTED_ISSUERS`      | List of trusted OIDC issuer URLs (separated by `;`). Supports mapping IDs and discovery URLs: `id=issuer=discovery_url` or `issuer=discovery_url`. The `id` is used for admin role scoping. |
| `-required-audience`    | `REQUIRED_AUDIENCE`    | Required `aud` claim in the JWT.                                                                                                                                                            |
| `-public-key-path`      | `PUBLIC_KEY_PATH`      | Path to a static RSA public key (PEM) for verifying tokens manually.                                                                                                                        |
| `-insecure-skip-verify` | `INSECURE_SKIP_VERIFY` | Skip TLS verification for OIDC discovery (useful for self-signed internal certs).                                                                                                           |

**Example: Multi-Cluster with Admin Scoping**
Define IDs for issuers to scope admin privileges. You can use a Kubernetes namespace as an admin role (e.g., `prod:admin-ci-ns`):

```bash
export TRUSTED_ISSUERS="prod=https://k8s.prod.svc=https://oidc.prod.local;dev=https://k8s.dev.svc=https://oidc.dev.local"
export ADMIN_ROLES="prod:ci-admin;prod:admin-ci-ns;global-admin"
```

**Example: Authenticated Client Usage**
If security is enabled, you must provide a token:

```bash
export TURBO_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
turbo build
```

### Bulk Artifact Download (Admin Only)

Admin users can download a tarball of artifacts matching a prefix.

**Endpoint:** `GET /v8/bulk?prefix=<prefix>&namespace=<namespace>`

**Headers:**

- `Authorization: Bearer <token>`

**Requirements:**

- The token must have an admin role configured in `ADMIN_ROLES`.
- If the admin role is scoped (e.g., `prod:admin`), the token's issuer must match the ID (`prod`) defined in `TRUSTED_ISSUERS`.

### Namespace Isolation & RBAC

If running in a multi-tenant environment (like Kubernetes), you can enforce strict isolation based on JWT claims.

| Flag                   | Env Variable          | Description                                                                                                                                                                            |
| ---------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-namespace-isolation` | `NAMESPACE_ISOLATION` | Use the Kubernetes namespace (from the token) as the `TURBO_TEAM` ID.                                                                                                                  |
| `-role-pattern`        | `ROLE_PATTERN`        | Pattern to validate roles against the namespace. Use `{namespace}` as a placeholder. Example: `sec-role-{namespace}-dev`.                                                              |
| `-role-claim-path`     | `ROLE_CLAIM_PATH`     | JSON path to the roles/groups claim in the JWT. Default: `groups`.                                                                                                                     |
| `-admin-roles`         | `ADMIN_ROLES`         | List of roles that have admin access (separated by `;` or `,`). Supports scoping to specific Issuer IDs: `id:role` (e.g., `prod:admin-group` or `prod:k8s-namespace`) or global roles. |

---

## Deployment Example (Kubernetes)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: goturbo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: goturbo
  template:
    metadata:
      labels:
        app: goturbo
    spec:
      containers:
        - name: goturbo
          image: obegron/goturbo:latest
          env:
            - name: TRUSTED_ISSUERS
              value: "https://kubernetes.default.svc"
            - name: NAMESPACE_ISOLATION
              value: "true"
          volumeMounts:
            - name: cache-storage
              mountPath: /tmp/turbo-cache
      volumes:
        - name: cache-storage
          emptyDir: {}
```
