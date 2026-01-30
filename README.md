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

| Flag                    | Env Variable           | Description                                                                                                         |
| ----------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `-trusted-issuers`      | `TRUSTED_ISSUERS`      | Comma-separated list of trusted OIDC issuer URLs. Supports mapping specific discovery URLs: `issuer=discovery_url`. |
| `-required-audience`    | `REQUIRED_AUDIENCE`    | Required `aud` claim in the JWT.                                                                                    |
| `-public-key-path`      | `PUBLIC_KEY_PATH`      | Path to a static RSA public key (PEM) for verifying tokens manually.                                                |
| `-insecure-skip-verify` | `INSECURE_SKIP_VERIFY` | Skip TLS verification for OIDC discovery (useful for self-signed internal certs).                                   |

**Example: Multiple Kubernetes Clusters**
You can trust the same issuer name from multiple discovery endpoints (e.g., for multi-cluster support):

```bash
export TRUSTED_ISSUERS="https://kubernetes.default.svc=https://cluster1.local,https://kubernetes.default.svc=https://cluster2.local"
```

**Example: Authenticated Client Usage**
If security is enabled, you must provide a token:

```bash
export TURBO_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
turbo build
```

### Namespace Isolation & RBAC

If running in a multi-tenant environment (like Kubernetes), you can enforce strict isolation based on JWT claims.

| Flag                   | Env Variable          | Description                                                                                                               |
| ---------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `-namespace-isolation` | `NAMESPACE_ISOLATION` | Use the Kubernetes namespace (from the token) as the `TURBO_TEAM` ID.                                                     |
| `-role-pattern`        | `ROLE_PATTERN`        | Pattern to validate roles against the namespace. Use `{namespace}` as a placeholder. Example: `sec-role-{namespace}-dev`. |
| `-role-claim-path`     | `ROLE_CLAIM_PATH`     | JSON path to the roles/groups claim in the JWT. Default: `groups`.                                                        |
| `-admin-roles`         | `ADMIN_ROLES`         | Comma-separated list of roles that have universal write access.                                                           |

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
