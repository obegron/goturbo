# goTurbo

**goTurbo** is a lightweight, on-premise remote cache server for [Vercel Turbo](https://turbo.build/) and Maven (WebDAV). It is designed to run within your infrastructure (e.g., Kubernetes), allowing you to cache build artifacts securely and efficiently without relying on external services.

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

### 3. Configure the Client (Maven Build Cache via WebDAV)

Maven uses a namespace-first path:

- Endpoint pattern: `http(s)://<host>/maven/<namespace>/...`
- Example namespace: `team-a`

The server enforces OIDC/JWT the same way as Turborepo endpoints. The namespace is taken from the first path segment after `/maven/`.

`maven-build-cache-config.xml` example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<cache xmlns="http://maven.apache.org">
  <configuration>
    <enabled>true</enabled>
  </configuration>
  <remote enabled="true" id="goturbo-maven">
    <url>http://localhost:8080/maven/team-a/</url>
  </remote>
</cache>
```

`settings.xml` example with OIDC bearer token header:

```xml
<settings>
  <servers>
    <server>
      <id>goturbo-maven</id>
      <configuration>
        <httpHeaders>
          <property>
            <name>Authorization</name>
            <value>Bearer ${env.OIDC_TOKEN}</value>
          </property>
        </httpHeaders>
      </configuration>
    </server>
  </servers>
</settings>
```

Example:

```bash
export OIDC_TOKEN="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
mvn -Dmaven.build.cache.remote.save.enabled=true verify
```

---

## Configuration

`goturbo` can be configured via command-line flags or environment variables.

| Flag                | Env Variable       | Default            | Description                                             |
| ------------------- | ------------------ | ------------------ | ------------------------------------------------------- |
| `-port`             | `PORT`             | `8080`             | HTTP server port.                                       |
| `-cache-dir`        | `CACHE_DIR`        | `/tmp/turbo-cache` | Directory for storing cache artifacts.                  |
| `-cache-max-age`    | `CACHE_MAX_AGE`    | `24h`              | Max age for cache retention.                            |
| `-disable-turbo`    | `DISABLE_TURBO`    | `false`            | Disable Turborepo endpoints (`/v8/...`). |
| `-disable-maven`    | `DISABLE_MAVEN`    | `false`            | Disable Maven WebDAV endpoint (`/maven/...`). |
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

### Maven Endpoint

- WebDAV endpoint: `/maven/{namespace}/...`
- Supported WebDAV operations are handled by the built-in WebDAV handler (e.g., `PUT`, `GET`, `HEAD`, `PROPFIND`, `MKCOL`, `DELETE`).
- `NO_SECURITY_READ=true` allows unauthenticated read-like methods (`GET`, `HEAD`, `OPTIONS`, `PROPFIND`) for Maven as well.

**Headers:**

- `Authorization: Bearer <token>`

**Requirements:**

- The token must have an admin role configured in `ADMIN_ROLES`.
- If the admin role is scoped (e.g., `prod:admin`), the token's issuer must match the ID (`prod`) defined in `TRUSTED_ISSUERS`.

### Maven Integration Smoke Directory

A standalone smoke setup lives in `integration/maven-webdav-smoke/`:

- real Maven project (`pom.xml`, `.mvn/extensions.xml`, `.mvn/maven-build-cache-config.xml`)
- `settings.xml` for remote server mapping
- script to run against a real `goturbo` Docker container with `NO_SECURITY=true`

Run:

```bash
./integration/maven-webdav-smoke/run.sh
```

k3d variant (cluster + Kubernetes `emptyDir` cache):

```bash
./integration/maven-webdav-smoke/run-k3d.sh
```

### Metrics (Turbo vs Maven)

`/metrics` now exposes both aggregate and per-backend metrics:

- Aggregate (backward compatible): `goturbo_hits_total`, `goturbo_misses_total`, `goturbo_cache_hit_ratio`
- Turborepo-specific: `goturbo_turbo_hits_total`, `goturbo_turbo_misses_total`, `goturbo_turbo_hit_ratio`, `goturbo_turbo_put_success_total`, `goturbo_turbo_put_errors_total`
- Maven-specific: `goturbo_maven_hits_total`, `goturbo_maven_misses_total`, `goturbo_maven_hit_ratio`, `goturbo_maven_put_success_total`, `goturbo_maven_put_errors_total`

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
