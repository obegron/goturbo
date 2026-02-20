# Maven WebDAV Smoke

This integration directory runs a real Maven build against a real `goturbo` Docker container.

## What It Does

1. Builds local `goturbo` image.
2. Starts container with `NO_SECURITY=true`.
3. Runs Maven build using the Apache Maven Build Cache Extension against `/maven/<namespace>/...`.
4. Verifies remote cache save/read behavior from Maven output.
5. Runs a second Maven build with remote save disabled.

## Run

```bash
./integration/maven-webdav-smoke/run.sh
```

## Run On k3d

Creates a fresh local cluster, deploys `goturbo` with `emptyDir` cache storage, and verifies WebDAV writes/reads.

```bash
./integration/maven-webdav-smoke/run-k3d.sh
```

## Optional Environment Variables

- `PORT` (default: `18080`)
- `NAMESPACE` (default: `maven-smoke`)
- `IMAGE_TAG` (default: `goturbo:maven-smoke`)
- `CONTAINER_NAME` (default: `goturbo-maven-smoke`)
- `MAVEN_BUILD_CACHE_EXTENSION_VERSION` (default: `1.2.2`)
