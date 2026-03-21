#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SMOKE_DIR="$ROOT_DIR/integration/maven-cache-smoke"

for cmd in docker mvn curl sed find; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
done

PORT="${PORT:-18080}"
NAMESPACE="${NAMESPACE:-maven-smoke}"
IMAGE_TAG="${IMAGE_TAG:-goturbo:maven-smoke}"
CONTAINER_NAME="${CONTAINER_NAME:-goturbo-maven-smoke}"
EXT_VERSION="${MAVEN_BUILD_CACHE_EXTENSION_VERSION:-1.2.2}"

WORK_DIR="$(mktemp -d)"
PROJECT_DIR="$WORK_DIR/project"
REPO1_DIR="$WORK_DIR/m2-repo-1"
REPO2_DIR="$WORK_DIR/m2-repo-2"
mkdir -p "$PROJECT_DIR" "$REPO1_DIR" "$REPO2_DIR"

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Building image: $IMAGE_TAG"
docker build -t "$IMAGE_TAG" "$ROOT_DIR" >/dev/null

echo "Starting container: $CONTAINER_NAME on :$PORT"
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d --rm \
  --name "$CONTAINER_NAME" \
  -p "$PORT:8080" \
  -e NO_SECURITY=true \
  "$IMAGE_TAG" >/dev/null

echo "Waiting for goturbo health endpoint"
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null; then
    break
  fi
  sleep 0.2
done
curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null

cp -R "$SMOKE_DIR/app/." "$PROJECT_DIR/"
REMOTE_URL="http://127.0.0.1:$PORT/maven/$NAMESPACE/"
sed -i "s|__REMOTE_URL__|$REMOTE_URL|g" "$PROJECT_DIR/.mvn/maven-build-cache-config.xml"
sed -i "s|<version>1.2.2</version>|<version>$EXT_VERSION</version>|g" "$PROJECT_DIR/.mvn/extensions.xml"

echo "First Maven build (remote save enabled)"
RUN1_LOG="$WORK_DIR/mvn-run1.log"
mvn -B -ntp \
  -s "$SMOKE_DIR/settings.xml" \
  -f "$PROJECT_DIR/pom.xml" \
  -Dmaven.repo.local="$REPO1_DIR" \
  -Dmaven.build.cache.remote.save.enabled=true \
  clean package | tee "$RUN1_LOG"

if ! grep -q "Saved to remote cache" "$RUN1_LOG"; then
  echo "expected remote cache save in first build output" >&2
  exit 1
fi
COUNT1="$(grep -c "Saved to remote cache" "$RUN1_LOG" | tr -d ' ')"
echo "Remote save events after first build: $COUNT1"

echo "Second Maven build (remote save disabled)"
RUN2_LOG="$WORK_DIR/mvn-run2.log"
mvn -B -ntp \
  -s "$SMOKE_DIR/settings.xml" \
  -f "$PROJECT_DIR/pom.xml" \
  -Dmaven.repo.local="$REPO2_DIR" \
  -Dmaven.build.cache.remote.save.enabled=false \
  -Dmaven.build.cache.remote.load.enabled=true \
  clean package | tee "$RUN2_LOG"

if grep -q "Saved to remote cache" "$RUN2_LOG"; then
  echo "unexpected remote cache save in second build output (save disabled)" >&2
  exit 1
fi

echo "Smoke test completed successfully"
echo "Remote cache save/read behavior verified"
