#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

for cmd in k3d kubectl docker curl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
done

CLUSTER_NAME="${CLUSTER_NAME:-goturbo-maven-smoke}"
NAMESPACE="${NAMESPACE:-goturbo-smoke}"
APP_NAME="goturbo"
IMAGE_TAG="${IMAGE_TAG:-goturbo:maven-smoke-k3d}"
PORT="${PORT:-18081}"
MAVEN_NAMESPACE="${MAVEN_NAMESPACE:-maven-smoke}"

cleanup() {
  kubectl delete ns "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
  k3d cluster delete "$CLUSTER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Creating k3d cluster: $CLUSTER_NAME"
k3d cluster create "$CLUSTER_NAME" --wait

echo "Building image: $IMAGE_TAG"
docker build -t "$IMAGE_TAG" "$ROOT_DIR" >/dev/null

echo "Importing image into k3d cluster"
k3d image import "$IMAGE_TAG" -c "$CLUSTER_NAME"

kubectl create namespace "$NAMESPACE"

cat <<YAML | kubectl -n "$NAMESPACE" apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${APP_NAME}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${APP_NAME}
  template:
    metadata:
      labels:
        app: ${APP_NAME}
    spec:
      containers:
        - name: ${APP_NAME}
          image: ${IMAGE_TAG}
          imagePullPolicy: IfNotPresent
          env:
            - name: NO_SECURITY
              value: "true"
          ports:
            - containerPort: 8080
          volumeMounts:
            - name: cache
              mountPath: /tmp/turbo-cache
      volumes:
        - name: cache
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: ${APP_NAME}
spec:
  selector:
    app: ${APP_NAME}
  ports:
    - name: http
      port: 8080
      targetPort: 8080
YAML

echo "Waiting for rollout"
kubectl -n "$NAMESPACE" rollout status deploy/"$APP_NAME" --timeout=120s

echo "Starting port-forward on :$PORT"
kubectl -n "$NAMESPACE" port-forward svc/"$APP_NAME" "$PORT:8080" >/tmp/goturbo-maven-smoke-port-forward.log 2>&1 &
PF_PID=$!
trap 'kill $PF_PID >/dev/null 2>&1 || true; cleanup' EXIT

for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null; then
    break
  fi
  sleep 0.2
done
curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null

echo "WebDAV write/read smoke check"
curl -fsS -X PUT --data-binary "hello-k3d-cache" \
  "http://127.0.0.1:$PORT/maven/$MAVEN_NAMESPACE/v1.1/com.example/smoke/item.txt" >/dev/null

RESP="$(curl -fsS "http://127.0.0.1:$PORT/maven/$MAVEN_NAMESPACE/v1.1/com.example/smoke/item.txt")"
if [[ "$RESP" != "hello-k3d-cache" ]]; then
  echo "unexpected payload from Maven WebDAV endpoint: $RESP" >&2
  exit 1
fi

echo "k3d smoke test completed successfully"
echo "Verified WebDAV PUT/GET through Kubernetes service"
