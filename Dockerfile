FROM golang:1.25-alpine AS builder

WORKDIR /app

RUN apk add --no-cache ca-certificates \
    && echo "turbo:x:10001:10001:turboUser:/:" > /etc/passwd_scratch

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o goturbo . \
    && mkdir -p /tmp/turbo-cache

FROM scratch

WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd_scratch /etc/passwd
COPY --from=builder /app/goturbo .
COPY --from=builder --chown=10001:10001 /tmp/turbo-cache /tmp/turbo-cache

USER 10001
EXPOSE 8080

ENTRYPOINT ["/app/goturbo"]
