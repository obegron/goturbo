# Stage 1: Builder
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install git for fetching dependencies and ca-certificates for the final image
RUN apk add --no-cache git ca-certificates

# Create a non-root user 'turbo' (uid 10001) for the scratch image
# We write this to a file so we can copy it later
RUN echo "turbo:x:10001:10001:turboUser:/:" > /etc/passwd_scratch

# Copy go mod and sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY main.go .

# Build the binary
# CGO_ENABLED=0 creates a statically linked binary
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o goturbo main.go

# Create the cache directory structure in the builder stage
RUN mkdir -p /tmp/turbo-cache

# Stage 2: Runtime
# "scratch" is an empty image - no shell, no libraries, just the kernel API.
FROM scratch

WORKDIR /app

# Copy CA Certificates to enable HTTPS (required for OIDC)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the user definition
COPY --from=builder /etc/passwd_scratch /etc/passwd

# Copy binary from builder
COPY --from=builder /app/goturbo .

# Copy the cache directory and set ownership to our 'turbo' user (10001)
COPY --from=builder --chown=10001:10001 /tmp/turbo-cache /tmp/turbo-cache

# Run as non-root user
USER 10001

# Expose port
EXPOSE 8080

# Run the service
ENTRYPOINT ["/app/goturbo"]
