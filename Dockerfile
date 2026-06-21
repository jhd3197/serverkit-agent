# ServerKit Agent - Docker Image
# Multi-stage build for minimal image size

# ============================================
# Stage 1: Build agent desktop UI (embedded by //go:embed)
# ============================================
FROM node:20-alpine AS ui-builder

WORKDIR /build

# Install UI dependencies first for better layer caching
COPY ui/package.json ui/package-lock.json ./ui/
RUN cd ui && npm ci

# Copy UI source and build it. Vite outputs to ../internal/agentui/dist,
# which is the exact path the Go embed directive expects.
COPY ui/ ./ui/
RUN cd ui && npm run build

# ============================================
# Stage 2: Build Go binary
# ============================================
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Copy the built UI bundle into the Go package that embeds it.
# This must happen before `go build` because //go:embed is validated
# at compile time.
COPY --from=ui-builder /build/internal/agentui/dist ./internal/agentui/dist

# Build arguments for version info
ARG VERSION=dev
ARG BUILD_TIME=unknown
ARG GIT_COMMIT=unknown

# Target architecture for multi-platform builds (buildx sets these).
ARG TARGETOS=linux
ARG TARGETARCH=amd64

# Build the agent binary
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s \
        -X main.Version=${VERSION} \
        -X main.BuildTime=${BUILD_TIME} \
        -X main.GitCommit=${GIT_COMMIT}" \
    -o serverkit-agent \
    ./cmd/agent

# ============================================
# Stage 3: Runtime
# ============================================
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    docker-cli \
    docker-cli-compose

# Create non-root user
RUN addgroup -g 1000 serverkit && \
    adduser -u 1000 -G serverkit -s /bin/sh -D serverkit

# Create directories
RUN mkdir -p /etc/serverkit-agent /var/log/serverkit-agent && \
    chown -R serverkit:serverkit /etc/serverkit-agent /var/log/serverkit-agent

# Copy binary from builder
COPY --from=builder /build/serverkit-agent /usr/local/bin/serverkit-agent

# Set permissions
RUN chmod +x /usr/local/bin/serverkit-agent

# Volume for configuration persistence
VOLUME ["/etc/serverkit-agent"]

# Volume for logs
VOLUME ["/var/log/serverkit-agent"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD serverkit-agent status || exit 1

# Labels
LABEL org.opencontainers.image.title="ServerKit Agent" \
      org.opencontainers.image.description="Remote server management agent for ServerKit" \
      org.opencontainers.image.vendor="ServerKit" \
      org.opencontainers.image.source="https://github.com/jhd3197/serverkit-agent"

# Default user (can be overridden for Docker socket access)
USER serverkit

ENTRYPOINT ["serverkit-agent"]
CMD ["start"]
