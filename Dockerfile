# Build stage
FROM golang:1.25.0-alpine AS builder

# Install ca-certificates and git for building
RUN apk --no-cache add ca-certificates git

# Set the working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-w -s -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" \
    -a -installsuffix cgo \
    -o sekisho \
    ./cmd/proxy

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates tzdata && \
    adduser -D -s /bin/sh sekisho

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /build/sekisho /usr/local/bin/sekisho

# Copy configuration files
COPY --from=builder /build/configs /app/configs

# Create directories for logs and data
RUN mkdir -p /var/log/sekisho /app/data && \
    chown -R sekisho:sekisho /app /var/log/sekisho

# Switch to non-root user
USER sekisho

# Expose port
EXPOSE 8080 5432

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Default command
ENTRYPOINT ["/usr/local/bin/sekisho"]
CMD ["-config", "/app/configs/config.yaml"]