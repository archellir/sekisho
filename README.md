# Sekisho (関所 🇯🇵)

A minimal zero-trust proxy for personal use. Single Go binary, no dependencies.

> **関所 (Sekisho)** - Japanese checkpoint stations that controlled access during the Edo period.

## Features ✨

- **OAuth2/OIDC Authentication** - Google, GitHub, Microsoft providers
- **Rule-based Authorization** - Flexible policy engine with glob patterns
- **HTTP/HTTPS Reverse Proxy** - Full reverse proxy with connection pooling
- **Session Management** - AES-256-GCM encrypted cookies
- **Rate Limiting** - Token bucket algorithm with per-IP/user limits
- **Security Headers** - Comprehensive security header injection
- **Audit Logging** - JSON logs to stdout for log aggregation
- **Health Checks** - Ready for monitoring stack integration
- **Metrics Endpoint** - Prometheus compatible metrics at `/metrics`

## Architecture 🏗️

Pure Go standard library implementation:
- **Zero external dependencies** - Only Go stdlib
- **Single binary deployment** - ~10MB static binary
- **In-memory session storage** - No external database required  
- **YAML configuration** - Simple, environment variable interpolation
- **Kubernetes ready** - Single deployment file
- **Security first** - Built with zero-trust principles

## Quick Start 🚀

### 1. Build from source
```bash
git clone https://github.com/archellir/sekisho.git
cd sekisho
make build
```

### 2. Generate configuration
```bash
./bin/sekisho -generate-config > config.yaml
```

### 3. Configure OAuth (Google example)
```bash
export OAUTH_CLIENT_ID="your-google-client-id"
export OAUTH_CLIENT_SECRET="your-google-client-secret"
```

### 4. Run
```bash
./bin/sekisho -config config.yaml
```

## Configuration 📝

### Basic Setup
```yaml
server:
  listen_addr: ":8080"
  
auth:
  provider: "google"
  client_id: "${OAUTH_CLIENT_ID}"
  client_secret: "${OAUTH_CLIENT_SECRET}"
  redirect_url: "https://auth.yourdomain.com/callback"

upstream:
  - host: "app.yourdomain.com"
    target: "http://app-service:8080"
    
policy:
  default_action: "deny"
  rules:
    - name: "public_access"
      path: "/public/*"
      action: "allow"
    - name: "authenticated_access" 
      path: "/*"
      require_auth: true
      action: "allow"
```

### Advanced Policy Rules
```yaml
policy:
  rules:
    - name: "admin_only"
      path: "/admin/*"
      methods: ["GET", "POST"]
      allow_users: ["admin@company.com"]
      action: "allow"
      
    - name: "api_access"
      path: "/api/*"
      allow_users: ["*@company.com"]  # Wildcard domain matching
      deny_ips: ["192.168.1.100"]     # IP blacklisting
      action: "allow"
```

## Deployment 🚀

### Docker
```bash
make docker
docker run -p 8080:8080 \
  -e OAUTH_CLIENT_ID=your-id \
  -e OAUTH_CLIENT_SECRET=your-secret \
  sekisho:latest
```

### Kubernetes (behind nginx ingress)
```bash
# Edit OAuth credentials in deployments/k8s/sekisho.yaml first
kubectl apply -f deployments/k8s/sekisho.yaml
```

The deployment assumes you have nginx ingress handling TLS termination and routing traffic to the `sekisho` service on port 8080. Metrics are exposed on `/metrics` for your existing monitoring stack.

## Security 🔒

### Built-in Security Features
- **AES-256-GCM encryption** for session cookies
- **HMAC-SHA256 signatures** for cookie authentication  
- **Constant-time comparisons** for all token validation
- **CSRF protection** with secure token generation
- **Security headers** (CSP, HSTS, X-Frame-Options, etc.)
- **Rate limiting** with token bucket algorithm
- **Request ID tracking** for audit trails

### OAuth2 Security
- **State parameter validation** prevents CSRF attacks
- **Secure redirect validation** prevents open redirects
- **Token exchange** uses client credentials securely
- **Session expiration** and automatic cleanup

### Network Security  
- **TLS termination** handled by nginx ingress
- **Minimal container** with basic security
- **Service-to-service** communication via ClusterIP

## Performance 📊

- **Sub-10ms latency** overhead for authenticated requests
- **1000+ concurrent connections** supported
- **Connection pooling** with keep-alive
- **DNS caching** (5-minute TTL)
- **Policy decision caching** (10,000 entry LRU cache)
- **Memory usage** <100MB for typical workloads

## Monitoring 📈

### Health Checks
```bash
curl http://localhost:8080/health
# {"status":"healthy","service":"sekisho"}
```

### Metrics (Prometheus compatible)
```bash
curl http://localhost:8080/metrics
```

### Audit Logs
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "user": "user@example.com",
  "action": "allowed",
  "method": "GET",
  "path": "/api/users",
  "ip": "10.0.0.1"
}
```

## Development 🛠️

### Prerequisites
- Go 1.25.0+
- Make

### Commands
```bash
make help                 # Show all available commands
make build               # Build binary
make test                # Run tests  
make test-cover         # Run tests with coverage
make docker             # Build Docker image
make deploy-k8s         # Deploy to Kubernetes
```

### Testing
```bash
# Unit tests
go test ./tests/unit/

# Integration tests  
go test ./tests/integration/

# All tests with coverage
make test-cover
```

## Comparison

| Feature | Sekisho | Pomerium | Teleport | Traefik | nginx | Authentik | Cloudflare ZT |
|---------|---------|----------|----------|---------|-------|-----------|---------------|
| Dependencies | 0 | Many (Go) | Many (Go) | Few (Go) | Few | Many (Python) | None (SaaS) |
| Binary Size | ~10MB | ~15MB | ~50MB | ~25MB | <1MB | N/A (Container) | ~10MB (agent) |
| Memory Usage | <100MB | ~200MB | >1.3GB | ~300MB | ~50MB | ~2GB | ~50MB (agent) |
| Configuration | YAML | YAML | YAML | YAML/TOML | Config files | Web UI | Web UI |
| OAuth2/OIDC | ✅ Native | ✅ Native | ✅ Native | Via Plugin | Via Lua | ✅ Native (IdP) | ✅ Native |
| Policy Engine | ✅ | ✅ | ✅ RBAC | Limited | Limited | ✅ Flow-based | ✅ Cloud |
| Session Management | ✅ | ✅ | ✅ Certs | Via Plugin | Via Lua | ✅ | ✅ |
| Certificate Auth | ❌ | ✅ | ✅ (Built-in CA) | ❌ | ✅ mTLS | ✅ | ✅ |
| SSH Proxy | ❌ | ✅ (v0.30+) | ✅ | ❌ | ❌ | ✅ (2025+) | ✅ |
| TCP Proxy | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Behind Ingress | ✅ | ❌ | ❌ | ✅ | N/A | ✅ | N/A |
| Deployment | Single binary | Single binary | Multi-node | Single binary | System service | Docker Compose | SaaS + agent |
| Target Use Case | Personal/Homelab | SMB/Enterprise | Enterprise DevOps | Cloud Native | Web Server | SMB/Homelab | Enterprise/Teams |
| License | MIT | Apache 2.0 | AGPL/Commercial | MIT | BSD | MIT | Commercial |

## License

MIT License - see [LICENSE](LICENSE) file.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Roadmap

- [ ] JWT validation with JWKS support
- [ ] Rate limiting by endpoint
- [ ] Request/response body logging options
- [ ] WebAssembly plugin support
