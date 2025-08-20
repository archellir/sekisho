# Sekisho (関所 🇯🇵)

A minimal zero-trust proxy for personal use. Single Go binary, no dependencies.

## Features

- OAuth2/OIDC authentication (Google, GitHub)
- Rule-based authorization 
- HTTP/HTTPS reverse proxy
- TCP proxy for databases
- Audit logging
- Session management with encrypted cookies

## Architecture

Pure Go standard library implementation:
- No external dependencies
- Single binary deployment
- In-memory session storage
- YAML configuration
- Kubernetes ready

Built from scratch for security and simplicity.
