package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/archellir/sekisho/internal/audit"
	"github.com/archellir/sekisho/internal/auth"
	"github.com/archellir/sekisho/internal/config"
	"github.com/archellir/sekisho/internal/middleware"
	"github.com/archellir/sekisho/internal/policy"
	"github.com/archellir/sekisho/internal/proxy"
	"github.com/archellir/sekisho/internal/session"
)

type Server struct {
	config        *config.Config
	httpServer    *http.Server
	sessionMgr    *session.Manager
	oauthMgr      *auth.OAuthManager
	policyEngine  *policy.Engine
	proxyHandler  *proxy.ProxyHandler
	tcpProxy      *proxy.TCPProxy
	auditLogger   *audit.Logger
	metrics       *middleware.ProxyMetrics
}

func NewServer(cfg *config.Config) (*Server, error) {
	encryptKey := []byte("your-32-byte-encryption-key-here!")
	signKey := []byte("your-32-byte-signing-key-here!!!")

	sessionMgr, err := session.NewManager(
		encryptKey, signKey,
		cfg.Auth.CookieDomain,
		cfg.Auth.CookieSecure,
		cfg.Auth.SessionDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session manager: %w", err)
	}

	provider, err := auth.NewProvider(cfg.Auth.Provider, cfg.Auth.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth provider: %w", err)
	}

	oauthMgr := auth.NewOAuthManager(
		provider,
		cfg.Auth.ClientID,
		cfg.Auth.ClientSecret,
		cfg.Auth.RedirectURL,
		sessionMgr,
	)

	rules := make([]*policy.Rule, len(cfg.Policy.Rules))
	for i, ruleConfig := range cfg.Policy.Rules {
		rules[i] = &policy.Rule{
			Name:        ruleConfig.Name,
			Path:        ruleConfig.Path,
			Methods:     ruleConfig.Methods,
			Action:      ruleConfig.Action,
			AllowUsers:  ruleConfig.AllowUsers,
			RequireAuth: ruleConfig.RequireAuth,
		}
	}

	policyEngine := policy.NewEngine(rules, cfg.Policy.DefaultAction, cfg.Policy.CacheSize)

	transport := proxy.NewTransport()
	proxyHandler := proxy.NewProxyHandler(cfg, transport)

	var tcpProxy *proxy.TCPProxy
	if len(cfg.TCPProxy) > 0 {
		tcpProxy = proxy.NewTCPProxy(cfg)
	}

	var auditWriter = os.Stdout
	if cfg.Audit.LogPath != "" && cfg.Audit.LogPath != "/dev/stdout" {
		if file, err := os.OpenFile(cfg.Audit.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			auditWriter = file
		}
	}

	auditLogger := audit.NewLogger(auditWriter, cfg.Audit.Enabled, cfg.Audit.IncludeRequestBody, cfg.Audit.IncludeResponseBody)
	metrics := middleware.NewProxyMetrics(cfg.Metrics.Namespace)

	server := &Server{
		config:       cfg,
		sessionMgr:   sessionMgr,
		oauthMgr:     oauthMgr,
		policyEngine: policyEngine,
		proxyHandler: proxyHandler,
		tcpProxy:     tcpProxy,
		auditLogger:  auditLogger,
		metrics:      metrics,
	}

	server.setupRoutes()

	if server.tcpProxy != nil {
		go func() {
			if err := server.tcpProxy.Start(); err != nil {
				log.Printf("TCP proxy failed to start: %v", err)
			}
		}()
	}

	return server, nil
}

func (s *Server) setupRoutes() {
	mux := http.NewServeMux()

	mux.HandleFunc("/auth/login", s.handleLogin)
	mux.HandleFunc("/auth/callback", s.handleCallback)
	mux.HandleFunc("/auth/logout", s.handleLogout)
	mux.HandleFunc("/health", s.handleHealth)
	
	if s.config.Metrics.Enabled {
		mux.Handle(s.config.Metrics.Path, s.metrics)
	}

	securityHeaders := middleware.DefaultSecurityHeaders()
	rateLimiter := middleware.NewRateLimiter(s.config.RateLimit.RequestsPerSecond, s.config.RateLimit.BurstSize)
	recovery := &middleware.Recovery{}
	requestID := &middleware.RequestID{}
	auditMiddleware := audit.NewAuditMiddleware(s.auditLogger)

	handler := securityHeaders.Handler(
		s.metrics.Handler(
			rateLimiter.Handler(
				recovery.Handler(
					requestID.Handler(
						auditMiddleware.Handler(
							s.authMiddleware(
								s.policyMiddleware(
									s.proxyHandler,
								),
							),
						),
					),
				),
			),
		),
	)

	mux.Handle("/", handler)

	s.httpServer = &http.Server{
		Addr:         s.config.Server.ListenAddr,
		Handler:      mux,
		ReadTimeout:  s.config.Server.ReadTimeout,
		WriteTimeout: s.config.Server.WriteTimeout,
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.sessionMgr.IsAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	s.oauthMgr.StartAuthFlow(w, r)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, err := s.oauthMgr.HandleCallback(w, r)
	if err != nil {
		log.Printf("OAuth callback error: %v", err)
		s.auditLogger.LogAuth("", "auth_failed", err.Error(), r)
		s.metrics.RecordAuth(false)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}
	
	s.metrics.RecordAuth(true)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := s.oauthMgr.Logout(w, r); err != nil {
		log.Printf("Logout error: %v", err)
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","service":"sekisho"}`))
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/auth/login" || 
		   r.URL.Path == "/auth/callback" || r.URL.Path == "/auth/logout" {
			next.ServeHTTP(w, r)
			return
		}

		session, err := s.sessionMgr.GetSession(r)
		if err != nil {
			s.oauthMgr.StartAuthFlow(w, r)
			return
		}

		r.Header.Set("X-User-ID", session.UserID)
		r.Header.Set("X-User-Email", session.Email)
		r.Header.Set("X-User-Name", session.Name)

		s.sessionMgr.UpdateLastSeen(r)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) policyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := policy.Context{
			UserID: r.Header.Get("X-User-ID"),
			Email:  r.Header.Get("X-User-Email"),
			Path:   r.URL.Path,
			Method: r.Method,
			IP:     getClientIP(r),
		}

		decision := s.policyEngine.Evaluate(ctx)
		if !decision.Allow {
			log.Printf("Access denied: %s", decision.Reason)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) Start() error {
	log.Printf("Starting Sekisho proxy server on %s", s.config.Server.ListenAddr)
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	log.Println("Shutting down server...")
	return s.httpServer.Shutdown(ctx)
}

func getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return forwarded
	}
	
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}
	
	return r.RemoteAddr
}

func (s *Server) Stats() map[string]interface{} {
	return map[string]interface{}{
		"active_sessions": s.sessionMgr.SessionCount(),
		"policy_cache_size": s.policyEngine.CacheSize(),
		"upstreams": len(s.config.Upstream),
	}
}