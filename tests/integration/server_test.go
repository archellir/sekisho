package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/archellir/sekisho/internal/config"
	"github.com/archellir/sekisho/internal/server"
)

func TestServerHealthCheck(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Auth.Provider = ""
	
	srv, err := server.NewServer(cfg)
	if err != nil {
		t.Fatal("Failed to create server:", err)
	}

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected JSON content type, got %s", contentType)
	}
}

func TestServerUnauthenticatedRequest(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Auth.Provider = "google"
	cfg.Auth.ClientID = "test-client-id"
	cfg.Auth.ClientSecret = "test-client-secret"
	cfg.Auth.RedirectURL = "http://localhost/callback"

	srv, err := server.NewServer(cfg)
	if err != nil {
		t.Fatal("Failed to create server:", err)
	}

	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusFound && w.Code != http.StatusUnauthorized {
		t.Errorf("Expected redirect or unauthorized, got %d", w.Code)
	}
}

func TestServerBasicProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("upstream response"))
	}))
	defer upstream.Close()

	cfg := config.DefaultConfig()
	cfg.Auth.Provider = ""
	cfg.Upstream = []config.UpstreamConfig{
		{
			Host:    "test.example.com",
			Target:  upstream.URL,
			Timeout: 30 * time.Second,
		},
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		t.Fatal("Failed to create server:", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.Host = "test.example.com"
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if body != "upstream response" {
		t.Errorf("Expected upstream response, got %s", body)
	}
}

func TestServerPolicyEnforcement(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Auth.Provider = ""
	cfg.Policy.Rules = []config.PolicyRule{
		{
			Name:   "deny_all",
			Path:   "/*",
			Action: "deny",
		},
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		t.Fatal("Failed to create server:", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}