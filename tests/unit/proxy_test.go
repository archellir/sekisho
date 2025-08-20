package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/archellir/sekisho/internal/config"
	"github.com/archellir/sekisho/internal/proxy"
)

func TestProxyHandler(t *testing.T) {
	// Create a test upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Header", "upstream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("upstream response"))
	}))
	defer upstream.Close()

	// Create proxy configuration
	cfg := &config.Config{
		Upstream: []config.UpstreamConfig{
			{
				Host:    "test.example.com",
				Target:  upstream.URL,
				Timeout: 30 * time.Second,
			},
		},
	}

	transport := proxy.NewTransport()
	handler := proxy.NewProxyHandler(cfg, transport)

	// Test proxying request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Host = "test.example.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	if w.Body.String() != "upstream response" {
		t.Errorf("Expected 'upstream response', got %s", w.Body.String())
	}

	if w.Header().Get("X-Test-Header") != "upstream" {
		t.Error("Expected upstream header to be forwarded")
	}
}

func TestProxyHandlerNoUpstream(t *testing.T) {
	cfg := &config.Config{
		Upstream: []config.UpstreamConfig{},
	}

	transport := proxy.NewTransport()
	handler := proxy.NewProxyHandler(cfg, transport)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Host = "unknown.example.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", w.Code)
	}
}

func TestProxyHandlerPOST(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected JSON content type")
		}
		
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created"))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Upstream: []config.UpstreamConfig{
			{
				Host:    "api.example.com",
				Target:  upstream.URL,
				Timeout: 30 * time.Second,
			},
		},
	}

	transport := proxy.NewTransport()
	handler := proxy.NewProxyHandler(cfg, transport)

	body := strings.NewReader(`{"test": "data"}`)
	req := httptest.NewRequest("POST", "/api/test", body)
	req.Host = "api.example.com"
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}
}

func TestTransportPooling(t *testing.T) {
	transport := proxy.NewTransport()
	
	if transport == nil {
		t.Error("Expected transport to be created")
	}

	// Test that we can create requests
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	if req == nil {
		t.Error("Failed to create test request")
	}
}

func TestProxyHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that hop-by-hop headers are removed
		if r.Header.Get("Connection") != "" {
			t.Error("Connection header should be removed")
		}
		
		// Check that X-Forwarded headers are added
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Error("X-Forwarded-For header should be added")
		}
		
		if r.Header.Get("X-Forwarded-Proto") == "" {
			t.Error("X-Forwarded-Proto header should be added")
		}
		
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Upstream: []config.UpstreamConfig{
			{
				Host:    "test.example.com",
				Target:  upstream.URL,
				Timeout: 30 * time.Second,
			},
		},
	}

	transport := proxy.NewTransport()
	handler := proxy.NewProxyHandler(cfg, transport)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Host = "test.example.com"
	req.Header.Set("Connection", "keep-alive")
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
}

func TestTunnelHandler(t *testing.T) {
	// Test CONNECT method handling
	cfg := &config.Config{}
	transport := proxy.NewTransport()
	handler := proxy.NewProxyHandler(cfg, transport)

	req := httptest.NewRequest("CONNECT", "example.com:443", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// CONNECT should be handled (even if it fails due to test environment)
	// We're mainly testing that it doesn't panic or return 404
	if w.Code == http.StatusNotFound {
		t.Error("CONNECT method should be handled")
	}
}

func TestProxyTimeout(t *testing.T) {
	// Create slow upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Upstream: []config.UpstreamConfig{
			{
				Host:    "slow.example.com",
				Target:  upstream.URL,
				Timeout: 100 * time.Millisecond, // Very short timeout
			},
		},
	}

	transport := proxy.NewTransport()
	handler := proxy.NewProxyHandler(cfg, transport)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Host = "slow.example.com"
	w := httptest.NewRecorder()

	start := time.Now()
	handler.ServeHTTP(w, req)
	duration := time.Since(start)

	// Should timeout quickly
	if duration > 1*time.Second {
		t.Error("Request should have timed out quickly")
	}
	
	if w.Code == http.StatusOK {
		t.Error("Expected timeout error, got 200")
	}
}

func TestProxyMultipleUpstreams(t *testing.T) {
	upstream1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream1"))
	}))
	defer upstream1.Close()

	upstream2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream2"))
	}))
	defer upstream2.Close()

	cfg := &config.Config{
		Upstream: []config.UpstreamConfig{
			{
				Host:    "app1.example.com",
				Target:  upstream1.URL,
				Timeout: 30 * time.Second,
			},
			{
				Host:    "app2.example.com",
				Target:  upstream2.URL,
				Timeout: 30 * time.Second,
			},
		},
	}

	transport := proxy.NewTransport()
	handler := proxy.NewProxyHandler(cfg, transport)

	// Test first upstream
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.Host = "app1.example.com"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if w1.Body.String() != "upstream1" {
		t.Errorf("Expected 'upstream1', got %s", w1.Body.String())
	}

	// Test second upstream
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Host = "app2.example.com"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Body.String() != "upstream2" {
		t.Errorf("Expected 'upstream2', got %s", w2.Body.String())
	}
}

func TestProxyWebSocket(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check WebSocket upgrade headers
		if r.Header.Get("Upgrade") != "websocket" {
			t.Error("Expected WebSocket upgrade header")
		}
		
		if r.Header.Get("Connection") != "upgrade" {
			t.Error("Expected Connection: upgrade header")
		}
		
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Upstream: []config.UpstreamConfig{
			{
				Host:    "ws.example.com",
				Target:  upstream.URL,
				Timeout: 30 * time.Second,
			},
		},
	}

	transport := proxy.NewTransport()
	handler := proxy.NewProxyHandler(cfg, transport)

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Host = "ws.example.com"
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Sec-WebSocket-Key", "test-key")
	req.Header.Set("Sec-WebSocket-Version", "13")
	
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusSwitchingProtocols {
		t.Errorf("Expected status 101, got %d", w.Code)
	}
}

func TestTCPProxy(t *testing.T) {
	cfg := &config.Config{
		TCPProxy: []config.TCPProxyConfig{
			{
				Name:       "test-tcp",
				ListenPort: 9999,
				Target:     "localhost:8888",
			},
		},
	}

	tcpProxy := proxy.NewTCPProxy(cfg)
	if tcpProxy == nil {
		t.Error("Expected TCP proxy to be created")
	}

	// Test getting connections
	connections := tcpProxy.GetConnections()
	if connections == nil {
		t.Error("Expected connections slice")
	}
	
	if len(connections) != 0 {
		t.Error("Expected no initial connections")
	}

	// Test getting active connections
	active := tcpProxy.GetActiveConnections()
	if active == nil {
		t.Error("Expected active connections slice")
	}
	
	if len(active) != 0 {
		t.Error("Expected no initial active connections")
	}
}

func TestTCPProxyConfigValidation(t *testing.T) {
	cfg := &config.Config{
		TCPProxy: []config.TCPProxyConfig{}, // Empty config
	}

	tcpProxy := proxy.NewTCPProxy(cfg)
	if tcpProxy == nil {
		t.Error("TCP proxy should be created even with empty config")
	}

	// Starting with no configs should not error
	err := tcpProxy.Start()
	if err != nil {
		t.Errorf("Starting TCP proxy with empty config should not error: %v", err)
	}
}

func TestProxyCircuitBreaker(t *testing.T) {
	failCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failCount++
		if failCount <= 3 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("recovered"))
		}
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Upstream: []config.UpstreamConfig{
			{
				Host:    "flaky.example.com",
				Target:  upstream.URL,
				Timeout: 30 * time.Second,
			},
		},
	}

	transport := proxy.NewTransport()
	handler := proxy.NewProxyHandler(cfg, transport)

	// First few requests should get 500s
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Host = "flaky.example.com"
		w := httptest.NewRecorder()
		
		handler.ServeHTTP(w, req)
		
		if w.Code != http.StatusInternalServerError {
			t.Errorf("Request %d should get 500, got %d", i+1, w.Code)
		}
	}

	// Later request should succeed
	req := httptest.NewRequest("GET", "/test", nil)
	req.Host = "flaky.example.com"
	w := httptest.NewRecorder()
	
	handler.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Recovery request should succeed, got %d", w.Code)
	}
}