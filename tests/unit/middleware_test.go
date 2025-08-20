package unit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/archellir/sekisho/internal/middleware"
)

func TestRateLimiter(t *testing.T) {
	limiter := middleware.NewRateLimiter(2, 5) // 2 requests per second, burst of 5

	handler := limiter.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Should allow first 5 requests (burst)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()
		
		handler.ServeHTTP(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("Request %d should be allowed, got status %d", i+1, w.Code)
		}
	}

	// 6th request should be rate limited
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	
	handler.ServeHTTP(w, req)
	
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("6th request should be rate limited, got status %d", w.Code)
	}
}

func TestRateLimiterDifferentIPs(t *testing.T) {
	limiter := middleware.NewRateLimiter(1, 1) // Very strict limits

	handler := limiter.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Different IPs should have separate rate limits
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "127.0.0.1:12345"
	w1 := httptest.NewRecorder()
	
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "127.0.0.2:12345"
	w2 := httptest.NewRecorder()
	
	handler.ServeHTTP(w1, req1)
	handler.ServeHTTP(w2, req2)
	
	if w1.Code != http.StatusOK {
		t.Errorf("First IP should be allowed, got status %d", w1.Code)
	}
	if w2.Code != http.StatusOK {
		t.Errorf("Second IP should be allowed, got status %d", w2.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	headers := middleware.DefaultSecurityHeaders()
	
	handler := headers.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	
	handler.ServeHTTP(w, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}

	for header, expected := range expectedHeaders {
		actual := w.Header().Get(header)
		if actual != expected {
			t.Errorf("Expected header %s: %s, got: %s", header, expected, actual)
		}
	}
}

func TestCustomSecurityHeaders(t *testing.T) {
	config := middleware.SecurityConfig{
		ContentTypeOptions: "nosniff",
		FrameOptions:       "SAMEORIGIN",
		XSSProtection:      "0",
		ReferrerPolicy:     "no-referrer",
		CSP:                "default-src 'self'",
		HSTS:               "max-age=31536000",
	}
	
	headers := middleware.NewSecurityHeaders(config)
	
	handler := headers.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	
	handler.ServeHTTP(w, req)

	if w.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Errorf("Expected custom frame options")
	}
	
	if w.Header().Get("Content-Security-Policy") != "default-src 'self'" {
		t.Errorf("Expected custom CSP")
	}
	
	if w.Header().Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Errorf("Expected HSTS header")
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	recovery := &middleware.Recovery{}
	
	handler := recovery.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	
	// Should not panic, should return 500
	handler.ServeHTTP(w, req)
	
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500 after panic, got %d", w.Code)
	}
}

func TestRequestIDMiddleware(t *testing.T) {
	requestID := &middleware.RequestID{}
	
	var capturedID string
	handler := requestID.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = r.Header.Get("X-Request-ID")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	
	handler.ServeHTTP(w, req)
	
	if capturedID == "" {
		t.Error("Expected X-Request-ID header to be set")
	}
	
	if w.Header().Get("X-Request-ID") != capturedID {
		t.Error("Expected X-Request-ID to be in response headers")
	}
}

func TestCSRFProtection(t *testing.T) {
	csrf := middleware.NewCSRFProtection(middleware.CSRFConfig{
		TokenLength:  16,
		SecureCookie: false, // For testing
	})
	
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// GET request should succeed and set CSRF cookie
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	
	handler.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("GET request should succeed, got status %d", w.Code)
	}
	
	// Should have set CSRF cookie
	cookies := w.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "_csrf_token" {
			csrfCookie = cookie
			break
		}
	}
	
	if csrfCookie == nil {
		t.Error("Expected CSRF cookie to be set")
	}
	
	// POST request without CSRF token should fail
	req2 := httptest.NewRequest("POST", "/", strings.NewReader("data"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	
	handler.ServeHTTP(w2, req2)
	
	if w2.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF token should fail, got status %d", w2.Code)
	}
}

func TestCSRFWithValidToken(t *testing.T) {
	csrf := middleware.NewCSRFProtection(middleware.CSRFConfig{
		SecureCookie: false,
	})
	
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First, get a CSRF token
	req1 := httptest.NewRequest("GET", "/", nil)
	w1 := httptest.NewRecorder()
	
	handler.ServeHTTP(w1, req1)
	
	var csrfCookie *http.Cookie
	cookies := w1.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "_csrf_token" {
			csrfCookie = cookie
			break
		}
	}
	
	if csrfCookie == nil {
		t.Fatal("Expected CSRF cookie")
	}
	
	// Now POST with the token in header
	req2 := httptest.NewRequest("POST", "/", strings.NewReader("data"))
	req2.AddCookie(csrfCookie)
	req2.Header.Set("X-CSRF-Token", csrfCookie.Value)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	
	handler.ServeHTTP(w2, req2)
	
	if w2.Code != http.StatusOK {
		t.Errorf("POST with valid CSRF token should succeed, got status %d", w2.Code)
	}
}

func TestMetricsMiddleware(t *testing.T) {
	metrics := middleware.NewProxyMetrics("test")
	
	handler := metrics.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	
	handler.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	
	// Check that metrics were recorded (basic test)
	if metrics == nil {
		t.Error("Metrics should be initialized")
	}
}

func TestMetricsEndpoint(t *testing.T) {
	metrics := middleware.NewProxyMetrics("test")
	
	// Record some test metrics
	metrics.RecordAuth(true)
	metrics.RecordAuth(false)
	
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	
	metrics.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	
	contentType := w.Header().Get("Content-Type")
	if contentType != "text/plain; version=0.0.4" {
		t.Errorf("Expected Prometheus content type, got %s", contentType)
	}
	
	body := w.Body.String()
	if !strings.Contains(body, "auth_attempts_total") {
		t.Error("Expected auth metrics in output")
	}
}

func TestCORSMiddleware(t *testing.T) {
	cors := middleware.NewCORSMiddleware(middleware.CORSConfig{
		AllowedOrigins: []string{"http://localhost:3000"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Content-Type"},
	})
	
	handler := cors.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test preflight request
	req := httptest.NewRequest("OPTIONS", "/", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	
	handler.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Preflight should succeed, got status %d", w.Code)
	}
	
	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "http://localhost:3000" {
		t.Errorf("Expected allowed origin, got %s", origin)
	}
}

func TestTimeoutMiddleware(t *testing.T) {
	timeout := middleware.NewTimeoutMiddleware(100 * time.Millisecond)
	
	handler := timeout.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // Sleep longer than timeout
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	
	handler.ServeHTTP(w, req)
	
	if w.Code != http.StatusRequestTimeout {
		t.Errorf("Expected timeout status, got %d", w.Code)
	}
}