package unit

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/archellir/sekisho/internal/audit"
)

func TestAuditLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewLogger(&buf, true, false, false)

	if logger == nil {
		t.Error("Expected logger to be created")
	}

	// Test logging a simple request
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	entry := &audit.Entry{
		ID:        "test-1",
		Timestamp: time.Now(),
		User: audit.UserInfo{
			ID:    "user-123",
			Email: "test@example.com",
			Name:  "Test User",
		},
		Request: audit.RequestInfo{
			Method: "GET",
			Path:   "/test",
			IP:     "127.0.0.1",
		},
		Response: audit.ResponseInfo{
			Status: 200,
			Size:   100,
		},
		Decision: audit.DecisionInfo{
			Action: "allow",
			Reason: "policy match",
		},
		Duration: 50 * time.Millisecond,
	}

	logger.Log(entry)

	output := buf.String()
	if output == "" {
		t.Error("Expected log output")
	}

	// Should contain JSON log entry
	if !strings.Contains(output, `"method":"GET"`) {
		t.Error("Expected method in log output")
	}

	if !strings.Contains(output, `"email":"test@example.com"`) {
		t.Error("Expected email in log output")
	}
}

func TestAuditLoggerDisabled(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewLogger(&buf, false, false, false)

	entry := &audit.Entry{
		ID:        "test-1",
		Timestamp: time.Now(),
		Request: audit.RequestInfo{
			Method: "GET",
			Path:   "/test",
		},
		Response: audit.ResponseInfo{
			Status: 200,
		},
	}

	logger.Log(entry)

	if buf.String() != "" {
		t.Error("Expected no output when logger disabled")
	}
}

func TestAuditMiddleware(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewLogger(&buf, true, false, false)
	middleware := audit.NewAuditMiddleware(logger)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	output := buf.String()
	if output == "" {
		t.Error("Expected audit log output")
	}

	if !strings.Contains(output, "/test") {
		t.Error("Expected path in audit log")
	}

	if !strings.Contains(output, "test-agent") {
		t.Error("Expected user agent in audit log")
	}
}

func TestAuditAuthLogging(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewLogger(&buf, true, false, false)

	req := httptest.NewRequest("GET", "/auth/login", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	logger.LogAuth("user-123", "login_success", "", req)

	output := buf.String()
	if !strings.Contains(output, "login_success") {
		t.Error("Expected auth action in log")
	}

	if !strings.Contains(output, "user-123") {
		t.Error("Expected user ID in auth log")
	}
}

func TestAuditRequestLogging(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewLogger(&buf, true, false, false)

	req := httptest.NewRequest("POST", "/api/users", strings.NewReader(`{"name":"test"}`))
	req.RemoteAddr = "192.168.1.100:54321"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer token123")

	userInfo := audit.UserInfo{ID: "user-456"}
	decision := audit.DecisionInfo{Action: "allow"}
	logger.LogAccess(userInfo, req, 201, 0, 50*time.Millisecond, decision)

	output := buf.String()
	if !strings.Contains(output, "POST") {
		t.Error("Expected POST method in log")
	}

	if !strings.Contains(output, "/api/users") {
		t.Error("Expected path in log")
	}

	if !strings.Contains(output, "192.168.1.100") {
		t.Error("Expected IP address in log")
	}

	if !strings.Contains(output, "user-456") {
		t.Error("Expected user ID in log")
	}
}

func TestJSONFormatter(t *testing.T) {
	formatter := audit.NewJSONFormatter()

	entry := &audit.Entry{
		Timestamp: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		User: audit.UserInfo{
			ID:    "user-123",
			Email: "test@example.com",
		},
		Request: audit.RequestInfo{
			Method: "GET",
			Path:   "/test",
			IP:     "127.0.0.1",
		},
		Response: audit.ResponseInfo{
			Status: 200,
		},
		Decision: audit.DecisionInfo{
			Action: "allow",
		},
		Duration: 100 * time.Millisecond,
	}

	data, err := formatter.Format(entry)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	output := string(data)
	if !strings.Contains(output, `"method":"GET"`) {
		t.Error("Expected JSON formatted method")
	}

	if !strings.Contains(output, `"email":"test@example.com"`) {
		t.Error("Expected JSON formatted email")
	}

	if !strings.Contains(output, `"action":"allow"`) {
		t.Error("Expected JSON formatted action")
	}
}

func TestTextFormatter(t *testing.T) {
	formatter := audit.NewTextFormatter()

	entry := &audit.Entry{
		Timestamp: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		User: audit.UserInfo{
			Email: "test@example.com",
		},
		Request: audit.RequestInfo{
			Method: "GET",
			Path:   "/test",
			IP:     "127.0.0.1",
		},
		Response: audit.ResponseInfo{
			Status: 200,
		},
		Decision: audit.DecisionInfo{
			Action: "allow",
		},
		Duration: 100 * time.Millisecond,
	}

	data, err := formatter.Format(entry)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	output := string(data)
	if !strings.Contains(output, "GET /test") {
		t.Error("Expected method and path in text format")
	}

	if !strings.Contains(output, "test@example.com") {
		t.Error("Expected email in text format")
	}

	if !strings.Contains(output, "action=allow") {
		t.Error("Expected action in text format")
	}
}

func TestCompactFormatter(t *testing.T) {
	formatter := audit.NewCompactFormatter()

	entry := &audit.Entry{
		Timestamp: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		Request: audit.RequestInfo{
			Method: "POST",
			Path:   "/api/test",
			IP:     "192.168.1.1",
		},
		Response: audit.ResponseInfo{
			Status: 201,
		},
		Decision: audit.DecisionInfo{
			Action: "allow",
		},
		Duration: 75 * time.Millisecond,
	}

	data, err := formatter.Format(entry)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	output := string(data)
	expected := []string{"POST", "/api/test", "192.168.1.1", "201", "allow", "75ms"}
	
	for _, exp := range expected {
		if !strings.Contains(output, exp) {
			t.Errorf("Expected %s in compact output: %s", exp, output)
		}
	}
}

func TestCEFFormatter(t *testing.T) {
	formatter := audit.NewCEFFormatter()

	entry := &audit.Entry{
		Timestamp: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		User: audit.UserInfo{
			Email: "admin@example.com",
		},
		Request: audit.RequestInfo{
			Method: "DELETE",
			Path:   "/admin/users/123",
			IP:     "10.0.0.1",
		},
		Response: audit.ResponseInfo{
			Status: 200,
		},
		Decision: audit.DecisionInfo{
			Action: "deny",
			Rule:   "admin-only",
		},
		Duration: 25 * time.Millisecond,
	}

	data, err := formatter.Format(entry)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	output := string(data)
	if !strings.HasPrefix(output, "CEF:0|") {
		t.Error("Expected CEF format prefix")
	}

	if !strings.Contains(output, "Sekisho") {
		t.Error("Expected vendor name in CEF output")
	}

	if !strings.Contains(output, "src=10.0.0.1") {
		t.Error("Expected source IP in CEF format")
	}

	if !strings.Contains(output, "suser=admin@example.com") {
		t.Error("Expected user email in CEF format")
	}
}

func TestAuditRotatingWriter(t *testing.T) {
	// Test size parsing
	size, err := audit.ParseSize("100KB")
	if err != nil {
		t.Errorf("Expected no error parsing size, got %v", err)
	}
	
	expected := int64(100 * 1024)
	if size != expected {
		t.Errorf("Expected size %d, got %d", expected, size)
	}

	// Test MB parsing
	size, err = audit.ParseSize("5MB")
	if err != nil {
		t.Errorf("Expected no error parsing MB size, got %v", err)
	}
	
	expected = int64(5 * 1024 * 1024)
	if size != expected {
		t.Errorf("Expected size %d, got %d", expected, size)
	}
}

func TestAuditDurationParsing(t *testing.T) {
	// Test day parsing
	duration, err := audit.ParseDuration("7d")
	if err != nil {
		t.Errorf("Expected no error parsing duration, got %v", err)
	}
	
	expected := 7 * 24 * time.Hour
	if duration != expected {
		t.Errorf("Expected duration %v, got %v", expected, duration)
	}

	// Test standard duration
	duration, err = audit.ParseDuration("2h30m")
	if err != nil {
		t.Errorf("Expected no error parsing standard duration, got %v", err)
	}
	
	expected = 2*time.Hour + 30*time.Minute
	if duration != expected {
		t.Errorf("Expected duration %v, got %v", expected, duration)
	}
}

func TestAuditFormatterWithFields(t *testing.T) {
	formatter := audit.NewJSONFormatter()
	formatter.IncludeFields = map[string]bool{
		"timestamp": true,
		"request":   true,
		"user":      false, // Exclude user info
	}

	entry := &audit.Entry{
		Timestamp: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		User: audit.UserInfo{
			Email: "test@example.com",
		},
		Request: audit.RequestInfo{
			Method: "GET",
			Path:   "/test",
		},
	}

	data, err := formatter.Format(entry)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	output := string(data)
	if strings.Contains(output, "test@example.com") {
		t.Error("User info should be excluded")
	}

	if !strings.Contains(output, `"method":"GET"`) {
		t.Error("Request info should be included")
	}
}