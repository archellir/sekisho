package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

type Logger struct {
	writer     io.Writer
	mutex      sync.Mutex
	enabled    bool
	includeReq bool
	includeRes bool
	buffer     []*Entry
	bufferSize int
}

type Entry struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	User      UserInfo               `json:"user,omitempty"`
	Request   RequestInfo            `json:"request"`
	Response  ResponseInfo           `json:"response"`
	Decision  DecisionInfo           `json:"decision"`
	Duration  time.Duration          `json:"duration_ms"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type UserInfo struct {
	ID    string `json:"id,omitempty"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}

type RequestInfo struct {
	Method    string      `json:"method"`
	Path      string      `json:"path"`
	Query     string      `json:"query,omitempty"`
	IP        string      `json:"ip"`
	UserAgent string      `json:"user_agent,omitempty"`
	Headers   http.Header `json:"headers,omitempty"`
	Body      string      `json:"body,omitempty"`
}

type ResponseInfo struct {
	Status  int         `json:"status"`
	Size    int64       `json:"size"`
	Headers http.Header `json:"headers,omitempty"`
	Body    string      `json:"body,omitempty"`
}

type DecisionInfo struct {
	Action string `json:"action"` // "allow", "deny", "redirect"
	Reason string `json:"reason"`
	Rule   string `json:"rule,omitempty"`
}

func NewLogger(writer io.Writer, enabled bool, includeReq, includeRes bool) *Logger {
	if writer == nil {
		writer = os.Stdout
	}

	return &Logger{
		writer:     writer,
		enabled:    enabled,
		includeReq: includeReq,
		includeRes: includeRes,
		buffer:     make([]*Entry, 0, 100),
		bufferSize: 100,
	}
}

func (l *Logger) Log(entry *Entry) {
	if !l.enabled {
		return
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()

	entry.Timestamp = time.Now()
	entry.ID = generateID()

	if len(l.buffer) >= l.bufferSize {
		l.flush()
	}

	l.buffer = append(l.buffer, entry)
}

func (l *Logger) LogAccess(user UserInfo, req *http.Request, status int, size int64, duration time.Duration, decision DecisionInfo) {
	if !l.enabled {
		return
	}

	entry := &Entry{
		User:     user,
		Duration: duration,
		Decision: decision,
		Request: RequestInfo{
			Method:    req.Method,
			Path:      req.URL.Path,
			Query:     req.URL.RawQuery,
			IP:        getClientIP(req),
			UserAgent: req.UserAgent(),
		},
		Response: ResponseInfo{
			Status: status,
			Size:   size,
		},
	}

	if l.includeReq {
		entry.Request.Headers = cloneHeaders(req.Header)
	}

	l.Log(entry)
}

func (l *Logger) LogAuth(email, action, reason string, req *http.Request) {
	if !l.enabled {
		return
	}

	entry := &Entry{
		User: UserInfo{Email: email},
		Decision: DecisionInfo{
			Action: action,
			Reason: reason,
		},
		Request: RequestInfo{
			Method: req.Method,
			Path:   req.URL.Path,
			IP:     getClientIP(req),
		},
		Response: ResponseInfo{},
	}

	l.Log(entry)
}

func (l *Logger) LogError(err error, req *http.Request, user UserInfo) {
	if !l.enabled {
		return
	}

	entry := &Entry{
		User: user,
		Decision: DecisionInfo{
			Action: "error",
			Reason: err.Error(),
		},
		Request: RequestInfo{
			Method: req.Method,
			Path:   req.URL.Path,
			IP:     getClientIP(req),
		},
		Response: ResponseInfo{
			Status: 500,
		},
	}

	l.Log(entry)
}

func (l *Logger) Flush() {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.flush()
}

func (l *Logger) flush() {
	if len(l.buffer) == 0 {
		return
	}

	for _, entry := range l.buffer {
		data, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		fmt.Fprintf(l.writer, "%s\n", data)
	}

	l.buffer = l.buffer[:0]
}

func (l *Logger) Close() error {
	l.Flush()
	if closer, ok := l.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func generateID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), simpleRand())
}

func simpleRand() int {
	return int(time.Now().UnixNano() % 1000000)
}

func getClientIP(req *http.Request) string {
	if ip := req.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := req.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return req.RemoteAddr
}

func cloneHeaders(headers http.Header) http.Header {
	clone := make(http.Header)
	for k, v := range headers {
		if !isSensitiveHeader(k) {
			clone[k] = append([]string{}, v...)
		}
	}
	return clone
}

func isSensitiveHeader(name string) bool {
	sensitive := []string{
		"Authorization",
		"Cookie",
		"X-Auth-Token",
		"X-API-Key",
	}
	
	for _, s := range sensitive {
		if name == s {
			return true
		}
	}
	return false
}

type AuditMiddleware struct {
	logger *Logger
}

func NewAuditMiddleware(logger *Logger) *AuditMiddleware {
	return &AuditMiddleware{logger: logger}
}

func (am *AuditMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapper := &responseWriter{
			ResponseWriter: w,
			statusCode:     200,
		}

		next.ServeHTTP(wrapper, r)

		duration := time.Since(start)

		var user UserInfo
		if userID := r.Header.Get("X-User-ID"); userID != "" {
			user.ID = userID
		}
		if email := r.Header.Get("X-User-Email"); email != "" {
			user.Email = email
		}

		decision := DecisionInfo{
			Action: "allow",
			Reason: "request processed",
		}

		if wrapper.statusCode >= 400 {
			decision.Action = "deny"
			decision.Reason = fmt.Sprintf("HTTP %d", wrapper.statusCode)
		}

		am.logger.LogAccess(user, r, wrapper.statusCode, wrapper.size, duration, decision)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int64
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(data)
	rw.size += int64(n)
	return n, err
}