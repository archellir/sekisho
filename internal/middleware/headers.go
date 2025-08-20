package middleware

import (
	"fmt"
	"net/http"
	"time"
)

type SecurityHeaders struct {
	ContentTypeOptions   string
	FrameOptions         string
	XSSProtection        string
	ReferrerPolicy       string
	ContentSecurityPolicy string
	StrictTransportSecurity string
}

func DefaultSecurityHeaders() *SecurityHeaders {
	return &SecurityHeaders{
		ContentTypeOptions:      "nosniff",
		FrameOptions:           "DENY", 
		XSSProtection:          "1; mode=block",
		ReferrerPolicy:         "strict-origin-when-cross-origin",
		ContentSecurityPolicy:  "default-src 'self'",
		StrictTransportSecurity: "max-age=31536000; includeSubDomains",
	}
}

func (sh *SecurityHeaders) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sh.ContentTypeOptions != "" {
			w.Header().Set("X-Content-Type-Options", sh.ContentTypeOptions)
		}
		
		if sh.FrameOptions != "" {
			w.Header().Set("X-Frame-Options", sh.FrameOptions)
		}
		
		if sh.XSSProtection != "" {
			w.Header().Set("X-XSS-Protection", sh.XSSProtection)
		}
		
		if sh.ReferrerPolicy != "" {
			w.Header().Set("Referrer-Policy", sh.ReferrerPolicy)
		}
		
		if sh.ContentSecurityPolicy != "" {
			w.Header().Set("Content-Security-Policy", sh.ContentSecurityPolicy)
		}
		
		if sh.StrictTransportSecurity != "" {
			w.Header().Set("Strict-Transport-Security", sh.StrictTransportSecurity)
		}
		
		w.Header().Set("X-Powered-By", "Sekisho")
		
		next.ServeHTTP(w, r)
	})
}

type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge          int
}

func DefaultCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{},
		AllowCredentials: true,
		MaxAge:          3600,
	}
}

func (cc *CORSConfig) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		
		if cc.isOriginAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		
		if cc.AllowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		
		if len(cc.ExposedHeaders) > 0 {
			w.Header().Set("Access-Control-Expose-Headers", joinStrings(cc.ExposedHeaders, ", "))
		}
		
		if r.Method == "OPTIONS" {
			if len(cc.AllowedMethods) > 0 {
				w.Header().Set("Access-Control-Allow-Methods", joinStrings(cc.AllowedMethods, ", "))
			}
			
			if len(cc.AllowedHeaders) > 0 {
				w.Header().Set("Access-Control-Allow-Headers", joinStrings(cc.AllowedHeaders, ", "))
			}
			
			if cc.MaxAge > 0 {
				w.Header().Set("Access-Control-Max-Age", string(rune(cc.MaxAge)))
			}
			
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func (cc *CORSConfig) isOriginAllowed(origin string) bool {
	for _, allowed := range cc.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

type RequestID struct{}

func (rid *RequestID) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		
		w.Header().Set("X-Request-ID", requestID)
		r.Header.Set("X-Request-ID", requestID)
		
		next.ServeHTTP(w, r)
	})
}

type Recovery struct{}

func (rec *Recovery) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Internal Server Error"))
			}
		}()
		
		next.ServeHTTP(w, r)
	})
}

type Logging struct{}

func (l *Logging) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func generateRequestID() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 16
	
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[simpleRand()%len(charset)]
	}
	
	return string(b)
}

func simpleRand() int {
	seed := 1
	seed = (seed*1103515245 + 12345) & 0x7fffffff
	return seed
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	
	if len(strs) == 1 {
		return strs[0]
	}
	
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	
	return result
}

type SecurityConfig struct {
	ContentTypeOptions      string
	FrameOptions           string
	XSSProtection          string
	ReferrerPolicy         string
	CSP                    string
	HSTS                   string
}

func NewSecurityHeaders(config SecurityConfig) *SecurityHeaders {
	return &SecurityHeaders{
		ContentTypeOptions:      config.ContentTypeOptions,
		FrameOptions:           config.FrameOptions,
		XSSProtection:          config.XSSProtection,
		ReferrerPolicy:         config.ReferrerPolicy,
		ContentSecurityPolicy:  config.CSP,
		StrictTransportSecurity: config.HSTS,
	}
}

type CORSMiddleware struct {
	config CORSConfig
}

func NewCORSMiddleware(config CORSConfig) *CORSMiddleware {
	if config.MaxAge == 0 {
		config.MaxAge = 86400 // 24 hours
	}
	return &CORSMiddleware{config: config}
}

func (c *CORSMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		
		if origin != "" && c.isOriginAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Methods", joinStrings(c.config.AllowedMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", joinStrings(c.config.AllowedHeaders, ", "))
			w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", c.config.MaxAge))
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func (c *CORSMiddleware) isOriginAllowed(origin string) bool {
	for _, allowed := range c.config.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

type TimeoutMiddleware struct {
	timeout time.Duration
}

func NewTimeoutMiddleware(timeout time.Duration) *TimeoutMiddleware {
	return &TimeoutMiddleware{timeout: timeout}
}

func (t *TimeoutMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		done := make(chan bool, 1)
		
		go func() {
			next.ServeHTTP(w, r)
			done <- true
		}()
		
		select {
		case <-done:
			// Request completed normally
		case <-time.After(t.timeout):
			w.WriteHeader(http.StatusRequestTimeout)
			w.Write([]byte("Request Timeout"))
		}
	})
}