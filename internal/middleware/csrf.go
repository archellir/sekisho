package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type CSRFProtection struct {
	tokenStore  map[string]time.Time
	mutex       sync.RWMutex
	tokenLength int
	cookieName  string
	headerName  string
	fieldName   string
	maxAge      time.Duration
	secureCookie bool
	sameSite     http.SameSite
}

type CSRFConfig struct {
	TokenLength  int
	CookieName   string
	HeaderName   string
	FieldName    string
	MaxAge       time.Duration
	SecureCookie bool
	SameSite     http.SameSite
}

func NewCSRFProtection(config CSRFConfig) *CSRFProtection {
	if config.TokenLength == 0 {
		config.TokenLength = 32
	}
	if config.CookieName == "" {
		config.CookieName = "_csrf_token"
	}
	if config.HeaderName == "" {
		config.HeaderName = "X-CSRF-Token"
	}
	if config.FieldName == "" {
		config.FieldName = "_csrf_token"
	}
	if config.MaxAge == 0 {
		config.MaxAge = 24 * time.Hour
	}
	if config.SameSite == 0 {
		config.SameSite = http.SameSiteStrictMode
	}

	csrf := &CSRFProtection{
		tokenStore:   make(map[string]time.Time),
		tokenLength:  config.TokenLength,
		cookieName:   config.CookieName,
		headerName:   config.HeaderName,
		fieldName:    config.FieldName,
		maxAge:       config.MaxAge,
		secureCookie: config.SecureCookie,
		sameSite:     config.SameSite,
	}

	go csrf.cleanupExpiredTokens()
	return csrf
}

func (c *CSRFProtection) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.isSafeMethod(r.Method) {
			token := c.getOrCreateToken(w, r)
			r.Header.Set("X-CSRF-Token", token)
			next.ServeHTTP(w, r)
			return
		}

		if !c.validateToken(r) {
			http.Error(w, "CSRF token validation failed", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (c *CSRFProtection) isSafeMethod(method string) bool {
	return method == "GET" || method == "HEAD" || method == "OPTIONS" || method == "TRACE"
}

func (c *CSRFProtection) getOrCreateToken(w http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie(c.cookieName)
	if err == nil && c.isValidToken(cookie.Value) {
		return cookie.Value
	}

	token := c.generateToken()
	c.storeToken(token)
	c.setCookie(w, token)
	return token
}

func (c *CSRFProtection) validateToken(r *http.Request) bool {
	var token string

	if headerToken := r.Header.Get(c.headerName); headerToken != "" {
		token = headerToken
	} else if err := r.ParseForm(); err == nil {
		if formToken := r.Form.Get(c.fieldName); formToken != "" {
			token = formToken
		}
	}

	if token == "" {
		return false
	}

	cookie, err := r.Cookie(c.cookieName)
	if err != nil {
		return false
	}

	return c.compareTokens(token, cookie.Value) && c.isValidToken(token)
}

func (c *CSRFProtection) generateToken() string {
	bytes := make([]byte, c.tokenLength)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("Failed to generate CSRF token: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func (c *CSRFProtection) storeToken(token string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.tokenStore[token] = time.Now().Add(c.maxAge)
}

func (c *CSRFProtection) isValidToken(token string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	expiry, exists := c.tokenStore[token]
	if !exists {
		return false
	}
	
	return time.Now().Before(expiry)
}

func (c *CSRFProtection) compareTokens(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (c *CSRFProtection) setCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     c.cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(c.maxAge.Seconds()),
		HttpOnly: true,
		Secure:   c.secureCookie,
		SameSite: c.sameSite,
	}
	http.SetCookie(w, cookie)
}

func (c *CSRFProtection) cleanupExpiredTokens() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		c.mutex.Lock()
		now := time.Now()
		for token, expiry := range c.tokenStore {
			if now.After(expiry) {
				delete(c.tokenStore, token)
			}
		}
		c.mutex.Unlock()
	}
}

func (c *CSRFProtection) GetToken(r *http.Request) string {
	return r.Header.Get("X-CSRF-Token")
}

func (c *CSRFProtection) ClearToken(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     c.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secureCookie,
		SameSite: c.sameSite,
	}
	http.SetCookie(w, cookie)
}

func DefaultCSRFProtection() *CSRFProtection {
	return NewCSRFProtection(CSRFConfig{
		SecureCookie: true,
		SameSite:     http.SameSiteStrictMode,
	})
}