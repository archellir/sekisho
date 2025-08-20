package middleware

import (
	"net/http"

	"github.com/archellir/sekisho/internal/auth"
	"github.com/archellir/sekisho/internal/session"
)

type AuthMiddleware struct {
	sessionMgr *session.Manager
	oauthMgr   *auth.OAuthManager
	required   bool
}

func NewAuthMiddleware(sessionMgr *session.Manager, oauthMgr *auth.OAuthManager, required bool) *AuthMiddleware {
	return &AuthMiddleware{
		sessionMgr: sessionMgr,
		oauthMgr:   oauthMgr,
		required:   required,
	}
}

func (am *AuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health and auth endpoints
		if am.isPublicEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// If authentication is not required and no OAuth manager, skip
		if !am.required && am.oauthMgr == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Try to get existing session
		session, err := am.sessionMgr.GetSession(r)
		if err != nil {
			// No valid session
			if am.oauthMgr != nil && am.required {
				am.oauthMgr.StartAuthFlow(w, r)
			} else if am.required {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
			} else {
				next.ServeHTTP(w, r)
			}
			return
		}

		// Valid session - add user context to request
		r.Header.Set("X-User-ID", session.UserID)
		r.Header.Set("X-User-Email", session.Email)
		r.Header.Set("X-User-Name", session.Name)

		// Update session activity
		am.sessionMgr.UpdateLastSeen(r)

		next.ServeHTTP(w, r)
	})
}

func (am *AuthMiddleware) isPublicEndpoint(path string) bool {
	publicPaths := []string{
		"/health",
		"/auth/login",
		"/auth/callback",
		"/auth/logout",
		"/metrics",
	}

	for _, publicPath := range publicPaths {
		if path == publicPath {
			return true
		}
	}
	return false
}

func (am *AuthMiddleware) RequireAuth() *AuthMiddleware {
	return &AuthMiddleware{
		sessionMgr: am.sessionMgr,
		oauthMgr:   am.oauthMgr,
		required:   true,
	}
}

func (am *AuthMiddleware) OptionalAuth() *AuthMiddleware {
	return &AuthMiddleware{
		sessionMgr: am.sessionMgr,
		oauthMgr:   am.oauthMgr,
		required:   false,
	}
}

type UserContext struct {
	UserID  string
	Email   string
	Name    string
	IsAdmin bool
}

func GetUserFromRequest(r *http.Request) *UserContext {
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		return nil
	}

	return &UserContext{
		UserID: userID,
		Email:  r.Header.Get("X-User-Email"),
		Name:   r.Header.Get("X-User-Name"),
	}
}

func (uc *UserContext) HasRole(role string) bool {
	// Simple role checking - can be extended
	switch role {
	case "admin":
		return uc.IsAdmin
	case "user":
		return uc.UserID != ""
	default:
		return false
	}
}

type RoleMiddleware struct {
	requiredRole string
}

func NewRoleMiddleware(role string) *RoleMiddleware {
	return &RoleMiddleware{requiredRole: role}
}

func (rm *RoleMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromRequest(r)
		if user == nil {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		if !user.HasRole(rm.requiredRole) {
			http.Error(w, "Insufficient permissions", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type APIKeyMiddleware struct {
	validKeys map[string]string // key -> description
}

func NewAPIKeyMiddleware() *APIKeyMiddleware {
	return &APIKeyMiddleware{
		validKeys: make(map[string]string),
	}
}

func (akm *APIKeyMiddleware) AddKey(key, description string) {
	akm.validKeys[key] = description
}

func (akm *APIKeyMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for API key in header
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			// Check in query parameter
			apiKey = r.URL.Query().Get("api_key")
		}

		if apiKey == "" {
			http.Error(w, "API key required", http.StatusUnauthorized)
			return
		}

		if _, valid := akm.validKeys[apiKey]; !valid {
			http.Error(w, "Invalid API key", http.StatusUnauthorized)
			return
		}

		// Add API key info to request context
		r.Header.Set("X-API-Key-Used", apiKey)

		next.ServeHTTP(w, r)
	})
}