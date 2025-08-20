package session

import (
	"errors"
	"net/http"
	"time"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrInvalidCSRF     = errors.New("invalid CSRF token")
)

type Manager struct {
	store         *Store
	cookieManager *CookieManager
	crypto        *Crypto
	duration      time.Duration
}

func NewManager(encryptKey, signKey []byte, domain string, secure bool, duration time.Duration) (*Manager, error) {
	crypto, err := NewCrypto(encryptKey, signKey)
	if err != nil {
		return nil, err
	}

	store := NewStore(duration)
	cookieManager := NewCookieManager(crypto, domain, secure)

	return &Manager{
		store:         store,
		cookieManager: cookieManager,
		crypto:        crypto,
		duration:      duration,
	}, nil
}

type SessionRequest struct {
	UserID  string
	Email   string
	Name    string
	Picture string
}

func (m *Manager) CreateSession(w http.ResponseWriter, req *SessionRequest) (*Session, error) {
	session, err := m.store.Create(req.UserID, req.Email, req.Name, req.Picture)
	if err != nil {
		return nil, err
	}

	if err := m.cookieManager.SetSessionCookie(w, session); err != nil {
		m.store.Delete(session.ID)
		return nil, err
	}

	if err := m.cookieManager.SetCSRFCookie(w, session.CSRFToken, session.ExpiresAt); err != nil {
		m.store.Delete(session.ID)
		return nil, err
	}

	return session, nil
}

// CreateSessionFromUserData creates a session using individual parameters (for backward compatibility)
func (m *Manager) CreateSessionFromUserData(w http.ResponseWriter, userID, email, name, picture string) (*Session, error) {
	return m.CreateSession(w, &SessionRequest{
		UserID:  userID,
		Email:   email,
		Name:    name,
		Picture: picture,
	})
}

// CreateSessionWithExpiry creates a session with custom expiration (mainly for testing)
func (m *Manager) CreateSessionWithExpiry(w http.ResponseWriter, req *SessionRequest, expiresAt time.Time) (*Session, error) {
	session, err := m.store.CreateWithExpiry(req.UserID, req.Email, req.Name, req.Picture, expiresAt)
	if err != nil {
		return nil, err
	}

	if err := m.cookieManager.SetSessionCookie(w, session); err != nil {
		m.store.Delete(session.ID)
		return nil, err
	}

	if err := m.cookieManager.SetCSRFCookie(w, session.CSRFToken, session.ExpiresAt); err != nil {
		m.store.Delete(session.ID)
		return nil, err
	}

	return session, nil
}

func (m *Manager) GetSession(r *http.Request) (*Session, error) {
	sessionID, err := m.cookieManager.GetSessionID(r)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	session, exists := m.store.Get(sessionID)
	if !exists {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(session.ExpiresAt) {
		m.store.Delete(sessionID)
		return nil, ErrSessionExpired
	}

	return session, nil
}

func (m *Manager) RenewSession(w http.ResponseWriter, r *http.Request) (*Session, error) {
	sessionID, err := m.cookieManager.GetSessionID(r)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	session, exists := m.store.Renew(sessionID)
	if !exists {
		return nil, ErrSessionNotFound
	}

	if err := m.cookieManager.RefreshSessionCookie(w, session); err != nil {
		return nil, err
	}

	return session, nil
}

func (m *Manager) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	sessionID, err := m.cookieManager.GetSessionID(r)
	if err != nil {
		return nil
	}

	m.store.Delete(sessionID)
	m.cookieManager.ClearAllCookies(w)
	return nil
}

func (m *Manager) ValidateCSRF(r *http.Request) error {
	session, err := m.GetSession(r)
	if err != nil {
		return err
	}

	cookieToken, err := m.cookieManager.GetCSRFToken(r)
	if err != nil {
		return ErrInvalidCSRF
	}

	headerToken := r.Header.Get("X-CSRF-Token")
	if headerToken == "" {
		formToken := r.FormValue("csrf_token")
		if formToken == "" {
			return ErrInvalidCSRF
		}
		headerToken = formToken
	}

	if cookieToken != headerToken || cookieToken != session.CSRFToken {
		return ErrInvalidCSRF
	}

	return nil
}

func (m *Manager) IsAuthenticated(r *http.Request) bool {
	_, err := m.GetSession(r)
	return err == nil
}

func (m *Manager) GetUserID(r *http.Request) (string, error) {
	session, err := m.GetSession(r)
	if err != nil {
		return "", err
	}
	return session.UserID, nil
}

func (m *Manager) GetUserEmail(r *http.Request) (string, error) {
	session, err := m.GetSession(r)
	if err != nil {
		return "", err
	}
	return session.Email, nil
}

func (m *Manager) UpdateLastSeen(r *http.Request) {
	sessionID, err := m.cookieManager.GetSessionID(r)
	if err != nil {
		return
	}
	m.store.UpdateLastSeen(sessionID)
}

func (m *Manager) GetActiveSessions() []*Session {
	return m.store.ActiveSessions()
}

func (m *Manager) GetUserSessions(userID string) []*Session {
	return m.store.GetByUserID(userID)
}

func (m *Manager) DeleteAllUserSessions(userID string) int {
	return m.store.DeleteByUserID(userID)
}

func (m *Manager) CleanupExpired() int {
	return m.store.CleanupExpired()
}

func (m *Manager) SessionCount() int {
	return m.store.Count()
}

func (m *Manager) StoreOAuthState(state, originalURL string) {
	m.store.StoreState(state, originalURL)
}

func (m *Manager) GetOAuthState(state string) (string, bool) {
	return m.store.GetState(state)
}

func (m *Manager) DeleteOAuthState(state string) {
	m.store.DeleteState(state)
}

func (m *Manager) GenerateState() (string, error) {
	return m.crypto.GenerateState()
}