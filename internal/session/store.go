package session

import (
	"sync"
	"time"
)

type Store struct {
	sessions map[string]*Session
	states   map[string]*StateEntry
	mutex    sync.RWMutex
	ttl      time.Duration
}

type Session struct {
	ID        string
	UserID    string
	Email     string
	Name      string
	Picture   string
	ExpiresAt time.Time
	CreatedAt time.Time
	LastSeen  time.Time
	CSRFToken string
}

type StateEntry struct {
	OriginalURL string
	CreatedAt   time.Time
}

func NewStore(ttl time.Duration) *Store {
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	store := &Store{
		sessions: make(map[string]*Session),
		states:   make(map[string]*StateEntry),
		ttl:      ttl,
	}

	go store.cleanup()
	return store
}

func (s *Store) Create(userID, email, name, picture string) (*Session, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Generate secure random keys for this session
	encryptKey, signKey, err := GenerateKeys()
	if err != nil {
		return nil, err
	}

	crypto, err := NewCrypto(encryptKey[:], signKey[:])
	if err != nil {
		return nil, err
	}

	sessionID, err := crypto.GenerateSessionID()
	if err != nil {
		return nil, err
	}

	csrfToken, err := crypto.GenerateCSRFToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		Email:     email,
		Name:      name,
		Picture:   picture,
		ExpiresAt: now.Add(s.ttl),
		CreatedAt: now,
		LastSeen:  now,
		CSRFToken: csrfToken,
	}

	s.sessions[sessionID] = session
	return session, nil
}

func (s *Store) CreateWithExpiry(userID, email, name, picture string, expiresAt time.Time) (*Session, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Generate secure random keys for this session
	encryptKey, signKey, err := GenerateKeys()
	if err != nil {
		return nil, err
	}

	crypto, err := NewCrypto(encryptKey[:], signKey[:])
	if err != nil {
		return nil, err
	}

	sessionID, err := crypto.GenerateSessionID()
	if err != nil {
		return nil, err
	}

	csrfToken, err := crypto.GenerateCSRFToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		Email:     email,
		Name:      name,
		Picture:   picture,
		ExpiresAt: expiresAt,
		CreatedAt: now,
		LastSeen:  now,
		CSRFToken: csrfToken,
	}

	s.sessions[sessionID] = session
	return session, nil
}

func (s *Store) Get(sessionID string) (*Session, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, false
	}

	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, sessionID)
		return nil, false
	}

	session.LastSeen = time.Now()
	return session, true
}

func (s *Store) Delete(sessionID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.sessions, sessionID)
}

func (s *Store) Renew(sessionID string) (*Session, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, false
	}

	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, sessionID)
		return nil, false
	}

	session.ExpiresAt = time.Now().Add(s.ttl)
	session.LastSeen = time.Now()
	return session, true
}

func (s *Store) StoreState(state, originalURL string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.states[state] = &StateEntry{
		OriginalURL: originalURL,
		CreatedAt:   time.Now(),
	}
}

func (s *Store) GetState(state string) (string, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	entry, exists := s.states[state]
	if !exists {
		return "", false
	}

	if time.Now().Sub(entry.CreatedAt) > 10*time.Minute {
		delete(s.states, state)
		return "", false
	}

	return entry.OriginalURL, true
}

func (s *Store) DeleteState(state string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.states, state)
}

func (s *Store) Count() int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return len(s.sessions)
}

func (s *Store) ActiveSessions() []*Session {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	now := time.Now()
	var active []*Session
	
	for _, session := range s.sessions {
		if now.Before(session.ExpiresAt) {
			active = append(active, session)
		}
	}

	return active
}

func (s *Store) CleanupExpired() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	cleaned := 0

	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
			cleaned++
		}
	}

	for state, entry := range s.states {
		if now.Sub(entry.CreatedAt) > 10*time.Minute {
			delete(s.states, state)
			cleaned++
		}
	}

	return cleaned
}

func (s *Store) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			s.CleanupExpired()
		}
	}()
}

func (s *Store) GetByUserID(userID string) []*Session {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var userSessions []*Session
	now := time.Now()

	for _, session := range s.sessions {
		if session.UserID == userID && now.Before(session.ExpiresAt) {
			userSessions = append(userSessions, session)
		}
	}

	return userSessions
}

func (s *Store) DeleteByUserID(userID string) int {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	deleted := 0
	for id, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, id)
			deleted++
		}
	}

	return deleted
}

func (s *Store) UpdateLastSeen(sessionID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if session, exists := s.sessions[sessionID]; exists {
		session.LastSeen = time.Now()
	}
}