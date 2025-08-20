package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

var (
	ErrKeyNotFound = errors.New("key not found")
	ErrInvalidKey  = errors.New("invalid key format")
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	N         string `json:"n"`
	E         string `json:"e"`
}

type JWKSProvider struct {
	url        string
	cache      map[string]*rsa.PublicKey
	mutex      sync.RWMutex
	httpClient *http.Client
	lastFetch  time.Time
	cacheTTL   time.Duration
}

func NewJWKSProvider(url string, cacheTTL time.Duration) *JWKSProvider {
	if cacheTTL == 0 {
		cacheTTL = 1 * time.Hour
	}

	return &JWKSProvider{
		url:        url,
		cache:      make(map[string]*rsa.PublicKey),
		httpClient: &http.Client{Timeout: 30 * time.Second},
		cacheTTL:   cacheTTL,
	}
}

func (p *JWKSProvider) GetKey(keyID string) (*rsa.PublicKey, error) {
	p.mutex.RLock()
	if key, exists := p.cache[keyID]; exists && time.Since(p.lastFetch) < p.cacheTTL {
		p.mutex.RUnlock()
		return key, nil
	}
	p.mutex.RUnlock()

	if err := p.refreshKeys(); err != nil {
		return nil, err
	}

	p.mutex.RLock()
	defer p.mutex.RUnlock()

	key, exists := p.cache[keyID]
	if !exists {
		return nil, ErrKeyNotFound
	}

	return key, nil
}

func (p *JWKSProvider) refreshKeys() error {
	resp, err := p.httpClient.Get(p.url)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.cache = make(map[string]*rsa.PublicKey)

	for _, jwk := range jwks.Keys {
		if jwk.KeyType == "RSA" && (jwk.Use == "sig" || jwk.Use == "") {
			key, err := p.jwkToRSAKey(&jwk)
			if err != nil {
				continue
			}
			p.cache[jwk.KeyID] = key
		}
	}

	p.lastFetch = time.Now()
	return nil
}

func (p *JWKSProvider) jwkToRSAKey(jwk *JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, ErrInvalidKey
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, ErrInvalidKey
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e*256 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

func (p *JWKSProvider) InvalidateCache() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.cache = make(map[string]*rsa.PublicKey)
	p.lastFetch = time.Time{}
}

func (p *JWKSProvider) CacheStats() (int, time.Time) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return len(p.cache), p.lastFetch
}

type StaticKeyProvider struct {
	keys map[string]*rsa.PublicKey
}

func NewStaticKeyProvider() *StaticKeyProvider {
	return &StaticKeyProvider{
		keys: make(map[string]*rsa.PublicKey),
	}
}

func (p *StaticKeyProvider) AddKey(keyID string, key *rsa.PublicKey) {
	p.keys[keyID] = key
}

func (p *StaticKeyProvider) GetKey(keyID string) (*rsa.PublicKey, error) {
	key, exists := p.keys[keyID]
	if !exists {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

type MultiKeyProvider struct {
	providers []KeyProvider
}

func NewMultiKeyProvider(providers ...KeyProvider) *MultiKeyProvider {
	return &MultiKeyProvider{providers: providers}
}

func (p *MultiKeyProvider) GetKey(keyID string) (*rsa.PublicKey, error) {
	for _, provider := range p.providers {
		key, err := provider.GetKey(keyID)
		if err == nil {
			return key, nil
		}
	}
	return nil, ErrKeyNotFound
}

func GetGoogleJWKSURL() string {
	return "https://www.googleapis.com/oauth2/v3/certs"
}

func GetMicrosoftJWKSURL(tenantID string) string {
	if tenantID == "" {
		tenantID = "common"
	}
	return fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenantID)
}

func GetAuth0JWKSURL(domain string) string {
	return fmt.Sprintf("https://%s/.well-known/jwks.json", domain)
}

type CachedJWKSProvider struct {
	*JWKSProvider
	backgroundRefresh bool
	stopCh            chan struct{}
}

func NewCachedJWKSProvider(url string, cacheTTL time.Duration, backgroundRefresh bool) *CachedJWKSProvider {
	provider := &CachedJWKSProvider{
		JWKSProvider:      NewJWKSProvider(url, cacheTTL),
		backgroundRefresh: backgroundRefresh,
		stopCh:            make(chan struct{}),
	}

	if backgroundRefresh {
		go provider.backgroundRefreshLoop()
	}

	return provider
}

func (p *CachedJWKSProvider) backgroundRefreshLoop() {
	ticker := time.NewTicker(p.cacheTTL / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.refreshKeys()
		case <-p.stopCh:
			return
		}
	}
}

func (p *CachedJWKSProvider) Stop() {
	if p.backgroundRefresh {
		close(p.stopCh)
	}
}

type JWKSConfig struct {
	GoogleEnabled    bool   `json:"google_enabled"`
	MicrosoftEnabled bool   `json:"microsoft_enabled"`
	MicrosoftTenant  string `json:"microsoft_tenant"`
	Auth0Enabled     bool   `json:"auth0_enabled"`
	Auth0Domain      string `json:"auth0_domain"`
	CacheTTL         string `json:"cache_ttl"`
	BackgroundRefresh bool  `json:"background_refresh"`
}

func NewJWKSProviderFromConfig(config *JWKSConfig) (*MultiKeyProvider, error) {
	var providers []KeyProvider

	cacheTTL := 1 * time.Hour
	if config.CacheTTL != "" {
		var err error
		cacheTTL, err = time.ParseDuration(config.CacheTTL)
		if err != nil {
			return nil, fmt.Errorf("invalid cache TTL: %w", err)
		}
	}

	if config.GoogleEnabled {
		provider := NewCachedJWKSProvider(
			GetGoogleJWKSURL(),
			cacheTTL,
			config.BackgroundRefresh,
		)
		providers = append(providers, provider)
	}

	if config.MicrosoftEnabled {
		provider := NewCachedJWKSProvider(
			GetMicrosoftJWKSURL(config.MicrosoftTenant),
			cacheTTL,
			config.BackgroundRefresh,
		)
		providers = append(providers, provider)
	}

	if config.Auth0Enabled && config.Auth0Domain != "" {
		provider := NewCachedJWKSProvider(
			GetAuth0JWKSURL(config.Auth0Domain),
			cacheTTL,
			config.BackgroundRefresh,
		)
		providers = append(providers, provider)
	}

	if len(providers) == 0 {
		return nil, errors.New("no JWKS providers configured")
	}

	return NewMultiKeyProvider(providers...), nil
}