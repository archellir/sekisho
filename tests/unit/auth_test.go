package unit

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/archellir/sekisho/internal/auth"
)

func TestJWTValidation(t *testing.T) {
	// Mock key provider for testing
	keyProvider := auth.NewStaticKeyProvider()
	
	validator := auth.NewJWTValidator(keyProvider, "test-issuer", "test-audience")
	
	// Test invalid token format
	_, err := validator.ValidateToken("invalid.token")
	if err == nil {
		t.Error("Expected error for invalid token format")
	}
	
	// Test empty token
	_, err = validator.ValidateToken("")
	if err == nil {
		t.Error("Expected error for empty token")
	}
}

func TestJWTClaims(t *testing.T) {
	// Test token with invalid format
	claims, err := auth.ExtractClaims("invalid.token.format")
	if err == nil {
		t.Error("Expected error for invalid token")
	}
	if claims != nil {
		t.Error("Expected nil claims for invalid token")
	}
}

func TestJWKSProvider(t *testing.T) {
	provider := auth.NewJWKSProvider("http://example.com/jwks", time.Hour)
	
	// Test getting non-existent key
	_, err := provider.GetKey("non-existent-key")
	if err == nil {
		t.Error("Expected error for non-existent key")
	}
	
	// Test cache stats
	count, lastFetch := provider.CacheStats()
	if count != 0 {
		t.Errorf("Expected 0 cached keys, got %d", count)
	}
	if !lastFetch.IsZero() {
		t.Error("Expected zero last fetch time")
	}
}

func TestStaticKeyProvider(t *testing.T) {
	provider := auth.NewStaticKeyProvider()
	
	// Test getting non-existent key
	_, err := provider.GetKey("test-key")
	if err != auth.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
	
	// Add a test key (we'll use a mock RSA key)
	testKey := &rsa.PublicKey{N: nil, E: 65537}
	provider.AddKey("test-key", testKey)
	
	// Test getting existing key
	key, err := provider.GetKey("test-key")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if key != testKey {
		t.Error("Expected same key instance")
	}
}

func TestMultiKeyProvider(t *testing.T) {
	provider1 := auth.NewStaticKeyProvider()
	provider2 := auth.NewStaticKeyProvider()
	
	testKey := &rsa.PublicKey{N: nil, E: 65537}
	provider2.AddKey("test-key", testKey)
	
	multiProvider := auth.NewMultiKeyProvider(provider1, provider2)
	
	// Test key found in second provider
	key, err := multiProvider.GetKey("test-key")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if key != testKey {
		t.Error("Expected same key instance")
	}
	
	// Test non-existent key
	_, err = multiProvider.GetKey("non-existent")
	if err != auth.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestProviderCreation(t *testing.T) {
	tests := []struct {
		name       string
		provider   string
		clientID   string
		expectErr  bool
	}{
		{"Google provider", "google", "test-client", false},
		{"GitHub provider", "github", "test-client", false},
		{"Microsoft provider", "microsoft", "test-client", false},
		{"Invalid provider", "invalid", "test-client", true},
		{"Empty provider", "", "test-client", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := auth.NewProvider(tt.provider, tt.clientID)
			if tt.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestGoogleProvider(t *testing.T) {
	provider := &auth.GoogleProvider{ClientID: "test-client-id"}
	
	authURL := provider.AuthURL("test-state", "http://localhost/callback")
	if authURL == "" {
		t.Error("Expected non-empty auth URL")
	}
	
	tokenURL := provider.TokenURL()
	expected := "https://oauth2.googleapis.com/token"
	if tokenURL != expected {
		t.Errorf("Expected token URL %s, got %s", expected, tokenURL)
	}
	
	userInfoURL := provider.UserInfoURL()
	expected = "https://www.googleapis.com/oauth2/v2/userinfo"
	if userInfoURL != expected {
		t.Errorf("Expected userinfo URL %s, got %s", expected, userInfoURL)
	}
	
	scopes := provider.Scopes()
	expectedScopes := []string{"openid", "email", "profile"}
	if len(scopes) != len(expectedScopes) {
		t.Errorf("Expected %d scopes, got %d", len(expectedScopes), len(scopes))
	}
}

func TestGitHubProvider(t *testing.T) {
	provider := &auth.GitHubProvider{ClientID: "test-client-id"}
	
	tokenURL := provider.TokenURL()
	expected := "https://github.com/login/oauth/access_token"
	if tokenURL != expected {
		t.Errorf("Expected token URL %s, got %s", expected, tokenURL)
	}
	
	userInfoURL := provider.UserInfoURL()
	expected = "https://api.github.com/user"
	if userInfoURL != expected {
		t.Errorf("Expected userinfo URL %s, got %s", expected, userInfoURL)
	}
}

func TestMicrosoftProvider(t *testing.T) {
	provider := &auth.MicrosoftProvider{ClientID: "test-client-id"}
	
	tokenURL := provider.TokenURL()
	expected := "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	if tokenURL != expected {
		t.Errorf("Expected token URL %s, got %s", expected, tokenURL)
	}
	
	userInfoURL := provider.UserInfoURL()
	expected = "https://graph.microsoft.com/v1.0/me"
	if userInfoURL != expected {
		t.Errorf("Expected userinfo URL %s, got %s", expected, userInfoURL)
	}
}

func TestJWKSURLHelpers(t *testing.T) {
	googleURL := auth.GetGoogleJWKSURL()
	expected := "https://www.googleapis.com/oauth2/v3/certs"
	if googleURL != expected {
		t.Errorf("Expected Google JWKS URL %s, got %s", expected, googleURL)
	}
	
	microsoftURL := auth.GetMicrosoftJWKSURL("test-tenant")
	expected = "https://login.microsoftonline.com/test-tenant/discovery/v2.0/keys"
	if microsoftURL != expected {
		t.Errorf("Expected Microsoft JWKS URL %s, got %s", expected, microsoftURL)
	}
	
	microsoftCommonURL := auth.GetMicrosoftJWKSURL("")
	expected = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
	if microsoftCommonURL != expected {
		t.Errorf("Expected Microsoft common JWKS URL %s, got %s", expected, microsoftCommonURL)
	}
	
	auth0URL := auth.GetAuth0JWKSURL("test.auth0.com")
	expected = "https://test.auth0.com/.well-known/jwks.json"
	if auth0URL != expected {
		t.Errorf("Expected Auth0 JWKS URL %s, got %s", expected, auth0URL)
	}
}

func TestTokenUtilities(t *testing.T) {
	// Test with invalid token
	expired := auth.IsTokenExpired("invalid.token.format")
	if !expired {
		t.Error("Expected invalid token to be considered expired")
	}
	
	subject, err := auth.GetTokenSubject("invalid.token.format")
	if err == nil {
		t.Error("Expected error for invalid token")
	}
	if subject != "" {
		t.Error("Expected empty subject for invalid token")
	}
	
	email, err := auth.GetTokenEmail("invalid.token.format")
	if err == nil {
		t.Error("Expected error for invalid token")
	}
	if email != "" {
		t.Error("Expected empty email for invalid token")
	}
}

func TestTokenInfo(t *testing.T) {
	// Test with invalid token
	info := auth.InspectToken("invalid.token.format")
	if info.Valid {
		t.Error("Expected invalid token info")
	}
	if info.Error == "" {
		t.Error("Expected error message in token info")
	}
}