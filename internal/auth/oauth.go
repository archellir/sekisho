package auth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/archellir/sekisho/internal/session"
)

var (
	ErrInvalidCode     = errors.New("invalid authorization code")
	ErrTokenExchange   = errors.New("token exchange failed")
	ErrUserInfoFetch   = errors.New("failed to fetch user info")
	ErrInvalidState    = errors.New("invalid state parameter")
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

type OAuthManager struct {
	provider      Provider
	clientID      string
	clientSecret  string
	redirectURL   string
	sessionMgr    *session.Manager
	httpClient    *http.Client
}

func NewOAuthManager(provider Provider, clientID, clientSecret, redirectURL string, sessionMgr *session.Manager) *OAuthManager {
	return &OAuthManager{
		provider:     provider,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		sessionMgr:   sessionMgr,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (o *OAuthManager) GetAuthURL(state string) string {
	return o.provider.AuthURL(state, o.redirectURL)
}

func (o *OAuthManager) StartAuthFlow(w http.ResponseWriter, r *http.Request) error {
	state, err := o.sessionMgr.GenerateState()
	if err != nil {
		return err
	}

	originalURL := r.URL.String()
	o.sessionMgr.StoreOAuthState(state, originalURL)

	authURL := o.GetAuthURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

func (o *OAuthManager) HandleCallback(w http.ResponseWriter, r *http.Request) (*session.Session, error) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	if errorParam != "" {
		return nil, fmt.Errorf("OAuth error: %s", errorParam)
	}

	if code == "" {
		return nil, ErrInvalidCode
	}

	originalURL, valid := o.sessionMgr.GetOAuthState(state)
	if !valid {
		return nil, ErrInvalidState
	}
	o.sessionMgr.DeleteOAuthState(state)

	token, err := o.exchangeCodeForToken(code)
	if err != nil {
		return nil, err
	}

	userInfo, err := o.fetchUserInfo(token.AccessToken)
	if err != nil {
		return nil, err
	}

	session, err := o.sessionMgr.CreateSession(w, &session.SessionRequest{
		UserID:  userInfo.ID,
		Email:   userInfo.Email,
		Name:    userInfo.Name,
		Picture: userInfo.Picture,
	})
	if err != nil {
		return nil, err
	}

	if originalURL != "" && originalURL != "/" {
		http.Redirect(w, r, originalURL, http.StatusFound)
	} else {
		http.Redirect(w, r, "/", http.StatusFound)
	}

	return session, nil
}

func (o *OAuthManager) exchangeCodeForToken(code string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", o.clientID)
	data.Set("client_secret", o.clientSecret)
	data.Set("redirect_uri", o.redirectURL)
	data.Set("code", code)

	req, err := http.NewRequest("POST", o.provider.TokenURL(), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, ErrTokenExchange
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrTokenExchange
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	token := &TokenResponse{}
	if err := parseTokenResponse(body, token); err != nil {
		return nil, err
	}

	return token, nil
}

func (o *OAuthManager) fetchUserInfo(accessToken string) (*UserInfo, error) {
	req, err := http.NewRequest("GET", o.provider.UserInfoURL(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, ErrUserInfoFetch
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrUserInfoFetch
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseUserInfo(o.provider, body)
}

func parseTokenResponse(data []byte, token *TokenResponse) error {
	str := string(data)
	
	token.AccessToken = extractJSONValue(str, "access_token")
	token.TokenType = extractJSONValue(str, "token_type")
	token.RefreshToken = extractJSONValue(str, "refresh_token")
	token.IDToken = extractJSONValue(str, "id_token")
	
	expiresStr := extractJSONValue(str, "expires_in")
	if expiresStr != "" {
		token.ExpiresIn = parseInt(expiresStr)
	}

	if token.AccessToken == "" {
		return ErrTokenExchange
	}

	return nil
}

func parseInt(s string) int {
	result := 0
	for _, char := range s {
		if char >= '0' && char <= '9' {
			result = result*10 + int(char-'0')
		} else {
			break
		}
	}
	return result
}

func (o *OAuthManager) Logout(w http.ResponseWriter, r *http.Request) error {
	return o.sessionMgr.DeleteSession(w, r)
}

func (o *OAuthManager) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !o.sessionMgr.IsAuthenticated(r) {
			o.StartAuthFlow(w, r)
			return
		}
		
		o.sessionMgr.UpdateLastSeen(r)
		next.ServeHTTP(w, r)
	}
}

func (o *OAuthManager) GetSession(r *http.Request) (*session.Session, error) {
	return o.sessionMgr.GetSession(r)
}

type AuthMiddleware struct {
	oauthMgr *OAuthManager
}

func NewAuthMiddleware(oauthMgr *OAuthManager) *AuthMiddleware {
	return &AuthMiddleware{oauthMgr: oauthMgr}
}

func (am *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !am.oauthMgr.sessionMgr.IsAuthenticated(r) {
			am.oauthMgr.StartAuthFlow(w, r)
			return
		}

		am.oauthMgr.sessionMgr.UpdateLastSeen(r)
		next.ServeHTTP(w, r)
	})
}

func (am *AuthMiddleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if am.oauthMgr.sessionMgr.IsAuthenticated(r) {
			am.oauthMgr.sessionMgr.UpdateLastSeen(r)
		}
		next.ServeHTTP(w, r)
	})
}

func (am *AuthMiddleware) SetUserHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if session, err := am.oauthMgr.sessionMgr.GetSession(r); err == nil {
			r.Header.Set("X-User-ID", session.UserID)
			r.Header.Set("X-User-Email", session.Email)
			r.Header.Set("X-User-Name", session.Name)
		}
		next.ServeHTTP(w, r)
	})
}