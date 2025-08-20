package auth

import (
	"fmt"
	"net/url"
)

type Provider interface {
	AuthURL(state, redirectURI string) string
	TokenURL() string
	UserInfoURL() string
	Scopes() []string
}

type GoogleProvider struct {
	ClientID string
}

func (g *GoogleProvider) AuthURL(state, redirectURI string) string {
	params := url.Values{}
	params.Set("client_id", g.ClientID)
	params.Set("response_type", "code")
	params.Set("scope", "openid email profile")
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)
	params.Set("access_type", "offline")
	params.Set("prompt", "consent")
	
	return "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
}

func (g *GoogleProvider) TokenURL() string {
	return "https://oauth2.googleapis.com/token"
}

func (g *GoogleProvider) UserInfoURL() string {
	return "https://www.googleapis.com/oauth2/v2/userinfo"
}

func (g *GoogleProvider) Scopes() []string {
	return []string{"openid", "email", "profile"}
}

type GitHubProvider struct {
	ClientID string
}

func (gh *GitHubProvider) AuthURL(state, redirectURI string) string {
	params := url.Values{}
	params.Set("client_id", gh.ClientID)
	params.Set("response_type", "code")
	params.Set("scope", "user:email")
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)
	
	return "https://github.com/login/oauth/authorize?" + params.Encode()
}

func (gh *GitHubProvider) TokenURL() string {
	return "https://github.com/login/oauth/access_token"
}

func (gh *GitHubProvider) UserInfoURL() string {
	return "https://api.github.com/user"
}

func (gh *GitHubProvider) Scopes() []string {
	return []string{"user:email"}
}

type MicrosoftProvider struct {
	ClientID string
	Tenant   string
}

func (m *MicrosoftProvider) AuthURL(state, redirectURI string) string {
	params := url.Values{}
	params.Set("client_id", m.ClientID)
	params.Set("response_type", "code")
	params.Set("scope", "openid email profile")
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)
	
	tenant := m.Tenant
	if tenant == "" {
		tenant = "common"
	}
	
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize?%s", 
		tenant, params.Encode())
}

func (m *MicrosoftProvider) TokenURL() string {
	tenant := m.Tenant
	if tenant == "" {
		tenant = "common"
	}
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant)
}

func (m *MicrosoftProvider) UserInfoURL() string {
	return "https://graph.microsoft.com/v1.0/me"
}

func (m *MicrosoftProvider) Scopes() []string {
	return []string{"openid", "email", "profile"}
}

func NewProvider(providerName, clientID string) (Provider, error) {
	switch providerName {
	case "google":
		return &GoogleProvider{ClientID: clientID}, nil
	case "github":
		return &GitHubProvider{ClientID: clientID}, nil
	case "microsoft":
		return &MicrosoftProvider{ClientID: clientID}, nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", providerName)
	}
}

type UserInfo struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

func parseUserInfo(provider Provider, data []byte) (*UserInfo, error) {
	switch provider.(type) {
	case *GoogleProvider:
		return parseGoogleUserInfo(data)
	case *GitHubProvider:
		return parseGitHubUserInfo(data)
	case *MicrosoftProvider:
		return parseMicrosoftUserInfo(data)
	default:
		return nil, fmt.Errorf("unsupported provider type")
	}
}

func parseGoogleUserInfo(data []byte) (*UserInfo, error) {
	return simpleJSONParse(data, map[string]string{
		"id":      "id",
		"email":   "email", 
		"name":    "name",
		"picture": "picture",
	}), nil
}

func parseGitHubUserInfo(data []byte) (*UserInfo, error) {
	return simpleJSONParse(data, map[string]string{
		"id":    "id",
		"email": "email",
		"name":  "name",
		"picture": "avatar_url",
	}), nil
}

func parseMicrosoftUserInfo(data []byte) (*UserInfo, error) {
	return simpleJSONParse(data, map[string]string{
		"id":    "id",
		"email": "mail",
		"name":  "displayName", 
		"picture": "",
	}), nil
}

func simpleJSONParse(data []byte, mapping map[string]string) *UserInfo {
	str := string(data)
	info := &UserInfo{}
	
	info.ID = extractJSONValue(str, mapping["id"])
	info.Email = extractJSONValue(str, mapping["email"])
	info.Name = extractJSONValue(str, mapping["name"])
	if pictureKey := mapping["picture"]; pictureKey != "" {
		info.Picture = extractJSONValue(str, pictureKey)
	}
	
	return info
}

func extractJSONValue(jsonStr, key string) string {
	keyPattern := `"` + key + `"`
	start := findString(jsonStr, keyPattern)
	if start == -1 {
		return ""
	}
	
	start = findString(jsonStr[start:], `"`) + start + 1
	if start <= 0 {
		return ""
	}
	
	start = findString(jsonStr[start:], `"`) + start + 1
	if start <= 0 {
		return ""
	}
	
	end := findString(jsonStr[start:], `"`)
	if end == -1 {
		return ""
	}
	
	return jsonStr[start : start+end]
}

func findString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}