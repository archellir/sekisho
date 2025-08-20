package session

import (
	"net/http"
	"time"
)

const (
	SessionCookieName = "sekisho_session"
	CSRFCookieName    = "sekisho_csrf"
)

type CookieManager struct {
	crypto       *Crypto
	domain       string
	secure       bool
	httpOnly     bool
	sameSite     http.SameSite
	path         string
}

func NewCookieManager(crypto *Crypto, domain string, secure bool) *CookieManager {
	return &CookieManager{
		crypto:   crypto,
		domain:   domain,
		secure:   secure,
		httpOnly: true,
		sameSite: http.SameSiteStrictMode,
		path:     "/",
	}
}

func (cm *CookieManager) SetSessionCookie(w http.ResponseWriter, session *Session) error {
	encrypted, err := cm.crypto.Encrypt([]byte(session.ID))
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    encrypted,
		Path:     cm.path,
		Domain:   cm.domain,
		Expires:  session.ExpiresAt,
		MaxAge:   int(time.Until(session.ExpiresAt).Seconds()),
		HttpOnly: cm.httpOnly,
		Secure:   cm.secure,
		SameSite: cm.sameSite,
	}

	http.SetCookie(w, cookie)
	return nil
}

func (cm *CookieManager) GetSessionID(r *http.Request) (string, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return "", err
	}

	decrypted, err := cm.crypto.Decrypt(cookie.Value)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func (cm *CookieManager) SetCSRFCookie(w http.ResponseWriter, token string, expires time.Time) error {
	encrypted, err := cm.crypto.Encrypt([]byte(token))
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     CSRFCookieName,
		Value:    encrypted,
		Path:     cm.path,
		Domain:   cm.domain,
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: false,
		Secure:   cm.secure,
		SameSite: cm.sameSite,
	}

	http.SetCookie(w, cookie)
	return nil
}

func (cm *CookieManager) GetCSRFToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(CSRFCookieName)
	if err != nil {
		return "", err
	}

	decrypted, err := cm.crypto.Decrypt(cookie.Value)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func (cm *CookieManager) ClearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     cm.path,
		Domain:   cm.domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: cm.httpOnly,
		Secure:   cm.secure,
		SameSite: cm.sameSite,
	}

	http.SetCookie(w, cookie)
}

func (cm *CookieManager) ClearCSRFCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     CSRFCookieName,
		Value:    "",
		Path:     cm.path,
		Domain:   cm.domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   cm.secure,
		SameSite: cm.sameSite,
	}

	http.SetCookie(w, cookie)
}

func (cm *CookieManager) ClearAllCookies(w http.ResponseWriter) {
	cm.ClearSessionCookie(w)
	cm.ClearCSRFCookie(w)
}

func (cm *CookieManager) RefreshSessionCookie(w http.ResponseWriter, session *Session) error {
	return cm.SetSessionCookie(w, session)
}

func (cm *CookieManager) IsSecure() bool {
	return cm.secure
}

func (cm *CookieManager) GetDomain() string {
	return cm.domain
}

func (cm *CookieManager) ValidateCookieFormat(cookieValue string) bool {
	_, err := cm.crypto.Decrypt(cookieValue)
	return err == nil
}