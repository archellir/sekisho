package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidToken     = errors.New("invalid token format")
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrTokenExpired     = errors.New("token expired")
	ErrInvalidIssuer    = errors.New("invalid issuer")
	ErrInvalidAudience  = errors.New("invalid audience")
)

type JWTHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

type JWTClaims struct {
	Issuer         string   `json:"iss"`
	Subject        string   `json:"sub"`
	Audience       []string `json:"aud"`
	ExpirationTime int64    `json:"exp"`
	NotBefore      int64    `json:"nbf"`
	IssuedAt       int64    `json:"iat"`
	JWTID          string   `json:"jti"`
	Email          string   `json:"email"`
	EmailVerified  bool     `json:"email_verified"`
	Name           string   `json:"name"`
	Picture        string   `json:"picture"`
	GivenName      string   `json:"given_name"`
	FamilyName     string   `json:"family_name"`
}

type JWTValidator struct {
	keyProvider KeyProvider
	issuer      string
	audience    string
	clockSkew   time.Duration
}

type KeyProvider interface {
	GetKey(keyID string) (*rsa.PublicKey, error)
}

func NewJWTValidator(keyProvider KeyProvider, issuer, audience string) *JWTValidator {
	return &JWTValidator{
		keyProvider: keyProvider,
		issuer:      issuer,
		audience:    audience,
		clockSkew:   5 * time.Minute,
	}
}

func (v *JWTValidator) ValidateToken(tokenString string) (*JWTClaims, error) {
	header, claims, signature, err := v.parseToken(tokenString)
	if err != nil {
		return nil, err
	}

	if err := v.validateSignature(tokenString, header, signature); err != nil {
		return nil, err
	}

	if err := v.validateClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func (v *JWTValidator) parseToken(tokenString string) (*JWTHeader, *JWTClaims, []byte, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, nil, nil, ErrInvalidToken
	}

	headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, ErrInvalidToken
	}

	var header JWTHeader
	if err := json.Unmarshal(headerData, &header); err != nil {
		return nil, nil, nil, ErrInvalidToken
	}

	claimsData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, ErrInvalidToken
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsData, &claims); err != nil {
		return nil, nil, nil, ErrInvalidToken
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, ErrInvalidToken
	}

	return &header, &claims, signature, nil
}

func (v *JWTValidator) validateSignature(tokenString string, header *JWTHeader, signature []byte) error {
	if header.Algorithm != "RS256" {
		return fmt.Errorf("unsupported algorithm: %s", header.Algorithm)
	}

	publicKey, err := v.keyProvider.GetKey(header.KeyID)
	if err != nil {
		return err
	}

	parts := strings.Split(tokenString, ".")
	message := parts[0] + "." + parts[1]

	hash := sha256.Sum256([]byte(message))
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return ErrInvalidSignature
	}

	return nil
}

func (v *JWTValidator) validateClaims(claims *JWTClaims) error {
	now := time.Now()

	if claims.ExpirationTime > 0 {
		exp := time.Unix(claims.ExpirationTime, 0)
		if now.After(exp.Add(v.clockSkew)) {
			return ErrTokenExpired
		}
	}

	if claims.NotBefore > 0 {
		nbf := time.Unix(claims.NotBefore, 0)
		if now.Before(nbf.Add(-v.clockSkew)) {
			return ErrTokenExpired
		}
	}

	if v.issuer != "" && claims.Issuer != v.issuer {
		return ErrInvalidIssuer
	}

	if v.audience != "" {
		validAudience := false
		for _, aud := range claims.Audience {
			if aud == v.audience {
				validAudience = true
				break
			}
		}
		if !validAudience {
			return ErrInvalidAudience
		}
	}

	return nil
}

func ParseJWT(tokenString string) (*JWTHeader, *JWTClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, nil, ErrInvalidToken
	}

	headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, ErrInvalidToken
	}

	var header JWTHeader
	if err := json.Unmarshal(headerData, &header); err != nil {
		return nil, nil, ErrInvalidToken
	}

	claimsData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, ErrInvalidToken
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsData, &claims); err != nil {
		return nil, nil, ErrInvalidToken
	}

	return &header, &claims, nil
}

func ExtractClaims(tokenString string) (*JWTClaims, error) {
	_, claims, err := ParseJWT(tokenString)
	return claims, err
}

func IsTokenExpired(tokenString string) bool {
	claims, err := ExtractClaims(tokenString)
	if err != nil {
		return true
	}

	if claims.ExpirationTime == 0 {
		return false
	}

	return time.Now().Unix() > claims.ExpirationTime
}

func GetTokenSubject(tokenString string) (string, error) {
	claims, err := ExtractClaims(tokenString)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

func GetTokenEmail(tokenString string) (string, error) {
	claims, err := ExtractClaims(tokenString)
	if err != nil {
		return "", err
	}
	return claims.Email, nil
}

type TokenInfo struct {
	Valid       bool      `json:"valid"`
	Expired     bool      `json:"expired"`
	Subject     string    `json:"subject,omitempty"`
	Email       string    `json:"email,omitempty"`
	Name        string    `json:"name,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	IssuedAt    time.Time `json:"issued_at,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	Audience    []string  `json:"audience,omitempty"`
	Error       string    `json:"error,omitempty"`
}

func InspectToken(tokenString string) *TokenInfo {
	info := &TokenInfo{}

	claims, err := ExtractClaims(tokenString)
	if err != nil {
		info.Valid = false
		info.Error = err.Error()
		return info
	}

	info.Valid = true
	info.Subject = claims.Subject
	info.Email = claims.Email
	info.Name = claims.Name
	info.Issuer = claims.Issuer
	info.Audience = claims.Audience

	if claims.ExpirationTime > 0 {
		info.ExpiresAt = time.Unix(claims.ExpirationTime, 0)
		info.Expired = time.Now().After(info.ExpiresAt)
	}

	if claims.IssuedAt > 0 {
		info.IssuedAt = time.Unix(claims.IssuedAt, 0)
	}

	return info
}