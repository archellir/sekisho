package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	ErrInvalidKey    = errors.New("invalid key length")
	ErrInvalidData   = errors.New("invalid encrypted data")
	ErrDecryption    = errors.New("decryption failed")
	ErrAuthentication = errors.New("authentication failed")
)

type Crypto struct {
	encryptKey [32]byte
	signKey    [32]byte
}

func NewCrypto(encryptKey, signKey []byte) (*Crypto, error) {
	if len(encryptKey) != 32 {
		return nil, ErrInvalidKey
	}
	if len(signKey) != 32 {
		return nil, ErrInvalidKey
	}

	c := &Crypto{}
	copy(c.encryptKey[:], encryptKey)
	copy(c.signKey[:], signKey)

	return c, nil
}

func GenerateKeys() (encryptKey, signKey [32]byte, err error) {
	if _, err = rand.Read(encryptKey[:]); err != nil {
		return
	}
	if _, err = rand.Read(signKey[:]); err != nil {
		return
	}
	return
}

func (c *Crypto) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(c.encryptKey[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	
	signature := c.sign(ciphertext)
	
	combined := append(ciphertext, signature...)
	
	return base64.URLEncoding.EncodeToString(combined), nil
}

func (c *Crypto) Decrypt(encoded string) ([]byte, error) {
	combined, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrInvalidData
	}

	if len(combined) < 32 {
		return nil, ErrInvalidData
	}

	signatureOffset := len(combined) - 32
	ciphertext := combined[:signatureOffset]
	signature := combined[signatureOffset:]

	if !c.verify(ciphertext, signature) {
		return nil, ErrAuthentication
	}

	block, err := aes.NewCipher(c.encryptKey[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidData
	}

	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, ErrDecryption
	}

	return plaintext, nil
}

func (c *Crypto) sign(data []byte) []byte {
	h := hmac.New(sha256.New, c.signKey[:])
	h.Write(data)
	return h.Sum(nil)
}

func (c *Crypto) verify(data, signature []byte) bool {
	expected := c.sign(data)
	return subtle.ConstantTimeCompare(expected, signature) == 1
}

func (c *Crypto) GenerateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (c *Crypto) GenerateCSRFToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (c *Crypto) GenerateState() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (c *Crypto) HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	h := sha256.New()
	h.Write([]byte(password))
	h.Write(salt)
	hash := h.Sum(nil)

	combined := append(salt, hash...)
	return base64.URLEncoding.EncodeToString(combined), nil
}

func (c *Crypto) VerifyPassword(password, hashed string) bool {
	combined, err := base64.URLEncoding.DecodeString(hashed)
	if err != nil || len(combined) != 48 {
		return false
	}

	salt := combined[:16]
	storedHash := combined[16:]

	h := sha256.New()
	h.Write([]byte(password))
	h.Write(salt)
	computedHash := h.Sum(nil)

	return subtle.ConstantTimeCompare(storedHash, computedHash) == 1
}

func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (c *Crypto) EncryptJSON(data interface{}) (string, error) {
	plaintext, err := jsonMarshal(data)
	if err != nil {
		return "", err
	}
	return c.Encrypt(plaintext)
}

func (c *Crypto) DecryptJSON(encoded string, v interface{}) error {
	plaintext, err := c.Decrypt(encoded)
	if err != nil {
		return err
	}
	return jsonUnmarshal(plaintext, v)
}

func jsonMarshal(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case string:
		return []byte(val), nil
	case []byte:
		return val, nil
	default:
		return nil, fmt.Errorf("unsupported type for marshaling: %T", v)
	}
}

func jsonUnmarshal(data []byte, v interface{}) error {
	switch ptr := v.(type) {
	case *string:
		*ptr = string(data)
		return nil
	case *[]byte:
		*ptr = data
		return nil
	default:
		return fmt.Errorf("unsupported type for unmarshaling: %T", v)
	}
}