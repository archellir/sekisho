package unit

import (
	"testing"
	"time"

	"github.com/archellir/sekisho/internal/session"
)

func TestSessionCrypto(t *testing.T) {
	encryptKey := make([]byte, 32)
	signKey := make([]byte, 32)
	
	for i := range encryptKey {
		encryptKey[i] = byte(i)
	}
	for i := range signKey {
		signKey[i] = byte(i + 32)
	}
	
	crypto, err := session.NewCrypto(encryptKey, signKey)
	if err != nil {
		t.Fatal("Failed to create crypto:", err)
	}

	plaintext := "sensitive session data"
	
	encrypted, err := crypto.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatal("Failed to encrypt:", err)
	}

	if encrypted == plaintext {
		t.Error("Encrypted text should not match plaintext")
	}

	decrypted, err := crypto.Decrypt(encrypted)
	if err != nil {
		t.Fatal("Failed to decrypt:", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("Decrypted text doesn't match: expected %s, got %s", plaintext, string(decrypted))
	}
}

func TestSessionStore(t *testing.T) {
	store := session.NewStore(1 * time.Hour)

	sess, err := store.Create("user123", "user@example.com", "User Name", "")
	if err != nil {
		t.Fatal("Failed to create session:", err)
	}

	if sess.UserID != "user123" {
		t.Errorf("Expected UserID user123, got %s", sess.UserID)
	}

	if sess.Email != "user@example.com" {
		t.Errorf("Expected email user@example.com, got %s", sess.Email)
	}

	retrieved, exists := store.Get(sess.ID)
	if !exists {
		t.Fatal("Session not found after creation")
	}

	if retrieved.UserID != sess.UserID {
		t.Error("Retrieved session doesn't match created session")
	}

	store.Delete(sess.ID)
	_, exists = store.Get(sess.ID)
	if exists {
		t.Error("Session still exists after deletion")
	}
}

func TestSessionExpiry(t *testing.T) {
	store := session.NewStore(1 * time.Millisecond)

	sess, err := store.Create("user123", "user@example.com", "User Name", "")
	if err != nil {
		t.Fatal("Failed to create session:", err)
	}

	time.Sleep(2 * time.Millisecond)

	_, exists := store.Get(sess.ID)
	if exists {
		t.Error("Expired session still exists")
	}
}

func TestGenerateSessionID(t *testing.T) {
	encryptKey := make([]byte, 32)
	signKey := make([]byte, 32)
	
	crypto, _ := session.NewCrypto(encryptKey, signKey)

	id1, err := crypto.GenerateSessionID()
	if err != nil {
		t.Fatal("Failed to generate session ID:", err)
	}

	id2, err := crypto.GenerateSessionID()
	if err != nil {
		t.Fatal("Failed to generate second session ID:", err)
	}

	if id1 == id2 {
		t.Error("Generated session IDs should be unique")
	}

	if len(id1) == 0 {
		t.Error("Session ID should not be empty")
	}
}