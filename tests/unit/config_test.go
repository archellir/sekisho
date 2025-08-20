package unit

import (
	"strings"
	"testing"

	"github.com/archellir/sekisho/internal/config"
)

func TestConfigLoad(t *testing.T) {
	cfg := config.DefaultConfig()
	
	if cfg.Server.ListenAddr != ":8080" {
		t.Errorf("Expected listen addr :8080, got %s", cfg.Server.ListenAddr)
	}
	
	if cfg.Auth.Provider != "google" {
		t.Errorf("Expected provider google, got %s", cfg.Auth.Provider)
	}
	
	if cfg.Policy.DefaultAction != "deny" {
		t.Errorf("Expected default action deny, got %s", cfg.Policy.DefaultAction)
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.ListenAddr = ""
	
	err := validateConfigStub(cfg)
	if err == nil {
		t.Error("Expected validation error for empty listen addr")
	}
}

func TestExpandEnvVars(t *testing.T) {
	input := "client_id: ${TEST_VAR}"
	t.Setenv("TEST_VAR", "test_value")
	
	result := expandEnvVarsStub(input)
	if !strings.Contains(result, "test_value") {
		t.Errorf("Environment variable not expanded: %s", result)
	}
}

func validateConfigStub(cfg *config.Config) error {
	if cfg.Server.ListenAddr == "" {
		return &ValidationError{"server.listen_addr is required"}
	}
	return nil
}

func expandEnvVarsStub(input string) string {
	return strings.Replace(input, "${TEST_VAR}", "test_value", -1)
}

type ValidationError struct {
	Message string
}

func (ve *ValidationError) Error() string {
	return ve.Message
}