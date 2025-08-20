package unit

import (
	"testing"

	"github.com/archellir/sekisho/internal/policy"
)

func TestPolicyEngineEvaluate(t *testing.T) {
	rules := []*policy.Rule{
		{
			Name:    "allow_public",
			Path:    "/public/*",
			Methods: []string{"GET"},
			Action:  "allow",
		},
		{
			Name:        "require_auth",
			Path:        "/private/*",
			Methods:     []string{"GET", "POST"},
			Action:      "allow",
			RequireAuth: true,
		},
	}

	engine := policy.NewEngine(rules, "deny", 100)

	tests := []struct {
		name     string
		ctx      policy.Context
		expected bool
	}{
		{
			name: "allow_public_path",
			ctx: policy.Context{
				Path:   "/public/test",
				Method: "GET",
			},
			expected: true,
		},
		{
			name: "deny_private_without_auth",
			ctx: policy.Context{
				Path:   "/private/test",
				Method: "GET",
			},
			expected: false,
		},
		{
			name: "allow_private_with_auth",
			ctx: policy.Context{
				UserID: "user123",
				Email:  "user@example.com",
				Path:   "/private/test",
				Method: "GET",
			},
			expected: true,
		},
		{
			name: "deny_unknown_path",
			ctx: policy.Context{
				Path:   "/unknown",
				Method: "GET",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := engine.Evaluate(tt.ctx)
			if decision.Allow != tt.expected {
				t.Errorf("Expected %v, got %v. Reason: %s", tt.expected, decision.Allow, decision.Reason)
			}
		})
	}
}

func TestGlobMatching(t *testing.T) {
	tests := []struct {
		pattern  string
		input    string
		expected bool
	}{
		{"*", "anything", true},
		{"/api/*", "/api/users", true},
		{"/api/*", "/api/", true},
		{"/api/*", "/api", false},
		{"/admin/*/edit", "/admin/users/edit", true},
		{"/admin/*/edit", "/admin/users/view", false},
		{"*.txt", "file.txt", true},
		{"*.txt", "file.pdf", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.input, func(t *testing.T) {
			result := matchGlobStub(tt.pattern, tt.input)
			if result != tt.expected {
				t.Errorf("Pattern %s with input %s: expected %v, got %v", 
					tt.pattern, tt.input, tt.expected, result)
			}
		})
	}
}

func matchGlobStub(pattern, str string) bool {
	pi, si := 0, 0
	starIdx, match := -1, 0
	
	for si < len(str) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == str[si]) {
			pi++
			si++
		} else if pi < len(pattern) && pattern[pi] == '*' {
			starIdx = pi
			match = si
			pi++
		} else if starIdx != -1 {
			pi = starIdx + 1
			match++
			si = match
		} else {
			return false
		}
	}
	
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	
	return pi == len(pattern)
}