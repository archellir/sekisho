package policy

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/archellir/sekisho/internal/config"
)

type Loader struct {
	engine   *Engine
	lastMod  time.Time
	filePath string
}

func NewLoader(configPath string) (*Loader, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	rules := make([]*Rule, len(cfg.Policy.Rules))
	for i, ruleConfig := range cfg.Policy.Rules {
		rules[i] = &Rule{
			Name:        ruleConfig.Name,
			Path:        ruleConfig.Path,
			Methods:     ruleConfig.Methods,
			Action:      ruleConfig.Action,
			AllowUsers:  ruleConfig.AllowUsers,
			RequireAuth: ruleConfig.RequireAuth,
		}
	}

	engine := NewEngine(rules, cfg.Policy.DefaultAction, cfg.Policy.CacheSize)

	var lastMod time.Time
	if configPath != "" {
		if info, err := os.Stat(configPath); err == nil {
			lastMod = info.ModTime()
		}
	}

	return &Loader{
		engine:   engine,
		lastMod:  lastMod,
		filePath: configPath,
	}, nil
}

func (l *Loader) GetEngine() *Engine {
	return l.engine
}

func (l *Loader) CheckForUpdates() error {
	if l.filePath == "" {
		return nil
	}

	info, err := os.Stat(l.filePath)
	if err != nil {
		return err
	}

	if info.ModTime().After(l.lastMod) {
		return l.reload()
	}

	return nil
}

func (l *Loader) reload() error {
	cfg, err := config.Load(l.filePath)
	if err != nil {
		return err
	}

	rules := make([]*Rule, len(cfg.Policy.Rules))
	for i, ruleConfig := range cfg.Policy.Rules {
		rules[i] = &Rule{
			Name:        ruleConfig.Name,
			Path:        ruleConfig.Path,
			Methods:     ruleConfig.Methods,
			Action:      ruleConfig.Action,
			AllowUsers:  ruleConfig.AllowUsers,
			RequireAuth: ruleConfig.RequireAuth,
		}
	}

	l.engine.UpdateRules(rules)

	if info, err := os.Stat(l.filePath); err == nil {
		l.lastMod = info.ModTime()
	}

	return nil
}

func (l *Loader) StartHotReload(interval time.Duration) {
	if interval == 0 {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			l.CheckForUpdates()
		}
	}()
}

func LoadRulesFromString(rulesYAML string) ([]*Rule, error) {
	lines := strings.Split(rulesYAML, "\n")
	var rules []*Rule
	var currentRule *Rule

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "- name:") {
			if currentRule != nil {
				rules = append(rules, currentRule)
			}
			currentRule = &Rule{}
			currentRule.Name = extractValue(line)
		} else if currentRule != nil {
			switch {
			case strings.HasPrefix(line, "path:"):
				currentRule.Path = extractValue(line)
			case strings.HasPrefix(line, "action:"):
				currentRule.Action = extractValue(line)
			case strings.HasPrefix(line, "methods:"):
				currentRule.Methods = parseStringArray(extractValue(line))
			case strings.HasPrefix(line, "allow_users:"):
				currentRule.AllowUsers = parseStringArray(extractValue(line))
			case strings.HasPrefix(line, "deny_users:"):
				currentRule.DenyUsers = parseStringArray(extractValue(line))
			case strings.HasPrefix(line, "require_auth:"):
				currentRule.RequireAuth = extractValue(line) == "true"
			}
		}
	}

	if currentRule != nil {
		rules = append(rules, currentRule)
	}

	return rules, nil
}

func extractValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) == 2 {
		return strings.Trim(strings.TrimSpace(parts[1]), `"'`)
	}
	return ""
}

func parseStringArray(value string) []string {
	if value == "" {
		return nil
	}

	value = strings.Trim(value, "[]")
	parts := strings.Split(value, ",")
	var result []string
	
	for _, part := range parts {
		part = strings.Trim(strings.TrimSpace(part), `"'`)
		if part != "" {
			result = append(result, part)
		}
	}
	
	return result
}

func ValidateRules(rules []*Rule) []error {
	var errors []error
	names := make(map[string]bool)

	for i, rule := range rules {
		if rule.Name == "" {
			errors = append(errors, fmt.Errorf("rule %d: name is required", i))
			continue
		}

		if names[rule.Name] {
			errors = append(errors, fmt.Errorf("rule %d: duplicate name '%s'", i, rule.Name))
		}
		names[rule.Name] = true

		if rule.Path == "" {
			errors = append(errors, fmt.Errorf("rule %d (%s): path is required", i, rule.Name))
		}

		if rule.Action != "allow" && rule.Action != "deny" {
			errors = append(errors, fmt.Errorf("rule %d (%s): action must be 'allow' or 'deny'", i, rule.Name))
		}

		for _, method := range rule.Methods {
			if !isValidHTTPMethod(method) {
				errors = append(errors, fmt.Errorf("rule %d (%s): invalid HTTP method '%s'", i, rule.Name, method))
			}
		}

		for _, email := range rule.AllowUsers {
			if !isValidEmail(email) {
				errors = append(errors, fmt.Errorf("rule %d (%s): invalid email pattern '%s'", i, rule.Name, email))
			}
		}

		for _, email := range rule.DenyUsers {
			if !isValidEmail(email) {
				errors = append(errors, fmt.Errorf("rule %d (%s): invalid email pattern '%s'", i, rule.Name, email))
			}
		}
	}

	return errors
}

func isValidHTTPMethod(method string) bool {
	validMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"}
	method = strings.ToUpper(method)
	
	for _, valid := range validMethods {
		if method == valid {
			return true
		}
	}
	return false
}

func isValidEmail(email string) bool {
	if email == "" {
		return false
	}

	if strings.HasPrefix(email, "@") {
		return len(email) > 1 && strings.Contains(email[1:], ".")
	}

	if strings.Contains(email, "*") || strings.Contains(email, "?") {
		return true
	}

	return strings.Contains(email, "@") && strings.Contains(email, ".")
}