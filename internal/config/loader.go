package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var envVarRegex = regexp.MustCompile(`\$\{([^}]+)\}`)

func Load(configPath string) (*Config, error) {
	config := DefaultConfig()

	if configPath == "" {
		return config, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	expanded := expandEnvVars(string(data))

	if err := parseYAML(expanded, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

func expandEnvVars(input string) string {
	return envVarRegex.ReplaceAllStringFunc(input, func(match string) string {
		varName := match[2 : len(match)-1]
		return os.Getenv(varName)
	})
}

func parseYAML(content string, config *Config) error {
	scanner := bufio.NewScanner(strings.NewReader(content))
	currentSection := ""
	currentRule := &PolicyRule{}
	ruleIndex := -1

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentSection = strings.TrimSpace(parts[0])
			}
			continue
		}

		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			
			if value == "" {
				continue
			}

			if err := setConfigValue(config, currentSection, key, value, currentRule, &ruleIndex); err != nil {
				return err
			}
		}
	}

	return scanner.Err()
}

func setConfigValue(config *Config, section, key, value string, currentRule *PolicyRule, ruleIndex *int) error {
	switch section {
	case "server":
		return setServerConfig(&config.Server, key, value)
	case "auth":
		return setAuthConfig(&config.Auth, key, value)
	case "policy":
		if key == "rules" || strings.HasPrefix(key, "-") {
			if strings.HasPrefix(key, "- name") || key == "name" {
				if *ruleIndex >= 0 {
					config.Policy.Rules = append(config.Policy.Rules, *currentRule)
				}
				*currentRule = PolicyRule{}
				*ruleIndex++
				currentRule.Name = strings.Trim(value, `"'`)
			} else {
				return setPolicyRuleValue(currentRule, key, value)
			}
		} else {
			return setPolicyConfig(&config.Policy, key, value)
		}
	}
	return nil
}

func setServerConfig(server *ServerConfig, key, value string) error {
	switch key {
	case "listen_addr":
		server.ListenAddr = strings.Trim(value, `"'`)
	case "tcp_proxy_addr":
		server.TCPProxyAddr = strings.Trim(value, `"'`)
	case "read_timeout":
		dur, err := time.ParseDuration(strings.Trim(value, `"'`))
		if err != nil {
			return err
		}
		server.ReadTimeout = dur
	case "write_timeout":
		dur, err := time.ParseDuration(strings.Trim(value, `"'`))
		if err != nil {
			return err
		}
		server.WriteTimeout = dur
	case "shutdown_timeout":
		dur, err := time.ParseDuration(strings.Trim(value, `"'`))
		if err != nil {
			return err
		}
		server.ShutdownTimeout = dur
	}
	return nil
}

func setAuthConfig(auth *AuthConfig, key, value string) error {
	switch key {
	case "provider":
		auth.Provider = strings.Trim(value, `"'`)
	case "client_id":
		auth.ClientID = strings.Trim(value, `"'`)
	case "client_secret":
		auth.ClientSecret = strings.Trim(value, `"'`)
	case "redirect_url":
		auth.RedirectURL = strings.Trim(value, `"'`)
	case "session_duration":
		dur, err := time.ParseDuration(strings.Trim(value, `"'`))
		if err != nil {
			return err
		}
		auth.SessionDuration = dur
	case "cookie_domain":
		auth.CookieDomain = strings.Trim(value, `"'`)
	case "cookie_secure":
		auth.CookieSecure = value == "true"
	}
	return nil
}

func setPolicyConfig(policy *PolicyConfig, key, value string) error {
	switch key {
	case "default_action":
		policy.DefaultAction = strings.Trim(value, `"'`)
	case "cache_size":
		size, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		policy.CacheSize = size
	}
	return nil
}

func setPolicyRuleValue(rule *PolicyRule, key, value string) error {
	switch key {
	case "path":
		rule.Path = strings.Trim(value, `"'`)
	case "action":
		rule.Action = strings.Trim(value, `"'`)
	case "require_auth":
		rule.RequireAuth = value == "true"
	}
	return nil
}

func validateConfig(config *Config) error {
	if config.Server.ListenAddr == "" {
		return fmt.Errorf("server.listen_addr is required")
	}

	if config.Auth.Provider != "" {
		if config.Auth.ClientID == "" {
			return fmt.Errorf("auth.client_id is required when provider is set")
		}
		if config.Auth.ClientSecret == "" {
			return fmt.Errorf("auth.client_secret is required when provider is set")
		}
		if config.Auth.RedirectURL == "" {
			return fmt.Errorf("auth.redirect_url is required when provider is set")
		}
	}

	for i, upstream := range config.Upstream {
		if upstream.Host == "" {
			return fmt.Errorf("upstream[%d].host is required", i)
		}
		if upstream.Target == "" {
			return fmt.Errorf("upstream[%d].target is required", i)
		}
		if upstream.Timeout == 0 {
			config.Upstream[i].Timeout = 30 * time.Second
		}
	}

	for i, rule := range config.Policy.Rules {
		if rule.Name == "" {
			return fmt.Errorf("policy.rules[%d].name is required", i)
		}
		if rule.Path == "" {
			return fmt.Errorf("policy.rules[%d].path is required", i)
		}
		if rule.Action != "allow" && rule.Action != "deny" {
			return fmt.Errorf("policy.rules[%d].action must be 'allow' or 'deny'", i)
		}
	}

	return nil
}

func WriteDefault(w io.Writer) error {
	config := DefaultConfig()
	
	fmt.Fprintf(w, `server:
  listen_addr: "%s"
  tcp_proxy_addr: "%s"
  read_timeout: "%s"
  write_timeout: "%s"
  shutdown_timeout: "%s"

auth:
  provider: "%s"
  client_id: "${OAUTH_CLIENT_ID}"
  client_secret: "${OAUTH_CLIENT_SECRET}"
  redirect_url: "https://auth.yourdomain.com/callback"
  session_duration: "%s"
  cookie_domain: ".yourdomain.com"
  cookie_secure: %t

upstream:
  - host: "app.yourdomain.com"
    target: "http://app-service:8080"
    timeout: "30s"
  - host: "api.yourdomain.com"
    target: "http://api-service:3000"
    timeout: "10s"

policy:
  default_action: "%s"
  cache_size: %d
  rules:
    - name: "public_access"
      path: "/public/*"
      methods: ["GET"]
      action: "allow"
    - name: "authenticated_access"
      path: "/*"
      methods: ["GET", "POST", "PUT", "DELETE"]
      require_auth: true
      action: "allow"

rate_limiting:
  requests_per_second: %.1f
  burst_size: %d
  auth_requests_per_minute: %d
  cleanup_interval: "%s"

audit:
  enabled: %t
  log_path: "%s"
  rotation_size: "%s"
  rotation_age: "%s"
  retention_count: %d
  include_request_body: %t
  include_response_body: %t

metrics:
  enabled: %t
  path: "%s"
  namespace: "%s"
`,
		config.Server.ListenAddr,
		config.Server.TCPProxyAddr,
		config.Server.ReadTimeout,
		config.Server.WriteTimeout,
		config.Server.ShutdownTimeout,
		config.Auth.Provider,
		config.Auth.SessionDuration,
		config.Auth.CookieSecure,
		config.Policy.DefaultAction,
		config.Policy.CacheSize,
		config.RateLimit.RequestsPerSecond,
		config.RateLimit.BurstSize,
		config.RateLimit.AuthRequestsPerMin,
		config.RateLimit.CleanupInterval,
		config.Audit.Enabled,
		config.Audit.LogPath,
		config.Audit.RotationSize,
		config.Audit.RotationAge,
		config.Audit.RetentionCount,
		config.Audit.IncludeRequestBody,
		config.Audit.IncludeResponseBody,
		config.Metrics.Enabled,
		config.Metrics.Path,
		config.Metrics.Namespace,
	)

	return nil
}