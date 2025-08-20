package config

import (
	"time"
)

type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Auth        AuthConfig        `yaml:"auth"`
	Upstream    []UpstreamConfig  `yaml:"upstream"`
	Policy      PolicyConfig      `yaml:"policy"`
	TCPProxy    []TCPProxyConfig  `yaml:"tcp_proxy"`
	RateLimit   RateLimitConfig   `yaml:"rate_limiting"`
	Audit       AuditConfig       `yaml:"audit"`
	Metrics     MetricsConfig     `yaml:"metrics"`
}

type ServerConfig struct {
	ListenAddr      string        `yaml:"listen_addr"`
	TCPProxyAddr    string        `yaml:"tcp_proxy_addr"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

type AuthConfig struct {
	Provider        string        `yaml:"provider"`
	ClientID        string        `yaml:"client_id"`
	ClientSecret    string        `yaml:"client_secret"`
	RedirectURL     string        `yaml:"redirect_url"`
	SessionDuration time.Duration `yaml:"session_duration"`
	CookieDomain    string        `yaml:"cookie_domain"`
	CookieSecure    bool          `yaml:"cookie_secure"`
}

type UpstreamConfig struct {
	Host    string        `yaml:"host"`
	Target  string        `yaml:"target"`
	Timeout time.Duration `yaml:"timeout"`
}

type PolicyConfig struct {
	DefaultAction string       `yaml:"default_action"`
	CacheSize     int          `yaml:"cache_size"`
	Rules         []PolicyRule `yaml:"rules"`
}

type PolicyRule struct {
	Name        string   `yaml:"name"`
	Path        string   `yaml:"path"`
	Methods     []string `yaml:"methods"`
	Action      string   `yaml:"action"`
	AllowUsers  []string `yaml:"allow_users"`
	RequireAuth bool     `yaml:"require_auth"`
}

type TCPProxyConfig struct {
	Name         string   `yaml:"name"`
	ListenPort   int      `yaml:"listen_port"`
	Target       string   `yaml:"target"`
	AllowedUsers []string `yaml:"allowed_users"`
}

type RateLimitConfig struct {
	RequestsPerSecond    float64       `yaml:"requests_per_second"`
	BurstSize            int           `yaml:"burst_size"`
	AuthRequestsPerMin   int           `yaml:"auth_requests_per_minute"`
	CleanupInterval      time.Duration `yaml:"cleanup_interval"`
}

type AuditConfig struct {
	Enabled             bool   `yaml:"enabled"`
	LogPath             string `yaml:"log_path"`
	RotationSize        string `yaml:"rotation_size"`
	RotationAge         string `yaml:"rotation_age"`
	RetentionCount      int    `yaml:"retention_count"`
	IncludeRequestBody  bool   `yaml:"include_request_body"`
	IncludeResponseBody bool   `yaml:"include_response_body"`
}

type MetricsConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Path      string `yaml:"path"`
	Namespace string `yaml:"namespace"`
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			ListenAddr:      ":8080",
			TCPProxyAddr:    ":5432",
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			ShutdownTimeout: 10 * time.Second,
		},
		Auth: AuthConfig{
			Provider:        "google",
			SessionDuration: 24 * time.Hour,
			CookieSecure:    true,
		},
		Policy: PolicyConfig{
			DefaultAction: "deny",
			CacheSize:     10000,
		},
		RateLimit: RateLimitConfig{
			RequestsPerSecond:  100,
			BurstSize:          200,
			AuthRequestsPerMin: 10,
			CleanupInterval:    5 * time.Minute,
		},
		Audit: AuditConfig{
			Enabled:        true,
			LogPath:        "/var/log/sekisho/audit.jsonl",
			RotationSize:   "100MB",
			RotationAge:    "7d",
			RetentionCount: 30,
		},
		Metrics: MetricsConfig{
			Enabled:   true,
			Path:      "/metrics",
			Namespace: "sekisho",
		},
	}
}