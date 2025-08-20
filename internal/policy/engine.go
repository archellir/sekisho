package policy

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Decision struct {
	Allow  bool
	Reason string
	Rule   *Rule
}

type Context struct {
	UserID   string
	Email    string
	Path     string
	Method   string
	IP       string
	UserAgent string
}

type Engine struct {
	rules      []*Rule
	defaultAction string
	cache      *DecisionCache
	mutex      sync.RWMutex
}

type DecisionCache struct {
	entries map[string]*CacheEntry
	mutex   sync.RWMutex
	maxSize int
	ttl     time.Duration
}

type CacheEntry struct {
	decision  Decision
	timestamp time.Time
}

func NewEngine(rules []*Rule, defaultAction string, cacheSize int) *Engine {
	if defaultAction != "allow" && defaultAction != "deny" {
		defaultAction = "deny"
	}

	cache := &DecisionCache{
		entries: make(map[string]*CacheEntry),
		maxSize: cacheSize,
		ttl:     5 * time.Minute,
	}

	engine := &Engine{
		rules:         rules,
		defaultAction: defaultAction,
		cache:         cache,
	}

	go engine.startCleanup()
	return engine
}

func (e *Engine) Evaluate(ctx Context) Decision {
	cacheKey := e.buildCacheKey(ctx)
	
	if cached := e.cache.Get(cacheKey); cached != nil {
		return *cached
	}

	decision := e.evaluateRules(ctx)
	e.cache.Set(cacheKey, decision)
	
	return decision
}

func (e *Engine) evaluateRules(ctx Context) Decision {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	for _, rule := range e.rules {
		if rule.Matches(ctx) {
			decision := rule.Evaluate(ctx)
			decision.Rule = rule
			return decision
		}
	}

	return Decision{
		Allow:  e.defaultAction == "allow",
		Reason: fmt.Sprintf("default action: %s", e.defaultAction),
		Rule:   nil,
	}
}

func (e *Engine) UpdateRules(rules []*Rule) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	
	e.rules = rules
	e.cache.Clear()
}

func (e *Engine) AddRule(rule *Rule) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	
	e.rules = append(e.rules, rule)
	e.cache.Clear()
}

func (e *Engine) RemoveRule(name string) bool {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	
	for i, rule := range e.rules {
		if rule.Name == name {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			e.cache.Clear()
			return true
		}
	}
	return false
}

func (e *Engine) GetRules() []*Rule {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	
	rules := make([]*Rule, len(e.rules))
	copy(rules, e.rules)
	return rules
}

func (e *Engine) buildCacheKey(ctx Context) string {
	return fmt.Sprintf("%s:%s:%s:%s", ctx.UserID, ctx.Email, ctx.Path, ctx.Method)
}

func (e *Engine) startCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			e.cache.Cleanup()
		}
	}()
}

func (c *DecisionCache) Get(key string) *Decision {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	entry, exists := c.entries[key]
	if !exists {
		return nil
	}
	
	if time.Since(entry.timestamp) > c.ttl {
		delete(c.entries, key)
		return nil
	}
	
	return &entry.decision
}

func (c *DecisionCache) Set(key string, decision Decision) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}
	
	c.entries[key] = &CacheEntry{
		decision:  decision,
		timestamp: time.Now(),
	}
}

func (c *DecisionCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.entries = make(map[string]*CacheEntry)
}

func (c *DecisionCache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	now := time.Now()
	for key, entry := range c.entries {
		if now.Sub(entry.timestamp) > c.ttl {
			delete(c.entries, key)
		}
	}
}

func (c *DecisionCache) evictOldest() {
	oldestKey := ""
	oldestTime := time.Now()
	
	for key, entry := range c.entries {
		if entry.timestamp.Before(oldestTime) {
			oldestTime = entry.timestamp
			oldestKey = key
		}
	}
	
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

func (c *DecisionCache) Size() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.entries)
}

func (e *Engine) Allow(userID, email, path, method string) bool {
	ctx := Context{
		UserID: userID,
		Email:  email,
		Path:   path,
		Method: method,
	}
	
	decision := e.Evaluate(ctx)
	return decision.Allow
}

func (e *Engine) CacheSize() int {
	return e.cache.Size()
}

type PolicyMiddleware struct {
	engine *Engine
}

func NewPolicyMiddleware(engine *Engine) *PolicyMiddleware {
	return &PolicyMiddleware{engine: engine}
}

func (pm *PolicyMiddleware) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := Context{
			Path:   r.URL.Path,
			Method: r.Method,
			IP:     getClientIP(r),
			UserAgent: r.UserAgent(),
		}

		if userID := r.Header.Get("X-User-ID"); userID != "" {
			ctx.UserID = userID
		}
		if email := r.Header.Get("X-User-Email"); email != "" {
			ctx.Email = email
		}

		decision := pm.engine.Evaluate(ctx)
		if !decision.Allow {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return forwarded
	}
	
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}
	
	return r.RemoteAddr
}