package middleware

import (
	"net/http"
	"sync"
	"time"
)

type RateLimiter struct {
	visitors map[string]*visitor
	mutex    sync.RWMutex
	rate     float64
	burst    int
	cleanup  time.Duration
}

type visitor struct {
	limiter  *TokenBucket
	lastSeen time.Time
}

type TokenBucket struct {
	tokens    float64
	capacity  int
	rate      float64
	lastRefill time.Time
	mutex     sync.Mutex
}

func NewRateLimiter(requestsPerSecond float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     requestsPerSecond,
		burst:    burst,
		cleanup:  5 * time.Minute,
	}
	
	go rl.cleanupVisitors()
	return rl
}

func (rl *RateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		
		if !rl.Allow(ip) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mutex.Lock()
	v, exists := rl.visitors[key]
	if !exists {
		v = &visitor{
			limiter: NewTokenBucket(rl.rate, rl.burst),
			lastSeen: time.Now(),
		}
		rl.visitors[key] = v
	} else {
		v.lastSeen = time.Now()
	}
	rl.mutex.Unlock()
	
	return v.limiter.Allow()
}

func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()
	
	for range ticker.C {
		rl.mutex.Lock()
		cutoff := time.Now().Add(-rl.cleanup)
		
		for key, v := range rl.visitors {
			if v.lastSeen.Before(cutoff) {
				delete(rl.visitors, key)
			}
		}
		rl.mutex.Unlock()
	}
}

func NewTokenBucket(rate float64, capacity int) *TokenBucket {
	return &TokenBucket{
		tokens:     float64(capacity),
		capacity:   capacity,
		rate:       rate,
		lastRefill: time.Now(),
	}
}

func (tb *TokenBucket) Allow() bool {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()
	
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	
	tb.tokens += elapsed * tb.rate
	if tb.tokens > float64(tb.capacity) {
		tb.tokens = float64(tb.capacity)
	}
	
	tb.lastRefill = now
	
	if tb.tokens >= 1.0 {
		tb.tokens--
		return true
	}
	
	return false
}

func (tb *TokenBucket) Tokens() float64 {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()
	return tb.tokens
}

type PerUserRateLimiter struct {
	limiters map[string]*RateLimiter
	mutex    sync.RWMutex
	rate     float64
	burst    int
}

func NewPerUserRateLimiter(requestsPerSecond float64, burst int) *PerUserRateLimiter {
	return &PerUserRateLimiter{
		limiters: make(map[string]*RateLimiter),
		rate:     requestsPerSecond,
		burst:    burst,
	}
}

func (prl *PerUserRateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := r.Header.Get("X-User-ID")
		if userID == "" {
			userID = getClientIP(r)
		}
		
		prl.mutex.RLock()
		limiter, exists := prl.limiters[userID]
		prl.mutex.RUnlock()
		
		if !exists {
			prl.mutex.Lock()
			limiter, exists = prl.limiters[userID]
			if !exists {
				limiter = NewRateLimiter(prl.rate, prl.burst)
				prl.limiters[userID] = limiter
			}
			prl.mutex.Unlock()
		}
		
		if !limiter.Allow(userID) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

type AdaptiveRateLimiter struct {
	baseLimiter *RateLimiter
	maxRate     float64
	minRate     float64
	currentRate float64
	errorCount  int
	successCount int
	mutex       sync.Mutex
	window      time.Duration
	lastAdjust  time.Time
}

func NewAdaptiveRateLimiter(baseRate, minRate, maxRate float64, burst int) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		baseLimiter: NewRateLimiter(baseRate, burst),
		maxRate:     maxRate,
		minRate:     minRate,
		currentRate: baseRate,
		window:      1 * time.Minute,
		lastAdjust:  time.Now(),
	}
}

func (arl *AdaptiveRateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		
		if !arl.Allow(ip) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			arl.recordError()
			return
		}
		
		wrapped := &responseWriter{ResponseWriter: w}
		next.ServeHTTP(wrapped, r)
		
		if wrapped.statusCode >= 500 {
			arl.recordError()
		} else {
			arl.recordSuccess()
		}
	})
}

func (arl *AdaptiveRateLimiter) Allow(key string) bool {
	arl.adjustRate()
	return arl.baseLimiter.Allow(key)
}

func (arl *AdaptiveRateLimiter) recordError() {
	arl.mutex.Lock()
	defer arl.mutex.Unlock()
	arl.errorCount++
}

func (arl *AdaptiveRateLimiter) recordSuccess() {
	arl.mutex.Lock()
	defer arl.mutex.Unlock()
	arl.successCount++
}

func (arl *AdaptiveRateLimiter) adjustRate() {
	arl.mutex.Lock()
	defer arl.mutex.Unlock()
	
	now := time.Now()
	if now.Sub(arl.lastAdjust) < arl.window {
		return
	}
	
	total := arl.errorCount + arl.successCount
	if total == 0 {
		return
	}
	
	errorRate := float64(arl.errorCount) / float64(total)
	
	if errorRate > 0.1 {
		arl.currentRate *= 0.8
		if arl.currentRate < arl.minRate {
			arl.currentRate = arl.minRate
		}
	} else if errorRate < 0.05 {
		arl.currentRate *= 1.2
		if arl.currentRate > arl.maxRate {
			arl.currentRate = arl.maxRate
		}
	}
	
	arl.baseLimiter.rate = arl.currentRate
	arl.errorCount = 0
	arl.successCount = 0
	arl.lastAdjust = now
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
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