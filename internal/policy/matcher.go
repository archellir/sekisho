package policy

import (
	"net"
	"strings"
)

type Matcher interface {
	Match(pattern, input string) bool
}

type GlobMatcher struct{}

func (gm *GlobMatcher) Match(pattern, input string) bool {
	return matchGlobPattern(pattern, input)
}

type RegexMatcher struct{}

func (rm *RegexMatcher) Match(pattern, input string) bool {
	return matchGlobPattern(pattern, input)
}

type PathMatcher struct {
	caseSensitive bool
}

func NewPathMatcher(caseSensitive bool) *PathMatcher {
	return &PathMatcher{caseSensitive: caseSensitive}
}

func (pm *PathMatcher) Match(pattern, path string) bool {
	if !pm.caseSensitive {
		pattern = strings.ToLower(pattern)
		path = strings.ToLower(path)
	}
	
	return matchGlobPattern(pattern, path)
}

type EmailMatcher struct{}

func (em *EmailMatcher) Match(pattern, email string) bool {
	if pattern == email {
		return true
	}
	
	if strings.HasPrefix(pattern, "@") {
		domain := strings.Split(email, "@")
		if len(domain) == 2 {
			return matchGlobPattern(pattern[1:], domain[1])
		}
	}
	
	return matchGlobPattern(pattern, email)
}

type IPMatcher struct{}

func (im *IPMatcher) Match(pattern, ip string) bool {
	return matchIPPattern(pattern, ip)
}

func matchGlobPattern(pattern, str string) bool {
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

func matchIPPattern(pattern, ip string) bool {
	ip = extractIP(ip)
	
	if pattern == ip {
		return true
	}
	
	if strings.Contains(pattern, "/") {
		return matchCIDR(pattern, ip)
	}
	
	if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
		return matchGlobPattern(pattern, ip)
	}
	
	return false
}

func matchCIDR(cidr, ip string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	
	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}
	
	return network.Contains(clientIP)
}

func extractIP(addr string) string {
	if strings.Contains(addr, ":") {
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			return host
		}
	}
	return addr
}

type MultiMatcher struct {
	matchers []Matcher
}

func NewMultiMatcher(matchers ...Matcher) *MultiMatcher {
	return &MultiMatcher{matchers: matchers}
}

func (mm *MultiMatcher) Match(pattern, input string) bool {
	for _, matcher := range mm.matchers {
		if matcher.Match(pattern, input) {
			return true
		}
	}
	return false
}

type CompoundMatcher struct {
	pathMatcher  *PathMatcher
	emailMatcher *EmailMatcher
	ipMatcher    *IPMatcher
	globMatcher  *GlobMatcher
}

func NewCompoundMatcher(caseSensitivePaths bool) *CompoundMatcher {
	return &CompoundMatcher{
		pathMatcher:  NewPathMatcher(caseSensitivePaths),
		emailMatcher: &EmailMatcher{},
		ipMatcher:    &IPMatcher{},
		globMatcher:  &GlobMatcher{},
	}
}

func (cm *CompoundMatcher) MatchPath(pattern, path string) bool {
	return cm.pathMatcher.Match(pattern, path)
}

func (cm *CompoundMatcher) MatchEmail(pattern, email string) bool {
	return cm.emailMatcher.Match(pattern, email)
}

func (cm *CompoundMatcher) MatchIP(pattern, ip string) bool {
	return cm.ipMatcher.Match(pattern, ip)
}

func (cm *CompoundMatcher) MatchGlob(pattern, str string) bool {
	return cm.globMatcher.Match(pattern, str)
}

func MatchAny(patterns []string, input string, matcher Matcher) bool {
	for _, pattern := range patterns {
		if matcher.Match(pattern, input) {
			return true
		}
	}
	return false
}

func MatchAll(patterns []string, input string, matcher Matcher) bool {
	for _, pattern := range patterns {
		if !matcher.Match(pattern, input) {
			return false
		}
	}
	return true
}

type CachedMatcher struct {
	matcher Matcher
	cache   map[string]bool
}

func NewCachedMatcher(matcher Matcher) *CachedMatcher {
	return &CachedMatcher{
		matcher: matcher,
		cache:   make(map[string]bool),
	}
}

func (cm *CachedMatcher) Match(pattern, input string) bool {
	key := pattern + ":" + input
	if result, exists := cm.cache[key]; exists {
		return result
	}
	
	result := cm.matcher.Match(pattern, input)
	cm.cache[key] = result
	return result
}

func (cm *CachedMatcher) ClearCache() {
	cm.cache = make(map[string]bool)
}