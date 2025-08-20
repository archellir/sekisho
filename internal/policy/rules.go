package policy

import (
	"net"
	"strings"
)

type Rule struct {
	Name        string   `yaml:"name"`
	Path        string   `yaml:"path"`
	Methods     []string `yaml:"methods"`
	Action      string   `yaml:"action"`
	AllowUsers  []string `yaml:"allow_users"`
	DenyUsers   []string `yaml:"deny_users"`
	AllowIPs    []string `yaml:"allow_ips"`
	DenyIPs     []string `yaml:"deny_ips"`
	RequireAuth bool     `yaml:"require_auth"`
	Priority    int      `yaml:"priority"`
}

func (r *Rule) Matches(ctx Context) bool {
	if !r.matchPath(ctx.Path) {
		return false
	}
	
	if !r.matchMethod(ctx.Method) {
		return false
	}
	
	return true
}

func (r *Rule) Evaluate(ctx Context) Decision {
	if r.Action == "deny" {
		return Decision{
			Allow:  false,
			Reason: "explicitly denied by rule: " + r.Name,
		}
	}

	if len(r.DenyUsers) > 0 && r.containsUser(r.DenyUsers, ctx.Email) {
		return Decision{
			Allow:  false,
			Reason: "user explicitly denied by rule: " + r.Name,
		}
	}

	if len(r.DenyIPs) > 0 && r.matchesIP(r.DenyIPs, ctx.IP) {
		return Decision{
			Allow:  false,
			Reason: "IP explicitly denied by rule: " + r.Name,
		}
	}

	if r.RequireAuth && (ctx.UserID == "" && ctx.Email == "") {
		return Decision{
			Allow:  false,
			Reason: "authentication required by rule: " + r.Name,
		}
	}

	if len(r.AllowUsers) > 0 && !r.containsUser(r.AllowUsers, ctx.Email) {
		return Decision{
			Allow:  false,
			Reason: "user not in allow list for rule: " + r.Name,
		}
	}

	if len(r.AllowIPs) > 0 && !r.matchesIP(r.AllowIPs, ctx.IP) {
		return Decision{
			Allow:  false,
			Reason: "IP not in allow list for rule: " + r.Name,
		}
	}

	return Decision{
		Allow:  true,
		Reason: "allowed by rule: " + r.Name,
	}
}

func (r *Rule) matchPath(path string) bool {
	return matchGlob(r.Path, path)
}

func (r *Rule) matchMethod(method string) bool {
	if len(r.Methods) == 0 {
		return true
	}
	
	for _, m := range r.Methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

func (r *Rule) containsUser(users []string, email string) bool {
	for _, user := range users {
		if matchGlob(user, email) {
			return true
		}
	}
	return false
}

func (r *Rule) matchesIP(ipList []string, clientIP string) bool {
	clientIP = strings.Split(clientIP, ":")[0]
	
	for _, ipPattern := range ipList {
		if matchIP(ipPattern, clientIP) {
			return true
		}
	}
	return false
}

func matchGlob(pattern, str string) bool {
	return matchGlobRecursive(pattern, str, 0, 0)
}

func matchGlobRecursive(pattern, str string, p, s int) bool {
	for p < len(pattern) {
		switch pattern[p] {
		case '*':
			if p == len(pattern)-1 {
				return true
			}
			
			for s <= len(str) {
				if matchGlobRecursive(pattern, str, p+1, s) {
					return true
				}
				s++
			}
			return false
			
		case '?':
			if s >= len(str) {
				return false
			}
			p++
			s++
			
		default:
			if s >= len(str) || pattern[p] != str[s] {
				return false
			}
			p++
			s++
		}
	}
	
	return s == len(str)
}

func matchIP(pattern, ip string) bool {
	if pattern == ip {
		return true
	}
	
	if strings.Contains(pattern, "/") {
		_, network, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		clientIP := net.ParseIP(ip)
		if clientIP == nil {
			return false
		}
		return network.Contains(clientIP)
	}
	
	return matchGlob(pattern, ip)
}

type RuleSet struct {
	Rules []*Rule
}

func (rs *RuleSet) Sort() {
	if len(rs.Rules) <= 1 {
		return
	}
	
	for i := 0; i < len(rs.Rules)-1; i++ {
		for j := 0; j < len(rs.Rules)-i-1; j++ {
			if rs.Rules[j].Priority < rs.Rules[j+1].Priority {
				rs.Rules[j], rs.Rules[j+1] = rs.Rules[j+1], rs.Rules[j]
			}
		}
	}
}

func (rs *RuleSet) Validate() []error {
	var errors []error
	
	for i, rule := range rs.Rules {
		if rule.Name == "" {
			errors = append(errors, ruleError(i, "name is required"))
		}
		
		if rule.Path == "" {
			errors = append(errors, ruleError(i, "path is required"))
		}
		
		if rule.Action != "allow" && rule.Action != "deny" {
			errors = append(errors, ruleError(i, "action must be 'allow' or 'deny'"))
		}
		
		for _, ip := range rule.AllowIPs {
			if !isValidIPPattern(ip) {
				errors = append(errors, ruleError(i, "invalid IP pattern: "+ip))
			}
		}
		
		for _, ip := range rule.DenyIPs {
			if !isValidIPPattern(ip) {
				errors = append(errors, ruleError(i, "invalid IP pattern: "+ip))
			}
		}
	}
	
	return errors
}

func ruleError(index int, message string) error {
	return &RuleError{Index: index, Message: message}
}

type RuleError struct {
	Index   int
	Message string
}

func (re *RuleError) Error() string {
	return "rule " + string(rune(re.Index)) + ": " + re.Message
}

func isValidIPPattern(pattern string) bool {
	if strings.Contains(pattern, "/") {
		_, _, err := net.ParseCIDR(pattern)
		return err == nil
	}
	
	if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
		return true
	}
	
	return net.ParseIP(pattern) != nil
}