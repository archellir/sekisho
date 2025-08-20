package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Formatter interface {
	Format(entry *Entry) ([]byte, error)
}

type JSONFormatter struct {
	TimeFormat    string
	PrettyPrint   bool
	IncludeFields map[string]bool
}

func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{
		TimeFormat: time.RFC3339,
		IncludeFields: map[string]bool{
			"timestamp":    true,
			"user":         true,
			"request":      true,
			"response":     true,
			"decision":     true,
			"duration":     true,
			"error":        true,
		},
	}
}

func (f *JSONFormatter) Format(entry *Entry) ([]byte, error) {
	data := make(map[string]interface{})

	if f.shouldInclude("timestamp") {
		data["timestamp"] = entry.Timestamp.Format(f.TimeFormat)
	}

	if f.shouldInclude("user") && entry.User.ID != "" {
		user := map[string]interface{}{
			"id":    entry.User.ID,
			"email": entry.User.Email,
		}
		if entry.User.Name != "" {
			user["name"] = entry.User.Name
		}
		data["user"] = user
	}

	if f.shouldInclude("request") {
		request := map[string]interface{}{
			"method": entry.Request.Method,
			"path":   entry.Request.Path,
			"ip":     entry.Request.IP,
		}
		
		if entry.Request.UserAgent != "" {
			request["user_agent"] = entry.Request.UserAgent
		}
		
		
		if len(entry.Request.Headers) > 0 {
			request["headers"] = entry.Request.Headers
		}
		
		
		if entry.Request.Body != "" {
			request["body"] = entry.Request.Body
		}
		
		data["request"] = request
	}

	if f.shouldInclude("response") {
		response := map[string]interface{}{
			"status": entry.Response.Status,
		}
		
		if len(entry.Response.Headers) > 0 {
			response["headers"] = entry.Response.Headers
		}
		
		if entry.Response.Size > 0 {
			response["size"] = entry.Response.Size
		}
		
		if entry.Response.Body != "" {
			response["body"] = entry.Response.Body
		}
		
		data["response"] = response
	}

	if f.shouldInclude("decision") {
		decision := map[string]interface{}{
			"action": entry.Decision.Action,
		}
		
		if entry.Decision.Rule != "" {
			decision["rule"] = entry.Decision.Rule
		}
		
		if entry.Decision.Reason != "" {
			decision["reason"] = entry.Decision.Reason
		}
		
		data["decision"] = decision
	}

	if f.shouldInclude("duration") && entry.Duration > 0 {
		data["duration_ms"] = entry.Duration.Milliseconds()
	}



	if f.PrettyPrint {
		return json.MarshalIndent(data, "", "  ")
	}
	
	return json.Marshal(data)
}

func (f *JSONFormatter) shouldInclude(field string) bool {
	if f.IncludeFields == nil {
		return true
	}
	include, exists := f.IncludeFields[field]
	return !exists || include
}

type TextFormatter struct {
	TimeFormat     string
	DisableColors  bool
	FullTimestamp  bool
	Template       string
}

func NewTextFormatter() *TextFormatter {
	return &TextFormatter{
		TimeFormat:    "15:04:05",
		FullTimestamp: false,
	}
}

func (f *TextFormatter) Format(entry *Entry) ([]byte, error) {
	if f.Template != "" {
		return f.formatWithTemplate(entry)
	}
	
	var b strings.Builder
	
	timestamp := entry.Timestamp.Format(f.TimeFormat)
	if f.FullTimestamp {
		timestamp = entry.Timestamp.Format(time.RFC3339)
	}
	
	b.WriteString(fmt.Sprintf("[%s]", timestamp))
	
	if entry.User.Email != "" {
		b.WriteString(fmt.Sprintf(" user=%s", entry.User.Email))
	}
	
	b.WriteString(fmt.Sprintf(" %s %s", entry.Request.Method, entry.Request.Path))
	
	if entry.Request.IP != "" {
		b.WriteString(fmt.Sprintf(" from=%s", entry.Request.IP))
	}
	
	b.WriteString(fmt.Sprintf(" status=%d", entry.Response.Status))
	
	if entry.Duration > 0 {
		b.WriteString(fmt.Sprintf(" duration=%dms", entry.Duration.Milliseconds()))
	}
	
	b.WriteString(fmt.Sprintf(" action=%s", entry.Decision.Action))
	
	if entry.Decision.Rule != "" {
		b.WriteString(fmt.Sprintf(" rule=%s", entry.Decision.Rule))
	}
	
	
	b.WriteString("\n")
	
	return []byte(b.String()), nil
}

func (f *TextFormatter) formatWithTemplate(entry *Entry) ([]byte, error) {
	template := f.Template
	
	replacements := map[string]string{
		"{timestamp}":    entry.Timestamp.Format(f.TimeFormat),
		"{user_id}":      entry.User.ID,
		"{user_email}":   entry.User.Email,
		"{user_name}":    entry.User.Name,
		"{method}":       entry.Request.Method,
		"{path}":         entry.Request.Path,
		"{ip}":           entry.Request.IP,
		"{user_agent}":   entry.Request.UserAgent,
		"{status}":       fmt.Sprintf("%d", entry.Response.Status),
		"{duration}":     fmt.Sprintf("%d", entry.Duration.Milliseconds()),
		"{action}":       entry.Decision.Action,
		"{rule}":         entry.Decision.Rule,
		"{reason}":       entry.Decision.Reason,
	}
	
	result := template
	for placeholder, value := range replacements {
		result = strings.ReplaceAll(result, placeholder, value)
	}
	
	return []byte(result + "\n"), nil
}

type CompactFormatter struct {
	TimeFormat string
}

func NewCompactFormatter() *CompactFormatter {
	return &CompactFormatter{
		TimeFormat: "15:04:05",
	}
}

func (f *CompactFormatter) Format(entry *Entry) ([]byte, error) {
	timestamp := entry.Timestamp.Format(f.TimeFormat)
	
	line := fmt.Sprintf("%s %s %s %s %d %s",
		timestamp,
		entry.Request.IP,
		entry.Request.Method,
		entry.Request.Path,
		entry.Response.Status,
		entry.Decision.Action,
	)
	
	if entry.Duration > 0 {
		line += fmt.Sprintf(" %dms", entry.Duration.Milliseconds())
	}
	
	
	return []byte(line + "\n"), nil
}

type CEFFormatter struct {
	DeviceVendor  string
	DeviceProduct string
	DeviceVersion string
}

func NewCEFFormatter() *CEFFormatter {
	return &CEFFormatter{
		DeviceVendor:  "Sekisho",
		DeviceProduct: "Zero-Trust Proxy",
		DeviceVersion: "1.0",
	}
}

func (f *CEFFormatter) Format(entry *Entry) ([]byte, error) {
	severity := f.getSeverity(entry)
	signatureID := f.getSignatureID(entry)
	name := f.getEventName(entry)
	
	header := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d",
		f.DeviceVendor,
		f.DeviceProduct,
		f.DeviceVersion,
		signatureID,
		name,
		severity,
	)
	
	extensions := []string{
		fmt.Sprintf("rt=%d", entry.Timestamp.UnixMilli()),
		fmt.Sprintf("src=%s", entry.Request.IP),
		fmt.Sprintf("requestMethod=%s", entry.Request.Method),
		fmt.Sprintf("request=%s", entry.Request.Path),
		fmt.Sprintf("cs1=%s", entry.Decision.Action),
		fmt.Sprintf("cs1Label=Decision"),
	}
	
	if entry.User.Email != "" {
		extensions = append(extensions, fmt.Sprintf("suser=%s", entry.User.Email))
	}
	
	if entry.Response.Status > 0 {
		extensions = append(extensions, fmt.Sprintf("cs2=%d", entry.Response.Status))
		extensions = append(extensions, "cs2Label=Status")
	}
	
	if entry.Duration > 0 {
		extensions = append(extensions, fmt.Sprintf("cs3=%d", entry.Duration.Milliseconds()))
		extensions = append(extensions, "cs3Label=Duration")
	}
	
	if entry.Decision.Rule != "" {
		extensions = append(extensions, fmt.Sprintf("cs4=%s", entry.Decision.Rule))
		extensions = append(extensions, "cs4Label=Rule")
	}
	
	
	result := header + "|" + strings.Join(extensions, " ")
	return []byte(result + "\n"), nil
}

func (f *CEFFormatter) getSeverity(entry *Entry) int {
	if entry.Decision.Action == "deny" {
		return 6
	}
	if entry.Response.Status >= 400 {
		return 4
	}
	return 2
}

func (f *CEFFormatter) getSignatureID(entry *Entry) string {
	if entry.Decision.Action == "deny" {
		return "access_denied"
	}
	return "access_granted"
}

func (f *CEFFormatter) getEventName(entry *Entry) string {
	if entry.Decision.Action == "deny" {
		return "Access Denied"
	}
	return "Access Granted"
}