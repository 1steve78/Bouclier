package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"bouclier/internal/config"
)

var secretPattern = regexp.MustCompile(`(?i)\b(bearer\s+|token[=:]\s*|api[_-]?key[=:]\s*|secret[=:]\s*|password[=:]\s*)([^\s,;&]+)`)

// RunConfigShow displays the active configuration in a safe, readable format.
// Secrets such as API keys, tokens, credentials, and passwords are fully redacted.
func RunConfigShow(cfg *config.Config, w io.Writer) error {
	if cfg == nil {
		cfg = config.Default()
	}

	data, err := redactConfig(cfg)
	if err != nil {
		return fmt.Errorf("marshal configuration: %w", err)
	}

	_, err = fmt.Fprintln(w, string(data))
	return err
}

func redactConfig(cfg *config.Config) ([]byte, error) {
	// Marshal the config into raw JSON without mutating the underlying cfg
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	sanitized := sanitizeNode(parsed)
	return json.MarshalIndent(sanitized, "", "  ")
}

func sanitizeNode(node any) any {
	switch v := node.(type) {
	case map[string]any:
		result := make(map[string]any, len(v))
		for k, val := range v {
			if isSecretKey(k) {
				if s, ok := val.(string); ok {
					if strings.TrimSpace(s) == "" {
						result[k] = ""
					} else {
						result[k] = "[REDACTED]"
					}
				} else if val == nil {
					result[k] = nil
				} else {
					result[k] = "[REDACTED]"
				}
			} else {
				result[k] = sanitizeNode(val)
			}
		}
		return result

	case []any:
		result := make([]any, len(v))
		for i, item := range v {
			result[i] = sanitizeNode(item)
		}
		return result

	case string:
		return sanitizeString(v)

	default:
		return v
	}
}

func isSecretKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
	secretTokens := []string{
		"apikey", "token", "secret", "password", "credential", "privatekey", "auth",
	}
	for _, token := range secretTokens {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}

func sanitizeString(s string) string {
	// If it's a URL, parse and sanitize userinfo and sensitive query parameters
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" {
			if u.User != nil {
				username := u.User.Username()
				if _, hasPass := u.User.Password(); hasPass {
					if username != "" {
						u.User = url.UserPassword("[REDACTED]", "[REDACTED]")
					} else {
						u.User = url.UserPassword("", "[REDACTED]")
					}
				} else if username != "" {
					u.User = url.User("[REDACTED]")
				}
			}
			q := u.Query()
			modified := false
			for param, values := range q {
				if isSecretKey(param) {
					modified = true
					for i := range values {
						if strings.TrimSpace(values[i]) != "" {
							values[i] = "[REDACTED]"
						}
					}
					q[param] = values
				}
			}
			if modified {
				u.RawQuery = q.Encode()
			}
			s = u.String()
		}
	}

	// Redact embedded secret keywords in non-URL strings or remaining patterns
	s = secretPattern.ReplaceAllString(s, "${1}[REDACTED]")
	return s
}
