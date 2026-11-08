// Package report renders completed risk assessments without changing their score.
package report

import (
	"regexp"
	"strings"
)

var (
	reportURL    = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)
	reportSecret = regexp.MustCompile(`(?i)\b(session(?:id)?|sid|auth(?:orization)?|jwt|token|password|secret|api[_-]?key|access[_-]?key)\s*[:=]\s*([^&;\s,]+)`)
	reportBearer = regexp.MustCompile(`(?i)(authorization\s*:\s*)[^\r\n]+`)
	reportCookie = regexp.MustCompile(`(?i)((?:set-)?cookie\s*:\s*)[^\r\n]+`)
	reportQuery  = regexp.MustCompile(`([?&][^=&#\s]+)=([^&#\s]*)`)
)

func redact(value string) string {
	value = reportBearer.ReplaceAllString(value, "$1[redacted]")
	value = reportCookie.ReplaceAllString(value, "$1=[redacted]")
	value = reportURL.ReplaceAllStringFunc(value, func(raw string) string {
		end := strings.IndexAny(raw, "?#")
		if end >= 0 {
			raw = raw[:end]
		}
		if at := strings.LastIndex(raw, "@"); at >= 0 {
			if scheme := strings.Index(raw, "://"); scheme >= 0 && at > scheme+2 {
				raw = raw[:scheme+3] + raw[at+1:]
			}
		}
		return raw
	})
	value = reportQuery.ReplaceAllString(value, "$1=[redacted]")
	value = reportSecret.ReplaceAllString(value, "$1=[redacted]")
	return value
}

func markdownEscape(value string) string {
	value = redact(value)
	replacer := strings.NewReplacer(
		"&", "&amp;", "\\", "\\\\", "\r", " ", "\n", " ", "|", "\\|", "`", "\\`",
		"<", "&lt;", ">", "&gt;", "*", "\\*", "_", "\\_",
		"[", "\\[", "]", "\\]", "#", "\\#", "!", "\\!",
	)
	return replacer.Replace(value)
}
