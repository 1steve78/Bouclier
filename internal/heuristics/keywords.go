package heuristics

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

type phishingKeyword struct {
	value    string
	category string
}

// phishingKeywords are contextual URL terms, not proof of phishing.
var phishingKeywords = []phishingKeyword{
	{value: "login", category: "authentication"},
	{value: "signin", category: "authentication"},
	{value: "authentication", category: "authentication"},
	{value: "verify", category: "account-action"},
	{value: "account", category: "account-action"},
	{value: "secure", category: "security"},
	{value: "update", category: "account-action"},
	{value: "password", category: "credentials"},
	{value: "banking", category: "finance"},
	{value: "wallet", category: "finance"},
	{value: "confirm", category: "account-action"},
	{value: "recovery", category: "account-action"},
}

type keywordEvidence struct {
	keyword   string
	component string
}

func detectPhishingKeywords(u *NormalizedURL) (*Finding, error) {
	if u == nil {
		return nil, fmt.Errorf("detect phishing keywords: URL is nil")
	}
	if u.Hostname == "" {
		return nil, fmt.Errorf("detect phishing keywords: hostname is empty")
	}

	matched := make(map[string]map[string]struct{})
	for _, label := range strings.Split(strings.ToLower(u.Hostname), ".") {
		for _, token := range keywordTokens(label) {
			if isPhishingKeyword(token) {
				addKeywordMatch(matched, token, "hostname")
			}
		}
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "" {
			continue
		}
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return nil, fmt.Errorf("detect phishing keywords: invalid escaped path segment")
		}
		for _, token := range keywordTokens(decoded) {
			if isPhishingKeyword(token) {
				addKeywordMatch(matched, token, "path")
			}
		}
	}
	if len(matched) == 0 {
		return nil, nil
	}

	keywords := make([]string, 0, len(matched))
	for keyword := range matched {
		keywords = append(keywords, keyword)
	}
	sort.Strings(keywords)
	evidenceParts := make([]string, 0, len(keywords))
	for _, keyword := range keywords {
		components := make([]string, 0, len(matched[keyword]))
		for component := range matched[keyword] {
			components = append(components, component)
		}
		sort.Strings(components)
		evidenceParts = append(evidenceParts, keywordCategory(keyword)+": "+keyword+" ("+strings.Join(components, ", ")+")")
	}
	return finding(
		"PHISHING_KEYWORD",
		"Account-related keyword in URL",
		"The URL contains one or more account, authentication, security, or finance-related terms. These words also occur in legitimate links and are contextual signals only.",
		"phishing-language",
		"matched terms: "+strings.Join(evidenceParts, "; "),
	), nil
}

func keywordTokens(value string) []string {
	return strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func isPhishingKeyword(value string) bool {
	for _, keyword := range phishingKeywords {
		if value == keyword.value {
			return true
		}
	}
	return false
}

func keywordCategory(value string) string {
	for _, keyword := range phishingKeywords {
		if value == keyword.value {
			return keyword.category
		}
	}
	return "other"
}

func addKeywordMatch(matches map[string]map[string]struct{}, keyword, component string) {
	if matches[keyword] == nil {
		matches[keyword] = make(map[string]struct{})
	}
	matches[keyword][component] = struct{}{}
}
