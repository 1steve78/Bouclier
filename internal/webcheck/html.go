package webcheck

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"bouclier/internal/heuristics"
	"golang.org/x/net/html"
)

// AnalyzeHTML parses only a body identified as HTML. It never fetches referenced resources.
func AnalyzeHTML(result *HTTPInspectionResult) ([]heuristics.Finding, error) {
	if result == nil {
		return nil, fmt.Errorf("analyze HTML: result is nil")
	}
	if !result.IsHTML {
		return nil, nil
	}
	base, err := url.Parse(result.FinalURL)
	if err != nil || base.Hostname() == "" {
		return nil, fmt.Errorf("analyze HTML: final URL is invalid")
	}
	document, err := html.Parse(strings.NewReader(string(result.HTML)))
	if err != nil {
		return nil, fmt.Errorf("analyze HTML: parse document: %w", err)
	}
	base = htmlBase(document, base)
	var findings []heuristics.Finding
	if result.BodyTruncated {
		findings = append(findings, finding("WEB_HTML_INCOMPLETE", "HTML document was truncated", "HTML signals were parsed from a bounded partial response and may be incomplete.", "web-html", "response body exceeded configured read limit"))
	}
	if !result.FinalHTTPS && !result.UsedHTTPS {
		// Mixed content is only meaningful when the document itself is HTTPS.
	}
	if result.FinalHTTPS {
		resourceOrigins := make(map[string]struct{})
		walkHTML(document, func(node *html.Node) {
			if node.Type == html.ElementNode {
				switch strings.ToLower(node.Data) {
				case "script":
					htmlResource(node, "src", "script", base, resourceOrigins, &findings)
				case "iframe":
					htmlResource(node, "src", "iframe", base, resourceOrigins, &findings)
				case "link":
					if hasRel(node, "stylesheet") {
						htmlResource(node, "href", "stylesheet", base, resourceOrigins, &findings)
					}
				case "object":
					htmlResource(node, "data", "object", base, resourceOrigins, &findings)
				case "embed":
					htmlResource(node, "src", "embed", base, resourceOrigins, &findings)
				case "a", "area":
					htmlLink(node, base, resourceOrigins, &findings)
				}
				if node.Data == "form" {
					inspectForm(node, base, resourceOrigins, &findings)
				}
			}
		})
		result.ExternalResourceOrigins = result.ExternalResourceOrigins[:0]
		for origin := range resourceOrigins {
			result.ExternalResourceOrigins = append(result.ExternalResourceOrigins, origin)
		}
		sort.Strings(result.ExternalResourceOrigins)
	}
	walkHTML(document, func(node *html.Node) {
		if node.Type != html.ElementNode || node.Data != "meta" {
			return
		}
		name := strings.ToLower(attr(node, "http-equiv"))
		if name == "content-security-policy" {
			findings = append(findings, finding("WEB_HTML_META_CSP_PRESENT", "CSP meta element is present", "A meta-delivered CSP is not equivalent to an HTTP response header policy and has browser processing limitations.", "web-html", "content-security-policy is declared in HTML metadata"))
		}
		if name == "referrer" || strings.EqualFold(attr(node, "name"), "referrer") {
			findings = append(findings, finding("WEB_HTML_META_REFERRER_POLICY", "Referrer policy is declared in HTML metadata", "The document contains a referrer policy meta element; the response header remains separately assessed.", "web-html", "referrer policy is declared in HTML metadata"))
		}
	})
	return sortedFindings(findings), nil
}

func htmlResource(node *html.Node, attribute, kind string, base *url.URL, origins map[string]struct{}, findings *[]heuristics.Finding) {
	value := strings.TrimSpace(attr(node, attribute))
	if value == "" {
		return
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "data" || parsed.Scheme == "javascript" {
		return
	}
	resolved := base.ResolveReference(parsed)
	if !strings.EqualFold(resolved.Scheme, "http") && !strings.EqualFold(resolved.Scheme, "https") {
		return
	}
	if resolved.Hostname() != "" {
		port := resolved.Port()
		if port == "" {
			if resolved.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		resolvedOrigin := strings.ToLower(resolved.Scheme) + "://" + strings.ToLower(resolved.Hostname()) + ":" + port
		if resolvedOrigin != origin(base) {
			origins[resolvedOrigin] = struct{}{}
		}
	}
	if strings.EqualFold(resolved.Scheme, "http") {
		*findings = append(*findings, finding("WEB_HTML_MIXED_CONTENT_"+strings.ToUpper(kind), "HTTPS document references an HTTP resource", "The browser may retrieve this security-relevant resource without transport encryption.", "web-html-mixed-content", "HTTP "+kind+" resource reference"))
	}
}

func htmlLink(node *html.Node, base *url.URL, origins map[string]struct{}, findings *[]heuristics.Finding) {
	value := strings.TrimSpace(attr(node, "href"))
	parsed, err := url.Parse(value)
	if err != nil || value == "" {
		return
	}
	resolved := base.ResolveReference(parsed)
	if resolved.Hostname() != "" {
		port := resolved.Port()
		if port == "" {
			if resolved.Scheme == "https" {
				port = "443"
			} else if resolved.Scheme == "http" {
				port = "80"
			}
		}
		if port != "" {
			resolvedOrigin := strings.ToLower(resolved.Scheme) + "://" + strings.ToLower(resolved.Hostname()) + ":" + port
			if resolvedOrigin != origin(base) {
				origins[resolvedOrigin] = struct{}{}
			}
		}
	}
	if strings.EqualFold(resolved.Scheme, "http") {
		*findings = append(*findings, finding("WEB_HTML_HTTP_LINK", "HTTPS document links to an HTTP destination", "The destination would be visited without transport encryption; the link is not fetched by this assessment.", "web-html-link", "HTTP navigation link reference"))
	}
}

func inspectForm(form *html.Node, base *url.URL, origins map[string]struct{}, findings *[]heuristics.Finding) {
	action := strings.TrimSpace(attr(form, "action"))
	if action == "" {
		action = base.String()
	}
	parsed, err := url.Parse(action)
	if err != nil {
		return
	}
	resolved := base.ResolveReference(parsed)
	if resolved.Hostname() != "" {
		port := resolved.Port()
		if port == "" {
			if resolved.Scheme == "https" {
				port = "443"
			} else if resolved.Scheme == "http" {
				port = "80"
			}
		}
		if port != "" {
			resolvedOrigin := strings.ToLower(resolved.Scheme) + "://" + strings.ToLower(resolved.Hostname()) + ":" + port
			if resolvedOrigin != origin(base) {
				origins[resolvedOrigin] = struct{}{}
			}
		}
	}
	if !strings.EqualFold(resolved.Scheme, "http") {
		return
	}
	if containsPasswordInput(form) {
		*findings = append(*findings, finding("WEB_HTML_INSECURE_PASSWORD_FORM", "Password form submits over HTTP", "An HTTPS document contains a password field whose form action uses unencrypted HTTP.", "web-html-form", "password form action uses HTTP"))
	} else {
		*findings = append(*findings, finding("WEB_HTML_INSECURE_FORM", "Form submits over HTTP", "An HTTPS document contains a form whose action uses unencrypted HTTP.", "web-html-form", "form action uses HTTP"))
	}
}

func htmlBase(document *html.Node, documentURL *url.URL) *url.URL {
	var candidate *url.URL
	walkHTML(document, func(node *html.Node) {
		if candidate != nil || node.Type != html.ElementNode || node.Data != "base" {
			return
		}
		value := strings.TrimSpace(attr(node, "href"))
		if value == "" {
			return
		}
		parsed, err := url.Parse(value)
		if err != nil {
			return
		}
		resolved := documentURL.ResolveReference(parsed)
		if resolved.Scheme == "http" || resolved.Scheme == "https" {
			candidate = resolved
		}
	})
	if candidate != nil {
		return candidate
	}
	return documentURL
}

func containsPasswordInput(node *html.Node) bool {
	found := false
	walkHTML(node, func(child *html.Node) {
		if child.Type == html.ElementNode && child.Data == "input" && strings.EqualFold(attr(child, "type"), "password") {
			found = true
		}
	})
	return found
}

func hasRel(node *html.Node, expected string) bool {
	for _, value := range strings.Fields(strings.ToLower(attr(node, "rel"))) {
		if value == expected {
			return true
		}
	}
	return false
}

func attr(node *html.Node, name string) string {
	for _, attribute := range node.Attr {
		if strings.EqualFold(attribute.Key, name) {
			return attribute.Val
		}
	}
	return ""
}

func walkHTML(node *html.Node, visit func(*html.Node)) {
	if node == nil {
		return
	}
	visit(node)
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		walkHTML(child, visit)
	}
}
