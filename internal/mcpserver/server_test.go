package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"bouclier/internal/config"
	"bouclier/internal/storage"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestServerAdvertisesDocumentedTools(t *testing.T) {
	server, err := New(config.Default(), nil)
	if err != nil {
		t.Fatal(err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	result, err := clientSession.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]bool, len(result.Tools))
	for _, tool := range result.Tools {
		got[tool.Name] = true
	}
	for _, name := range []string{
		"check_url", "inspect_tls", "scan_headers", "lookup_threat_feeds",
		"analyze_message", "get_report", "verify_report",
	} {
		if !got[name] {
			t.Errorf("MCP server did not advertise %q", name)
		}
	}
}

func TestAnalyzeMessageDoesNotRetainMessageText(t *testing.T) {
	server := &Server{config: config.Default()}
	const text = "Please review this note without any links."
	raw, err := json.Marshal(map[string]string{"message": text})
	if err != nil {
		t.Fatal(err)
	}
	value, err := server.analyzeMessage(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	result := value.(messageToolResult)
	if err := result.Report.Validate(); err != nil {
		t.Fatalf("message report is invalid: %v", err)
	}
	if strings.Contains(result.Report.Target.MessageSHA256, text) || len(result.URLReports) != 0 {
		t.Fatalf("message contents leaked or unexpected URL reports returned: %+v", result)
	}
}

func TestNormalizePublicURLRejectsPrivateDestinations(t *testing.T) {
	for _, target := range []string{
		"http://127.0.0.1/",
		"http://10.0.0.1/",
		"http://localhost/",
	} {
		if _, err := normalizePublicURL(target); err == nil {
			t.Errorf("normalizePublicURL(%q) accepted a private destination", target)
		}
	}
	if _, err := normalizePublicURL("https://example.com/"); err != nil {
		t.Fatalf("normalizePublicURL rejected a public hostname: %v", err)
	}
}

func TestVerifyReportChecksStoredDigest(t *testing.T) {
	repo, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.SaveScan(context.Background(), storage.ScanRecord{ID: "mcp-report", Target: "https://example.com"}, nil); err != nil {
		t.Fatal(err)
	}

	server := &Server{repo: repo}
	raw, _ := json.Marshal(map[string]string{"id": "mcp-report"})
	value, err := server.verifyReport(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if !value.(verifyReportResult).Verified {
		t.Fatalf("freshly saved report did not verify: %+v", value)
	}

	db, err := repo.SQLDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE scan_reports SET report_json = ? WHERE scan_id = ?`, `{"tampered":true}`, "mcp-report"); err != nil {
		t.Fatal(err)
	}
	value, err = server.verifyReport(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if value.(verifyReportResult).Verified {
		t.Fatalf("tampered report unexpectedly verified: %+v", value)
	}
}
