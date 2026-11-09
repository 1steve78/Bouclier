package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"bouclier/internal/config"
	"bouclier/internal/risk"
	"bouclier/internal/storage"
)

func TestKeccakAndRLPEncoding(t *testing.T) {
	if got, want := hex.EncodeToString(keccak256(nil)), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"; got != want {
		t.Fatalf("keccak256(empty) = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(functionSelector("transfer(address,uint256)")), "a9059cbb"; got != want {
		t.Fatalf("transfer selector = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(rlpEncodeList(rlpEncodeBytes([]byte("cat")), rlpEncodeBytes([]byte("dog")))), "c88363617483646f67"; got != want {
		t.Fatalf("RLP list = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(rlpEncodeInteger(big.NewInt(0))), "80"; got != want {
		t.Fatalf("RLP zero = %s, want %s", got, want)
	}
}

func TestParseEVMPrivateKeyAndAddress(t *testing.T) {
	key, err := parseEVMPrivateKey(strings.Repeat("0", 63) + "1")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := evmAddress(key), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"; got != want {
		t.Fatalf("address = %s, want %s", got, want)
	}
	for _, invalid := range []string{"", "0", strings.Repeat("0", 64), strings.Repeat("f", 64), "not-hex"} {
		if _, err := parseEVMPrivateKey(invalid); err == nil {
			t.Errorf("parseEVMPrivateKey(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestDecodeRegistryVerification(t *testing.T) {
	raw := make([]byte, 128)
	raw[31] = 1
	raw[63] = 3
	copy(raw[76:96], bytes.Repeat([]byte{0xab}, 20))
	raw[127] = 9
	got, err := decodeRegistryVerification("0x" + hex.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Exists || got.RiskLevel != 3 || got.Reporter != "0x"+strings.Repeat("ab", 20) || got.Timestamp != 9 {
		t.Fatalf("unexpected decoded verification: %+v", got)
	}
	raw[0] = 2
	if _, err := decodeRegistryVerification(hex.EncodeToString(raw)); err == nil {
		t.Fatal("expected invalid bool word to fail")
	}
}

func TestRunHistoryAnchorAndVerifyWithJSONRPC(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "history.db")
	db, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	assessment := &risk.RiskAssessment{
		SchemaVersion: "bouclier-risk/v1",
		Target:        "https://private-target.example/",
		AnalyzedAt:    time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC),
		Findings: []risk.NormalizedFinding{{
			Code: "TEST", Title: "Local report content", Evidence: "must not be sent",
		}},
	}
	record := storage.ScanRecord{
		ID: "scan-anchor-test-0001", Target: assessment.Target, StartedAt: assessment.AnalyzedAt,
		CompletedAt: assessment.AnalyzedAt, Status: storage.StatusCompleted,
	}
	if err := db.SaveScan(ctx, record, assessment); err != nil {
		t.Fatal(err)
	}
	savedReport, err := db.GetScanReport(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	hashBytes, err := hex.DecodeString(strings.TrimPrefix(savedReport.ReportHash, "0x"))
	if err != nil || len(hashBytes) != sha256.Size {
		t.Fatalf("stored hash is invalid: %q, %v", savedReport.ReportHash, err)
	}
	var hash [32]byte
	copy(hash[:], hashBytes)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	t.Setenv("BOUCLIER_EVM_PRIVATE_KEY", strings.Repeat("0", 63)+"1")
	var verifyCalls atomic.Int32
	var sawSubmit atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read JSON-RPC request: %v", err)
			return
		}
		if strings.Contains(string(body), assessment.Target) ||
			strings.Contains(string(body), assessment.Findings[0].Evidence) ||
			strings.Contains(string(body), savedReport.ReportJSON) {
			t.Errorf("report content was sent to JSON-RPC endpoint: %s", body)
		}
		var request struct {
			JSONRPC string            `json:"jsonrpc"`
			Method  string            `json:"method"`
			Params  []json.RawMessage `json:"params"`
			ID      uint64            `json:"id"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			t.Errorf("decode JSON-RPC request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var result any
		switch request.Method {
		case "eth_call":
			verifyCalls.Add(1)
			result = encodedVerification(verifyCalls.Load() > 1, 1)
		case "eth_chainId":
			result = "0x539"
		case "eth_getTransactionCount":
			result = "0x0"
		case "eth_gasPrice":
			result = "0x1"
		case "eth_estimateGas":
			var call map[string]string
			if err := json.Unmarshal(request.Params[0], &call); err != nil {
				t.Errorf("decode estimate call: %v", err)
			}
			if !strings.HasSuffix(call["data"], hex.EncodeToString(hash[:])+strings.Repeat("0", 63)+"1") {
				t.Errorf("submission calldata does not contain only expected hash and risk: %s", call["data"])
			}
			result = "0x5208"
		case "eth_sendRawTransaction":
			var rawTx string
			if err := json.Unmarshal(request.Params[0], &rawTx); err != nil {
				t.Errorf("decode raw transaction: %v", err)
			}
			tx, err := hex.DecodeString(strings.TrimPrefix(rawTx, "0x"))
			if err != nil || len(tx) == 0 {
				t.Errorf("invalid signed transaction: %v", err)
			}
			sawSubmit.Store(true)
			result = "0x" + hex.EncodeToString(keccak256(tx))
		case "eth_getTransactionReceipt":
			result = map[string]string{"status": "0x1"}
		default:
			t.Errorf("unexpected JSON-RPC method: %s", request.Method)
			result = nil
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": request.ID, "result": result,
		}); err != nil {
			t.Errorf("encode JSON-RPC response: %v", err)
		}
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	cfg := config.Default()
	cfg.Storage.DatabasePath = databasePath
	var anchorOutput bytes.Buffer
	if err := RunHistoryAnchor(ctx, cfg, ReportAnchorOptions{
		ScanID: record.ID, RPCURL: server.URL, ContractAddress: "0x1111111111111111111111111111111111111111",
		RiskLevel: 1,
	}, &anchorOutput); err != nil {
		t.Fatalf("anchor report: %v", err)
	}
	if !sawSubmit.Load() {
		t.Fatal("anchor did not submit a signed transaction")
	}
	if strings.Contains(anchorOutput.String(), assessment.Target) {
		t.Fatal("anchor output unexpectedly includes the scanned target")
	}
	var submitted registrySubmission
	if err := json.Unmarshal(anchorOutput.Bytes(), &submitted); err != nil {
		t.Fatalf("decode anchor response: %v", err)
	}
	if submitted.ReportHash != savedReport.ReportHash || submitted.TransactionHash == "" ||
		submitted.ChainID != "1337" || !submitted.Verification.Exists {
		t.Fatalf("unexpected anchor result: %+v", submitted)
	}

	db, err = storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	localAnchor, err := db.GetReportAnchor(ctx, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if localAnchor.TransactionHash != submitted.TransactionHash || localAnchor.RiskLevel != 1 {
		t.Fatalf("unexpected locally saved anchor: %+v", localAnchor)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	var verifyOutput bytes.Buffer
	if err := RunHistoryVerifyAnchor(ctx, cfg, ReportVerifyOptions{
		ScanID: record.ID, RPCURL: server.URL, ContractAddress: "0x1111111111111111111111111111111111111111",
	}, &verifyOutput); err != nil {
		t.Fatalf("verify report: %v", err)
	}
	var verified map[string]any
	if err := json.Unmarshal(verifyOutput.Bytes(), &verified); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	if verified["local_anchor_matches_registry"] != true {
		t.Fatalf("local anchor was not confirmed by registry: %s", verifyOutput.String())
	}
	if verifyCalls.Load() != 3 {
		t.Fatalf("verify() called %d times, want 3", verifyCalls.Load())
	}
}

func encodedVerification(exists bool, riskLevel uint8) string {
	raw := make([]byte, 128)
	if exists {
		raw[31] = 1
	}
	raw[63] = riskLevel
	raw[127] = 42
	return "0x" + hex.EncodeToString(raw)
}

func TestNewRegistryClientRejectsMalformedInputs(t *testing.T) {
	if _, _, err := newRegistryClient("file:///tmp/rpc", "0x1111111111111111111111111111111111111111"); err == nil {
		t.Fatal("non-HTTP RPC URL was accepted")
	}
	if _, _, err := newRegistryClient("https://rpc.example", "0x0"); err == nil {
		t.Fatal("malformed contract address was accepted")
	}
	if _, _, err := newRegistryClient("https://user:pass@rpc.example", "0x1111111111111111111111111111111111111111"); err == nil {
		t.Fatal("RPC URL containing embedded credentials was accepted")
	}
}

func TestValidatedReportHashRejectsTampering(t *testing.T) {
	hash := sha256.Sum256([]byte("original"))
	_, err := validatedReportHash(&storage.ScanReport{
		ReportJSON: "modified", ReportHash: "0x" + hex.EncodeToString(hash[:]),
	})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tampered report validation error = %v", err)
	}
}

func TestSignLegacyTransactionProducesEIP155Transaction(t *testing.T) {
	key, err := parseEVMPrivateKey(strings.Repeat("0", 63) + "1")
	if err != nil {
		t.Fatal(err)
	}
	var reportHash [32]byte
	reportHash[0] = 1
	tx, err := signLegacyTransaction(key, big.NewInt(1), 0, big.NewInt(1), big.NewInt(21000),
		"0x1111111111111111111111111111111111111111", encodeSubmitCall(reportHash, 1))
	if err != nil {
		t.Fatal(err)
	}
	if len(tx) < 100 || tx[0] < 0xc0 {
		t.Fatalf("unexpected signed legacy transaction encoding: %x", tx)
	}
}

func TestParseHexIntegerRejectsInvalid(t *testing.T) {
	for _, value := range []string{"", "0x", "xyz"} {
		if _, err := parseHexInteger(value); err == nil {
			t.Errorf("parseHexInteger(%q) unexpectedly succeeded", value)
		}
	}
	if got, err := parseHexInteger("0x539"); err != nil || got.Cmp(big.NewInt(1337)) != 0 {
		t.Fatalf("parseHexInteger(0x539) = %v, %v", got, err)
	}
}

func TestWriteRegistryJSONReportsWriterErrors(t *testing.T) {
	err := writeRegistryJSON(failingWriter{}, registrySubmission{})
	if err == nil || !strings.Contains(err.Error(), "write report registry result") {
		t.Fatalf("writeRegistryJSON error = %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("intentional writer failure")
}
