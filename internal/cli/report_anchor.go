package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"bouclier/internal/config"
	"bouclier/internal/storage"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

const (
	submitReportSignature = "submitReport(bytes32,uint8)"
	verifyReportSignature = "verify(bytes32)"
	maxRPCResponseBytes   = 1 << 20
)

var rpcRequestID atomic.Uint64

type ReportAnchorOptions struct {
	ScanID          string
	RPCURL          string
	ContractAddress string
	PrivateKeyEnv   string
	RiskLevel       int
}

type ReportVerifyOptions struct {
	ScanID          string
	RPCURL          string
	ContractAddress string
}

type registryVerification struct {
	Exists    bool   `json:"exists"`
	RiskLevel uint8  `json:"risk_level"`
	Reporter  string `json:"reporter"`
	Timestamp uint64 `json:"timestamp"`
}

type registrySubmission struct {
	ScanID          string               `json:"scan_id"`
	ChainID         string               `json:"chain_id"`
	ContractAddress string               `json:"contract_address"`
	ReportHash      string               `json:"report_hash"`
	RiskLevel       int                  `json:"risk_level"`
	TransactionHash string               `json:"transaction_hash,omitempty"`
	Verification    registryVerification `json:"verification"`
}

type evmRPC struct {
	url    string
	client *http.Client
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
	ID      uint64 `json:"id"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func RunHistoryAnchor(ctx context.Context, cfg *config.Config, opts ReportAnchorOptions, out io.Writer) error {
	if opts.RiskLevel < 1 || opts.RiskLevel > 3 {
		return NewExitError(ExitInvalidUsage, "risk level must be 1 (suspicious), 2 (high risk), or 3 (confirmed malicious); select it based on human review")
	}
	rpc, contract, err := newRegistryClient(opts.RPCURL, opts.ContractAddress)
	if err != nil {
		return NewExitError(ExitInvalidUsage, "%v", err)
	}
	if cfg == nil {
		cfg = config.Default()
	}
	db, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open scan history database: %w", err)
	}
	defer db.Close()

	scanReport, err := db.GetScanReport(ctx, opts.ScanID)
	if err != nil {
		return NewExitError(ExitGeneralError, "load report %q: %w", opts.ScanID, err)
	}
	hash, err := validatedReportHash(scanReport)
	if err != nil {
		return NewExitError(ExitGeneralError, "validate stored report %q: %w", scanReport.ScanID, err)
	}
	verification, err := verifyOnRegistry(ctx, rpc, contract, hash)
	if err != nil {
		return NewExitError(ExitGeneralError, "check report registry: %w", err)
	}
	if verification.Exists {
		return NewExitError(ExitGeneralError, "report hash is already registered with risk level %d by %s; use `history verify` to inspect it", verification.RiskLevel, verification.Reporter)
	}

	envName := strings.TrimSpace(opts.PrivateKeyEnv)
	if envName == "" {
		envName = "BOUCLIER_EVM_PRIVATE_KEY"
	}
	keyText, ok := os.LookupEnv(envName)
	if !ok || strings.TrimSpace(keyText) == "" {
		return NewExitError(ExitInvalidUsage, "set the signing key in environment variable %s; keys are never accepted as command-line arguments", envName)
	}
	privateKey, err := parseEVMPrivateKey(keyText)
	if err != nil {
		return NewExitError(ExitInvalidUsage, "invalid EVM private key in %s: %v", envName, err)
	}
	from := evmAddress(privateKey)

	chainIDRaw, err := rpc.callString(ctx, "eth_chainId", []any{})
	if err != nil {
		return NewExitError(ExitGeneralError, "read EVM chain ID: %w", err)
	}
	chainID, err := parseHexInteger(chainIDRaw)
	if err != nil || chainID.Sign() <= 0 {
		return NewExitError(ExitGeneralError, "invalid EVM chain ID returned by RPC")
	}
	nonceRaw, err := rpc.callString(ctx, "eth_getTransactionCount", []any{from, "pending"})
	if err != nil {
		return NewExitError(ExitGeneralError, "read account transaction count: %w", err)
	}
	nonce, err := parseHexInteger(nonceRaw)
	if err != nil || !nonce.IsUint64() {
		return NewExitError(ExitGeneralError, "invalid transaction count returned by RPC")
	}
	gasPriceRaw, err := rpc.callString(ctx, "eth_gasPrice", []any{})
	if err != nil {
		return NewExitError(ExitGeneralError, "read EVM gas price: %w", err)
	}
	gasPrice, err := parseHexInteger(gasPriceRaw)
	if err != nil || gasPrice.Sign() <= 0 {
		return NewExitError(ExitGeneralError, "invalid gas price returned by RPC")
	}
	callData := encodeSubmitCall(hash, uint8(opts.RiskLevel))
	gasRaw, err := rpc.callString(ctx, "eth_estimateGas", []any{map[string]string{
		"from": from, "to": contract, "value": "0x0", "data": callData,
	}})
	if err != nil {
		return NewExitError(ExitGeneralError, "estimate report submission gas: %w", err)
	}
	gasLimit, err := parseHexInteger(gasRaw)
	if err != nil || gasLimit.Sign() <= 0 {
		return NewExitError(ExitGeneralError, "invalid gas estimate returned by RPC")
	}
	gasLimit.Mul(gasLimit, big.NewInt(120))
	gasLimit.Div(gasLimit, big.NewInt(100))

	rawTransaction, err := signLegacyTransaction(privateKey, chainID, nonce.Uint64(), gasPrice, gasLimit, contract, callData)
	if err != nil {
		return NewExitError(ExitGeneralError, "sign EVM transaction: %w", err)
	}
	txHash := keccak256(rawTransaction)
	txHashHex := "0x" + hex.EncodeToString(txHash)
	submittedHash, err := rpc.callString(ctx, "eth_sendRawTransaction", []any{"0x" + hex.EncodeToString(rawTransaction)})
	if err != nil {
		return NewExitError(ExitGeneralError, "submit report hash to EVM registry: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(submittedHash), txHashHex) {
		return NewExitError(ExitGeneralError, "RPC returned transaction hash %q, expected locally computed hash %q", submittedHash, txHashHex)
	}
	if err := waitForTransaction(ctx, rpc, txHashHex); err != nil {
		return NewExitError(ExitGeneralError, "wait for report anchor transaction: %w", err)
	}
	verification, err = verifyOnRegistry(ctx, rpc, contract, hash)
	if err != nil {
		return NewExitError(ExitGeneralError, "confirm report registry transaction: %w", err)
	}
	if !verification.Exists || int(verification.RiskLevel) != opts.RiskLevel {
		return NewExitError(ExitGeneralError, "transaction was mined but registry verification did not match the submitted risk level")
	}
	chainIDString := chainID.String()
	response := registrySubmission{
		ScanID: scanReport.ScanID, ChainID: chainIDString, ContractAddress: contract,
		ReportHash: "0x" + hex.EncodeToString(hash[:]), RiskLevel: opts.RiskLevel,
		TransactionHash: txHashHex, Verification: verification,
	}
	if err := db.SaveReportAnchor(ctx, storage.ReportAnchor{
		ScanID: scanReport.ScanID, ChainID: chainIDString, ContractAddress: contract,
		TransactionHash: txHashHex, ReportHash: response.ReportHash, RiskLevel: opts.RiskLevel,
		AnchoredAt: time.Now().UTC(),
	}); err != nil {
		return NewExitError(ExitGeneralError, "save local report anchor metadata: %w", err)
	}
	return writeRegistryJSON(out, response)
}

func RunHistoryVerifyAnchor(ctx context.Context, cfg *config.Config, opts ReportVerifyOptions, out io.Writer) error {
	rpc, contract, err := newRegistryClient(opts.RPCURL, opts.ContractAddress)
	if err != nil {
		return NewExitError(ExitInvalidUsage, "%v", err)
	}
	if cfg == nil {
		cfg = config.Default()
	}
	db, err := storage.Open(cfg.Storage.DatabasePath)
	if err != nil {
		return NewExitError(ExitGeneralError, "open scan history database: %w", err)
	}
	defer db.Close()
	scanReport, err := db.GetScanReport(ctx, opts.ScanID)
	if err != nil {
		return NewExitError(ExitGeneralError, "load report %q: %w", opts.ScanID, err)
	}
	hash, err := validatedReportHash(scanReport)
	if err != nil {
		return NewExitError(ExitGeneralError, "validate stored report %q: %w", scanReport.ScanID, err)
	}
	verification, err := verifyOnRegistry(ctx, rpc, contract, hash)
	if err != nil {
		return NewExitError(ExitGeneralError, "verify report on EVM registry: %w", err)
	}
	chainIDRaw, err := rpc.callString(ctx, "eth_chainId", []any{})
	if err != nil {
		return NewExitError(ExitGeneralError, "read EVM chain ID: %w", err)
	}
	chainID, err := parseHexBig(chainIDRaw)
	if err != nil {
		return NewExitError(ExitGeneralError, "decode EVM chain ID: %w", err)
	}
	response := map[string]any{
		"scan_id": scanReport.ScanID, "chain_id": chainID, "contract_address": contract,
		"report_hash": "0x" + hex.EncodeToString(hash[:]), "verification": verification,
	}
	local, localErr := db.GetReportAnchor(ctx, scanReport.ScanID)
	if localErr == nil {
		response["local_transaction_hash"] = local.TransactionHash
		response["local_anchor_matches_registry"] = local.ChainID == chainID && strings.EqualFold(local.ContractAddress, contract) &&
			strings.EqualFold(local.ReportHash, "0x"+hex.EncodeToString(hash[:])) &&
			verification.Exists && int(verification.RiskLevel) == local.RiskLevel
	} else if !errors.Is(localErr, storage.ErrNotFound) {
		return NewExitError(ExitGeneralError, "load local report anchor metadata: %w", localErr)
	}
	return writeRegistryJSON(out, response)
}

func newRegistryClient(endpoint, address string) (*evmRPC, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") ||
		parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, "", errors.New("RPC URL must be a valid http or https URL without embedded credentials or fragments")
	}
	contract, err := normalizeEVMAddress(address)
	if err != nil {
		return nil, "", fmt.Errorf("invalid registry contract address: %w", err)
	}
	return &evmRPC{url: parsed.String(), client: &http.Client{Timeout: 20 * time.Second}}, contract, nil
}

func (rpc *evmRPC) callString(ctx context.Context, method string, params any) (string, error) {
	result, err := rpc.callRaw(ctx, method, params)
	if err != nil {
		return "", err
	}
	var decoded string
	if err := json.Unmarshal(result, &decoded); err != nil {
		return "", fmt.Errorf("decode JSON-RPC %s result: %w", method, err)
	}
	return decoded, nil
}

func (rpc *evmRPC) callRaw(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := rpcRequestID.Add(1)
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", Method: method, Params: params, ID: id})
	if err != nil {
		return nil, fmt.Errorf("encode JSON-RPC request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, rpc.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create JSON-RPC request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := rpc.client.Do(request)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return nil, fmt.Errorf("send JSON-RPC %s request: %w", method, urlErr.Err)
		}
		return nil, fmt.Errorf("send JSON-RPC %s request failed", method)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("JSON-RPC %s returned HTTP status %s", method, response.Status)
	}
	body, err = io.ReadAll(io.LimitReader(response.Body, maxRPCResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read JSON-RPC %s response: %w", method, err)
	}
	if len(body) > maxRPCResponseBytes {
		return nil, fmt.Errorf("JSON-RPC %s response exceeds %d bytes", method, maxRPCResponseBytes)
	}
	var decoded rpcResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("decode JSON-RPC %s response: %w", method, err)
	}
	if decoded.ID != id || decoded.JSONRPC != "2.0" {
		return nil, fmt.Errorf("JSON-RPC %s returned a mismatched response ID or version", method)
	}
	if decoded.Error != nil {
		return nil, fmt.Errorf("JSON-RPC %s error %d: %s", method, decoded.Error.Code, decoded.Error.Message)
	}
	if len(decoded.Result) == 0 {
		return nil, fmt.Errorf("JSON-RPC %s returned no result", method)
	}
	return decoded.Result, nil
}

func validatedReportHash(scanReport *storage.ScanReport) ([32]byte, error) {
	var hash [32]byte
	if scanReport == nil {
		return hash, errors.New("stored report is empty")
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(scanReport.ReportHash, "0x"))
	if err != nil || len(expected) != sha256.Size {
		return hash, errors.New("stored report hash has invalid format")
	}
	actual := sha256.Sum256([]byte(scanReport.ReportJSON))
	if !bytes.Equal(expected, actual[:]) {
		return hash, errors.New("stored report content does not match its SHA-256 digest")
	}
	copy(hash[:], expected)
	return hash, nil
}

func verifyOnRegistry(ctx context.Context, rpc *evmRPC, contract string, hash [32]byte) (registryVerification, error) {
	result, err := rpc.callString(ctx, "eth_call", []any{
		map[string]string{"to": contract, "data": encodeVerifyCall(hash)}, "latest",
	})
	if err != nil {
		return registryVerification{}, err
	}
	return decodeRegistryVerification(result)
}

func decodeRegistryVerification(encoded string) (registryVerification, error) {
	var verification registryVerification
	raw, err := hex.DecodeString(strings.TrimPrefix(encoded, "0x"))
	if err != nil || len(raw) != 128 {
		return verification, errors.New("verify() returned an invalid ABI payload")
	}
	exists := new(big.Int).SetBytes(raw[:32])
	risk := new(big.Int).SetBytes(raw[32:64])
	timestamp := new(big.Int).SetBytes(raw[96:128])
	if exists.Cmp(big.NewInt(1)) > 0 || !risk.IsUint64() || risk.Uint64() > 255 || !timestamp.IsUint64() {
		return verification, errors.New("verify() returned values outside the expected ABI types")
	}
	for _, padding := range raw[64:76] {
		if padding != 0 {
			return verification, errors.New("verify() returned a non-canonical address word")
		}
	}
	verification.Exists = exists.Sign() == 1
	verification.RiskLevel = uint8(risk.Uint64())
	verification.Reporter = "0x" + hex.EncodeToString(raw[76:96])
	verification.Timestamp = timestamp.Uint64()
	return verification, nil
}

func encodeSubmitCall(hash [32]byte, riskLevel uint8) string {
	data := append(functionSelector(submitReportSignature), hash[:]...)
	word := make([]byte, 32)
	word[31] = riskLevel
	data = append(data, word...)
	return "0x" + hex.EncodeToString(data)
}

func encodeVerifyCall(hash [32]byte) string {
	data := append(functionSelector(verifyReportSignature), hash[:]...)
	return "0x" + hex.EncodeToString(data)
}

func functionSelector(signature string) []byte {
	hash := keccak256([]byte(signature))
	return hash[:4]
}

func normalizeEVMAddress(address string) (string, error) {
	address = strings.TrimPrefix(strings.TrimSpace(address), "0x")
	decoded, err := hex.DecodeString(address)
	if err != nil || len(decoded) != 20 {
		return "", errors.New("expected a 20-byte hexadecimal address")
	}
	if new(big.Int).SetBytes(decoded).Sign() == 0 {
		return "", errors.New("zero address is not a valid registry address")
	}
	return "0x" + strings.ToLower(address), nil
}

func parseEVMPrivateKey(key string) (*secp256k1.PrivateKey, error) {
	key = strings.TrimPrefix(strings.TrimSpace(key), "0x")
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("expected exactly 32 hexadecimal bytes")
	}
	var scalar secp256k1.ModNScalar
	if scalar.SetByteSlice(raw) || scalar.IsZero() {
		return nil, errors.New("key scalar is outside the valid secp256k1 range")
	}
	return secp256k1.PrivKeyFromBytes(raw), nil
}

func evmAddress(privateKey *secp256k1.PrivateKey) string {
	publicKey := privateKey.PubKey().SerializeUncompressed()
	hash := keccak256(publicKey[1:])
	return "0x" + hex.EncodeToString(hash[12:])
}

func signLegacyTransaction(key *secp256k1.PrivateKey, chainID *big.Int, nonce uint64, gasPrice, gasLimit *big.Int, to, data string) ([]byte, error) {
	addressBytes, err := hex.DecodeString(strings.TrimPrefix(to, "0x"))
	if err != nil || len(addressBytes) != 20 {
		return nil, errors.New("invalid transaction recipient")
	}
	calldata, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
	if err != nil {
		return nil, errors.New("invalid transaction calldata")
	}
	unsigned := rlpEncodeList(
		rlpEncodeInteger(new(big.Int).SetUint64(nonce)),
		rlpEncodeInteger(gasPrice),
		rlpEncodeInteger(gasLimit),
		rlpEncodeBytes(addressBytes),
		rlpEncodeBytes(nil),
		rlpEncodeBytes(calldata),
		rlpEncodeInteger(chainID),
		rlpEncodeBytes(nil),
		rlpEncodeBytes(nil),
	)
	digest := keccak256(unsigned)
	signature := secpECDSA.SignCompact(key, digest, true)
	recoveryID := signature[0] - 31
	if recoveryID > 1 {
		return nil, errors.New("signer returned unsupported ECDSA recovery ID")
	}
	v := new(big.Int).Mul(chainID, big.NewInt(2))
	v.Add(v, big.NewInt(int64(35+recoveryID)))
	return rlpEncodeList(
		rlpEncodeInteger(new(big.Int).SetUint64(nonce)),
		rlpEncodeInteger(gasPrice),
		rlpEncodeInteger(gasLimit),
		rlpEncodeBytes(addressBytes),
		rlpEncodeBytes(nil),
		rlpEncodeBytes(calldata),
		rlpEncodeInteger(v),
		rlpEncodeInteger(new(big.Int).SetBytes(signature[1:33])),
		rlpEncodeInteger(new(big.Int).SetBytes(signature[33:65])),
	), nil
}

func rlpEncodeInteger(value *big.Int) []byte {
	if value == nil || value.Sign() == 0 {
		return rlpEncodeBytes(nil)
	}
	return rlpEncodeBytes(value.Bytes())
}

func rlpEncodeBytes(value []byte) []byte {
	if len(value) == 1 && value[0] < 0x80 {
		return append([]byte(nil), value...)
	}
	if len(value) < 56 {
		return append([]byte{byte(0x80 + len(value))}, value...)
	}
	length := lengthBytes(len(value))
	encoded := []byte{byte(0xb7 + len(length))}
	encoded = append(encoded, length...)
	return append(encoded, value...)
}

func rlpEncodeList(items ...[]byte) []byte {
	payload := bytes.Join(items, nil)
	if len(payload) < 56 {
		return append([]byte{byte(0xc0 + len(payload))}, payload...)
	}
	length := lengthBytes(len(payload))
	encoded := []byte{byte(0xf7 + len(length))}
	encoded = append(encoded, length...)
	return append(encoded, payload...)
}

func lengthBytes(length int) []byte {
	var buf [8]byte
	for i := len(buf) - 1; length > 0; i-- {
		buf[i] = byte(length)
		length >>= 8
	}
	first := 0
	for first < len(buf) && buf[first] == 0 {
		first++
	}
	return append([]byte(nil), buf[first:]...)
}

func parseHexInteger(value string) (*big.Int, error) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if value == "" {
		return nil, errors.New("empty hexadecimal integer")
	}
	integer, ok := new(big.Int).SetString(value, 16)
	if !ok {
		return nil, errors.New("invalid hexadecimal integer")
	}
	return integer, nil
}

func parseHexBig(value string) (string, error) {
	integer, err := parseHexInteger(value)
	if err != nil {
		return "", err
	}
	return integer.String(), nil
}

func waitForTransaction(ctx context.Context, rpc *evmRPC, txHash string) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	timeout := time.NewTimer(2 * time.Minute)
	defer timeout.Stop()
	for {
		receipt, err := rpc.callRaw(ctx, "eth_getTransactionReceipt", []any{txHash})
		if err == nil && !bytes.Equal(bytes.TrimSpace(receipt), []byte("null")) {
			var parsed struct {
				Status string `json:"status"`
			}
			if err := json.Unmarshal(receipt, &parsed); err != nil {
				return fmt.Errorf("decode transaction receipt: %w", err)
			}
			status, err := parseHexInteger(parsed.Status)
			if err != nil {
				return errors.New("transaction receipt has invalid status")
			}
			if status.Sign() == 0 {
				return errors.New("transaction was mined but reverted")
			}
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			return errors.New("timed out waiting for transaction receipt")
		case <-ticker.C:
		}
	}
}

func keccak256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write(data)
	return hash.Sum(nil)
}

func writeRegistryJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return NewExitError(ExitOutputError, "write report registry result: %w", err)
	}
	return nil
}
