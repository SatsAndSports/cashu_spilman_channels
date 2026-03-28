//go:build integration

package spilman

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

func getMintURL() string {
	if url := os.Getenv("MINT_URL"); url != "" {
		return url
	}
	return "http://localhost:3338"
}

// TestMintConnectivity verifies we can reach the mint
func TestMintConnectivity(t *testing.T) {
	mintURL := getMintURL()
	resp, err := http.Get(mintURL + "/v1/info")
	if err != nil {
		t.Fatalf("Cannot connect to mint at %s: %v", mintURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("Mint returned status %d", resp.StatusCode)
	}

	var info struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	json.NewDecoder(resp.Body).Decode(&info)
	t.Logf("Connected to mint: %s (version %s)", info.Name, info.Version)
}

// TestFundingOutputsAndChannelId tests the client-side channel setup flow.
// This requires a mint to fetch keyset info, but doesn't require minting tokens.
func TestFundingOutputsAndChannelId(t *testing.T) {
	mintURL := getMintURL()

	// 1. Generate sender keypair
	aliceSecret, senderPubkey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	t.Logf("Generated sender pubkey: %s...", senderPubkey[:16])

	// 2. Generate receiver keypair (normally this comes from the server)
	_, receiverPubkey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	t.Logf("Generated receiver pubkey: %s...", receiverPubkey[:16])

	// 3. Fetch active keyset from mint
	keysetInfo, err := fetchActiveKeyset(mintURL, "sat")
	if err != nil {
		t.Fatalf("Failed to fetch keyset: %v", err)
	}
	t.Logf("Fetched keyset: %s", keysetInfo["keysetId"])

	keysetJson, _ := json.Marshal(keysetInfo)

	// 4. Compute shared secret
	channelSecret, err := ComputeChannelSecret(aliceSecret, receiverPubkey)
	if err != nil {
		t.Fatalf("ComputeChannelSecret failed: %v", err)
	}
	t.Logf("Computed shared secret: %s...", channelSecret[:16])

	// 5. Build channel parameters
	fundingTokenAmount, err := ComputeFundingTokenAmount(uint64(100), string(keysetJson), uint64(64))
	if err != nil {
		t.Fatalf("ComputeFundingTokenAmount failed: %v", err)
	}
	params := map[string]interface{}{
		"sender_pubkey":        senderPubkey,
		"receiver_pubkey":      receiverPubkey,
		"mint":                 mintURL,
		"unit":                 "sat",
		"capacity":             uint64(100),
		"funding_token_amount": fundingTokenAmount,
		"maximum_amount":       uint64(64),
		"expiry_timestamp":     time.Now().Unix() + 7200,
		"setup_timestamp":      time.Now().Unix(),
		"keyset_id":            keysetInfo["keysetId"],
		"input_fee_ppk":        keysetInfo["inputFeePpk"],
	}
	paramsJson, _ := json.Marshal(params)

	// 6. Get channel ID
	channelId, err := ChannelParametersGetChannelId(string(paramsJson), channelSecret, string(keysetJson))
	if err != nil {
		t.Fatalf("ChannelParametersGetChannelId failed: %v", err)
	}
	t.Logf("Channel ID: %s", channelId)

	// 7. Create funding outputs
	fundingJson, err := CreateFundingOutputs(string(paramsJson), aliceSecret, string(keysetJson))
	if err != nil {
		t.Fatalf("CreateFundingOutputs failed: %v", err)
	}

	var funding struct {
		FundingTokenNominal uint64        `json:"funding_token_nominal"`
		BlindedMessages     []interface{} `json:"blinded_messages"`
	}
	json.Unmarshal([]byte(fundingJson), &funding)

	t.Logf("Funding nominal: %d sat, outputs: %d", funding.FundingTokenNominal, len(funding.BlindedMessages))

	// Verify we got reasonable outputs
	if funding.FundingTokenNominal < 100 {
		t.Errorf("Expected funding >= 100, got %d", funding.FundingTokenNominal)
	}
	if len(funding.BlindedMessages) == 0 {
		t.Error("Expected at least one blinded message")
	}
}

// ============================================================================
// TestClientBridge: end-to-end test of SpilmanClientBridge + server Bridge
// ============================================================================

// testClientHost implements SpilmanClientHost with HTTP swap and in-memory storage.
type testClientHost struct {
	mintURL      string
	mu           sync.Mutex
	funding      map[string]string // channelID -> fundingJSON
	paymentState map[string]string // channelID -> paymentStateJSON
	channelState map[string]string // channelID -> "open" or "closed"
	keys         map[string]string // pubkey_hex -> secret_hex
}

func newTestClientHost(mintURL string) *testClientHost {
	return &testClientHost{
		mintURL:      mintURL,
		funding:      make(map[string]string),
		paymentState: make(map[string]string),
		channelState: make(map[string]string),
		keys:         make(map[string]string),
	}
}

// RegisterKey stores a keypair so the host can sign on behalf of this key.
func (h *testClientHost) RegisterKey(secretHex, pubkeyHex string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keys[pubkeyHex] = secretHex
}

func (h *testClientHost) CallMintSwap(mintURL, swapRequestJSON string) (string, error) {
	resp, err := http.Post(
		mintURL+"/v1/swap",
		"application/json",
		bytes.NewBufferString(swapRequestJSON),
	)
	if err != nil {
		return "", fmt.Errorf("HTTP error: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		if len(body) > 0 {
			return "", errors.New(string(body))
		}
		return "", fmt.Errorf("swap failed with status %d", resp.StatusCode)
	}
	return string(body), nil
}

// Funding Data

func (h *testClientHost) SaveOpeningChannel(channelID, fundingJSON string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.funding[channelID] = fundingJSON
	h.channelState[channelID] = "opening"
}

func (h *testClientHost) MarkChannelOpen(channelID, fundingProofsJSON string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if existing, ok := h.funding[channelID]; ok {
		var funding map[string]interface{}
		if json.Unmarshal([]byte(existing), &funding) == nil {
			funding["funding_proofs_json"] = fundingProofsJSON
			if updated, err := json.Marshal(funding); err == nil {
				h.funding[channelID] = string(updated)
			}
		}
	}
	h.channelState[channelID] = "open"
}

func (h *testClientHost) GetChannelFunding(channelID string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.funding[channelID]
}

// Payment State

func (h *testClientHost) GetPaymentState(channelID string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.paymentState[channelID]
}

func (h *testClientHost) RecordPayment(channelID, stateJSON string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.paymentState[channelID] = stateJSON
}

// Lifecycle

func (h *testClientHost) GetChannelState(channelID string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	state := h.channelState[channelID]
	if state == "" {
		return "open"
	}
	return state
}

func (h *testClientHost) MarkChannelClosed(channelID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.channelState[channelID] = "closed"
}

func (h *testClientHost) ListChannelIDs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ids := make([]string, 0, len(h.funding))
	for id := range h.funding {
		ids = append(ids, id)
	}
	return ids
}

func (h *testClientHost) DeleteChannel(channelID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.funding, channelID)
	delete(h.paymentState, channelID)
	delete(h.channelState, channelID)
}

// Time

func (h *testClientHost) NowSeconds() uint64 {
	return uint64(time.Now().Unix())
}

func (h *testClientHost) SignWithTweakedKey(signerPubkeyHex, messageHex, tweakScalarHex string) (string, error) {
	h.mu.Lock()
	secretHex, ok := h.keys[signerPubkeyHex]
	h.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("no key registered for pubkey: %s", signerPubkeyHex)
	}
	return SignWithTweakedKeyUtil(secretHex, messageHex, tweakScalarHex)
}

func (h *testClientHost) ComputeChannelSecret(senderPubkeyHex, receiverPubkeyHex string) (string, error) {
	h.mu.Lock()
	secretHex, ok := h.keys[senderPubkeyHex]
	h.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("no key registered for pubkey: %s", senderPubkeyHex)
	}
	return ComputeChannelSecret(secretHex, receiverPubkeyHex)
}

type failingClientHost struct {
	*testClientHost
	mintErr string
}

func (h *failingClientHost) CallMintSwap(mintURL, swapRequestJSON string) (string, error) {
	return "", errors.New(h.mintErr)
}

// testServerHost implements SpilmanHost for the server-side bridge in tests.
type testServerHost struct {
	keysetID       string
	keysetInfoJSON string
	secretKey      string
	mu             sync.Mutex
	fundingData    map[string]serverFunding
	payments       map[string]serverPayment
}

type serverFunding struct {
	paramsJSON       string
	proofsJSON       string
	channelSecretHex string
	keysetInfoJSON   string
}

type serverPayment struct {
	balance   uint64
	signature string
}

func newTestServerHost(keysetID, keysetInfoJSON, secretKey string) *testServerHost {
	return &testServerHost{
		keysetID:       keysetID,
		keysetInfoJSON: keysetInfoJSON,
		secretKey:      secretKey,
		fundingData:    make(map[string]serverFunding),
		payments:       make(map[string]serverPayment),
	}
}

func (h *testServerHost) ReceiverKeyIsAcceptable(pubkeyHex string) bool        { return true }
func (h *testServerHost) MintAndKeysetIsAcceptable(mint, keysetId string) bool { return true }

func (h *testServerHost) GetFundingAndParams(channelId string) (string, string, string, string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f, ok := h.fundingData[channelId]
	if !ok {
		return "", "", "", "", false
	}
	return f.paramsJSON, f.proofsJSON, f.channelSecretHex, f.keysetInfoJSON, true
}

func (h *testServerHost) SaveFunding(channelId, paramsJSON, proofsJSON, channelSecretHex, keysetInfoJSON string, initialBalance uint64, initialSignature string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fundingData[channelId] = serverFunding{
		paramsJSON:       paramsJSON,
		proofsJSON:       proofsJSON,
		channelSecretHex: channelSecretHex,
		keysetInfoJSON:   keysetInfoJSON,
	}
}

func (h *testServerHost) GetAmountDue(channelId string, contextJson *string) uint64 { return 0 }

func (h *testServerHost) RecordPayment(channelId string, balance uint64, signature, contextJson string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.payments[channelId] = serverPayment{balance: balance, signature: signature}
}

func (h *testServerHost) GetChannelState(channelId string) string { return "open" }

func (h *testServerHost) MarkChannelClosing(channelId string, expiryTimestamp, balance uint64, signature string) error {
	return nil
}

func (h *testServerHost) GetClosingData(channelId string) *ClosingData { return nil }

func (h *testServerHost) GetChannelPolicy(unit string) *ChannelPolicy {
	if unit == "sat" {
		return &ChannelPolicy{MinExpiryInSeconds: 3600, MinCapacity: 10}
	}
	return nil
}

func (h *testServerHost) NowSeconds() uint64 { return uint64(time.Now().Unix()) }

func (h *testServerHost) GetBalanceAndSignatureForUnilateralExit(channelId string) (uint64, string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.payments[channelId]
	if !ok {
		return 0, "", false
	}
	return p.balance, p.signature, true
}

func (h *testServerHost) GetActiveKeysetIds(mint, unit string) []string {
	return []string{h.keysetID}
}

func (h *testServerHost) GetKeysetInfo(mint, keysetId string) (string, bool) {
	if keysetId == h.keysetID {
		return h.keysetInfoJSON, true
	}
	return "", false
}

func (h *testServerHost) CallMintSwap(mintUrl, swapRequestJson string) (string, error) {
	return "", fmt.Errorf("not used in this test")
}

func (h *testServerHost) RefreshAllKeysets(mintUrl string) error { return nil }

func (h *testServerHost) MarkChannelClosed(channelId string, expiryTimestamp, balance uint64, receiverProofsJson, senderProofsJson string, receiverSum, senderSum uint64) error {
	return nil
}

func (h *testServerHost) ComputeChannelSecret(senderPubkeyHex, receiverPubkeyHex string) (string, error) {
	return ComputeChannelSecret(h.secretKey, senderPubkeyHex)
}

func (h *testServerHost) SignWithTweakedKey(signerPubkeyHex, messageHex, tweakScalarHex string) (string, error) {
	return SignWithTweakedKeyUtil(h.secretKey, messageHex, tweakScalarHex)
}

// httpCallback is a simple HTTP callback for use with MintProofsFromMint.
// It performs GET and POST requests and returns the response body as a string.
func httpCallback(method, url, body string) (string, error) {
	var resp *http.Response
	var err error
	if method == "GET" {
		resp, err = http.Get(url)
	} else {
		resp, err = http.Post(url, "application/json", bytes.NewBufferString(body))
	}
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(respBody), nil
}

// TestClientBridge tests the full SpilmanClientBridge end-to-end:
// 1. Mints plain proofs via HTTP
// 2. Constructs a cashuA token
// 3. Opens a channel via ClientBridge.OpenChannelFromToken
// 4. Signs balance updates and builds payment headers
// 5. Validates headers on a server-side Bridge (full round-trip)
func TestClientBridge(t *testing.T) {
	mintURL := getMintURL()

	// ================================================================
	// Setup: fetch keyset, generate keypairs
	// ================================================================

	keysetInfo, err := fetchActiveKeyset(mintURL, "sat")
	if err != nil {
		t.Fatalf("Failed to fetch keyset: %v", err)
	}
	keysetJSON, _ := json.Marshal(keysetInfo)
	keysetID := keysetInfo["keysetId"].(string)
	t.Logf("Using keyset: %s", keysetID)

	// Generate Charlie (server/receiver) keypair
	charlieSecret, receiverPubkey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (charlie) failed: %v", err)
	}
	t.Logf("Charlie pubkey: %s...", receiverPubkey[:16])

	// ================================================================
	// Step 1: Mint plain proofs and build cashuA token
	// ================================================================

	proofsJSON, err := MintProofsFromMint(mintURL, 100, string(keysetJSON), httpCallback)
	if err != nil {
		t.Fatalf("MintProofsFromMint failed: %v", err)
	}
	token, err := BuildCashuAToken(mintURL, proofsJSON)
	if err != nil {
		t.Fatalf("BuildCashuAToken failed: %v", err)
	}
	t.Logf("Built cashuA token: %s...%s", token[:20], token[len(token)-10:])

	// ================================================================
	// Step 2: Create client bridge and open channel
	// ================================================================

	// Generate Alice keypair externally and register with host
	aliceSecret, senderPubkey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (alice) failed: %v", err)
	}

	clientHost := newTestClientHost(mintURL)
	clientHost.RegisterKey(aliceSecret, senderPubkey)

	clientBridge, err := NewClientBridge(clientHost)
	if err != nil {
		t.Fatalf("NewClientBridge failed: %v", err)
	}
	defer clientBridge.Free()

	t.Logf("Client bridge created, sender_pubkey: %s...", senderPubkey[:16])

	expiryTimestamp := uint64(time.Now().Unix()) + 7200 // 2 hours
	maxAmount := uint64(64)

	openResult, err := clientBridge.OpenChannelFromToken(token, receiverPubkey, senderPubkey, expiryTimestamp, string(keysetJSON), maxAmount)
	if err != nil {
		t.Fatalf("OpenChannelFromToken failed: %v", err)
	}

	t.Logf("Channel opened: id=%s, capacity=%d, funding=%d",
		openResult.ChannelID, openResult.Capacity, openResult.FundingTokenAmount)

	if openResult.Capacity == 0 {
		t.Fatal("Capacity should be positive")
	}
	if openResult.Capacity > 100 {
		t.Fatalf("Capacity should not exceed input value, got %d", openResult.Capacity)
	}

	// Verify channel is stored
	channels := clientBridge.ListChannels()
	if len(channels) != 1 {
		t.Fatalf("Expected 1 channel, got %d", len(channels))
	}
	if channels[0] != openResult.ChannelID {
		t.Fatalf("Channel ID mismatch: %s != %s", channels[0], openResult.ChannelID)
	}

	info := clientBridge.GetChannelInfo(openResult.ChannelID)
	if info == nil {
		t.Fatal("GetChannelInfo returned nil")
	}
	if info.Capacity != openResult.Capacity {
		t.Fatalf("Capacity mismatch: %d != %d", info.Capacity, openResult.Capacity)
	}
	t.Log("Channel stored and retrievable")

	// ================================================================
	// Step 3: Create payments
	// ================================================================

	paymentJSON, err := clientBridge.CreatePayment(openResult.ChannelID, 10)
	if err != nil {
		t.Fatalf("CreatePayment failed: %v", err)
	}

	var payment map[string]interface{}
	json.Unmarshal([]byte(paymentJSON), &payment)

	if payment["channel_id"].(string) != openResult.ChannelID {
		t.Fatal("Payment channel_id mismatch")
	}
	if uint64(payment["balance"].(float64)) != 10 {
		t.Fatal("Payment balance mismatch")
	}
	if _, ok := payment["signature"]; !ok {
		t.Fatal("Payment missing signature")
	}
	t.Log("CreatePayment returned valid JSON")

	// ================================================================
	// Step 4: Build payment headers
	// ================================================================

	// Header WITH funding (first request to server)
	headerWithFunding, err := clientBridge.BuildPaymentHeader(openResult.ChannelID, 10, true)
	if err != nil {
		t.Fatalf("BuildPaymentHeader (with funding) failed: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(headerWithFunding)
	if err != nil {
		t.Fatalf("Failed to base64 decode header: %v", err)
	}

	var headerJSON map[string]interface{}
	if err := json.Unmarshal(decoded, &headerJSON); err != nil {
		t.Fatalf("Failed to parse header JSON: %v", err)
	}

	if headerJSON["channel_id"].(string) != openResult.ChannelID {
		t.Fatal("Header channel_id mismatch")
	}
	if uint64(headerJSON["balance"].(float64)) != 10 {
		t.Fatal("Header balance mismatch")
	}
	if _, ok := headerJSON["signature"]; !ok {
		t.Fatal("Header missing signature")
	}
	if _, ok := headerJSON["params"]; !ok {
		t.Fatal("Header with funding should include params")
	}
	if _, ok := headerJSON["funding_proofs"]; !ok {
		t.Fatal("Header with funding should include funding_proofs")
	}
	t.Log("Payment header (with funding) is valid")

	// Header WITHOUT funding (subsequent requests)
	headerNoFunding, err := clientBridge.BuildPaymentHeader(openResult.ChannelID, 20, false)
	if err != nil {
		t.Fatalf("BuildPaymentHeader (no funding) failed: %v", err)
	}

	decoded2, err := base64.StdEncoding.DecodeString(headerNoFunding)
	if err != nil {
		t.Fatalf("Failed to base64 decode header: %v", err)
	}

	var headerJSON2 map[string]interface{}
	json.Unmarshal(decoded2, &headerJSON2)

	if uint64(headerJSON2["balance"].(float64)) != 20 {
		t.Fatal("Header balance mismatch")
	}
	if _, ok := headerJSON2["params"]; ok {
		t.Fatal("Header without funding should NOT include params")
	}
	if _, ok := headerJSON2["funding_proofs"]; ok {
		t.Fatal("Header without funding should NOT include funding_proofs")
	}
	t.Log("Payment header (without funding) omits params/proofs")

	// ================================================================
	// Step 5: Server-side validation (end-to-end!)
	// ================================================================

	serverHost := newTestServerHost(keysetID, string(keysetJSON), charlieSecret)
	serverBridge := NewBridge(serverHost)
	if serverBridge == nil {
		t.Fatal("NewBridge returned nil")
	}
	defer serverBridge.Free()

	// First payment: header with funding (server learns about channel)
	paymentResult, err := serverBridge.ProcessPayment(string(decoded), `{"type":"test"}`)
	if err != nil {
		t.Fatalf("Server ProcessPayment (first) failed: %v", err)
	}

	if paymentResult.ChannelID != openResult.ChannelID {
		t.Fatal("Server channel_id mismatch")
	}
	if paymentResult.Balance != 10 {
		t.Fatalf("Server balance mismatch: expected 10, got %d", paymentResult.Balance)
	}
	if paymentResult.Capacity != openResult.Capacity {
		t.Fatalf("Server capacity mismatch: expected %d, got %d", openResult.Capacity, paymentResult.Capacity)
	}
	t.Logf("Server accepted first payment (balance=%d, capacity=%d)",
		paymentResult.Balance, paymentResult.Capacity)

	// Second payment: header without funding (server already knows channel)
	paymentResult2, err := serverBridge.ProcessPayment(string(decoded2), `{"type":"test"}`)
	if err != nil {
		t.Fatalf("Server ProcessPayment (second) failed: %v", err)
	}

	if paymentResult2.Balance != 20 {
		t.Fatalf("Server balance mismatch: expected 20, got %d", paymentResult2.Balance)
	}
	t.Logf("Server accepted second payment (balance=%d)", paymentResult2.Balance)

	// ================================================================
	// Step 6: Delete channel
	// ================================================================

	clientBridge.DeleteChannel(openResult.ChannelID)

	if clientBridge.GetChannelInfo(openResult.ChannelID) != nil {
		t.Fatal("Channel should be removed")
	}
	if len(clientBridge.ListChannels()) != 0 {
		t.Fatal("Channel list should be empty")
	}
	t.Log("Channel removed from storage")

	t.Log("All client bridge tests passed!")
}

func TestClientBridgePreservesStructuredMintError(t *testing.T) {
	mintURL := getMintURL()

	keysetInfo, err := fetchActiveKeyset(mintURL, "sat")
	if err != nil {
		t.Fatalf("Failed to fetch keyset: %v", err)
	}
	keysetJSON, _ := json.Marshal(keysetInfo)

	_, receiverPubkey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (receiver) failed: %v", err)
	}

	proofsJSON, err := MintProofsFromMint(mintURL, 100, string(keysetJSON), httpCallback)
	if err != nil {
		t.Fatalf("MintProofsFromMint failed: %v", err)
	}
	token, err := BuildCashuAToken(mintURL, proofsJSON)
	if err != nil {
		t.Fatalf("BuildCashuAToken failed: %v", err)
	}

	aliceSecret, senderPubkey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (alice) failed: %v", err)
	}

	host := &failingClientHost{
		testClientHost: newTestClientHost(mintURL),
		mintErr:        "{\n  \"code\": 12001,\n  \"detail\": \"Unknown Keyset\"\n}",
	}
	host.RegisterKey(aliceSecret, senderPubkey)

	clientBridge, err := NewClientBridge(host)
	if err != nil {
		t.Fatalf("NewClientBridge failed: %v", err)
	}
	defer clientBridge.Free()

	_, err = clientBridge.OpenChannelFromToken(
		token,
		receiverPubkey,
		senderPubkey,
		uint64(time.Now().Unix())+7200,
		string(keysetJSON),
		64,
	)
	if err == nil {
		t.Fatal("expected open channel to fail")
	}

	var errJSON map[string]interface{}
	if decodeErr := json.Unmarshal([]byte(err.Error()), &errJSON); decodeErr != nil {
		t.Fatalf("expected structured JSON error, got %q: %v", err.Error(), decodeErr)
	}
	if uint64(errJSON["code"].(float64)) != 12001 {
		t.Fatalf("expected code 12001, got %v", errJSON["code"])
	}
	if errJSON["detail"].(string) != "Unknown Keyset" {
		t.Fatalf("expected detail %q, got %q", "Unknown Keyset", errJSON["detail"])
	}
}

// fetchActiveKeyset fetches the active keyset for a unit from the mint
func fetchActiveKeyset(mintURL, unit string) (map[string]interface{}, error) {
	resp, err := http.Get(mintURL + "/v1/keysets")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var keysetsResp struct {
		Keysets []struct {
			Id          string `json:"id"`
			Unit        string `json:"unit"`
			Active      bool   `json:"active"`
			InputFeePpk uint64 `json:"input_fee_ppk"`
		} `json:"keysets"`
	}
	json.NewDecoder(resp.Body).Decode(&keysetsResp)

	var activeId string
	var inputFeePpk uint64
	for _, k := range keysetsResp.Keysets {
		if k.Unit == unit && k.Active {
			activeId = k.Id
			inputFeePpk = k.InputFeePpk
			break
		}
	}
	if activeId == "" {
		return nil, fmt.Errorf("no active %s keyset found", unit)
	}

	// Fetch keys for this keyset
	resp, err = http.Get(fmt.Sprintf("%s/v1/keys/%s", mintURL, activeId))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var keysResp struct {
		Keysets []struct {
			Keys map[string]string `json:"keys"`
		} `json:"keysets"`
	}
	json.Unmarshal(body, &keysResp)

	return map[string]interface{}{
		"keysetId":    activeId,
		"unit":        unit,
		"inputFeePpk": inputFeePpk,
		"keys":        keysResp.Keysets[0].Keys,
	}, nil
}
