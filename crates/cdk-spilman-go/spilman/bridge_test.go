package spilman

import (
	"fmt"
	"strings"
	"testing"
)

// MockHost is a minimal SpilmanHost implementation for testing
type MockHost struct {
	receiverPubkey string
}

type stateHost struct {
	MockHost
	state string
	err   error
}

func (h *stateHost) GetChannelState(channelId string) (string, error) {
	return h.state, h.err
}

func TestReceiverStateCallback(t *testing.T) {
	for _, tc := range []struct {
		state    string
		err      error
		expected string
	}{
		{"", nil, "unknown_channel"},
		{"closing", nil, "channel_closing"},
		{"closed", nil, "channel_closed"},
		{"sender_refunded_after_expiry", nil, "channel_closed"},
		{"invalid", nil, "internal"},
		{"", fmt.Errorf("storage unavailable"), "internal"},
	} {
		t.Run(tc.expected+tc.state, func(t *testing.T) {
			bridge := NewBridge(&stateHost{state: tc.state, err: tc.err})
			defer bridge.Free()
			_, err := bridge.ValidatePayment(`{"channel_id":"missing","balance":0,"signature":"sig"}`, "{}")
			if err == nil || !strings.Contains(err.Error(), tc.expected) {
				t.Fatalf("expected %s, got %v", tc.expected, err)
			}
		})
	}
}

func (m *MockHost) ReceiverKeyIsAcceptable(pubkeyHex string) bool {
	return pubkeyHex == m.receiverPubkey
}

func (m *MockHost) MintAndKeysetIsAcceptable(mint string, keysetId string) bool {
	return true
}

func (m *MockHost) GetFundingAndParams(channelId string) (string, string, string, string, bool) {
	return "", "", "", "", false
}

func (m *MockHost) SaveFunding(channelId, paramsJson, proofsJson, channelSecretHex, keysetInfoJson string, initialBalance uint64, initialSignature string) {
}

func (m *MockHost) GetAmountDue(channelId string, contextJson *string) uint64 {
	return 0
}

func (m *MockHost) RecordPayment(channelId string, balance uint64, signature, contextJson string) {
}

func (m *MockHost) GetChannelState(channelId string) (string, error) {
	return "", nil
}

func (m *MockHost) MarkChannelClosing(channelId string, expiryTimestamp, balance uint64, signature string) error {
	return nil
}

func (m *MockHost) GetClosingData(channelId string) *ClosingData {
	return nil
}

func (m *MockHost) GetChannelPolicy(unit string) *ChannelPolicy {
	return &ChannelPolicy{MinExpiryInSeconds: 3600, MinCapacity: 10}
}

func (m *MockHost) NowSeconds() uint64 {
	return 1700000000
}

func (m *MockHost) GetBalanceAndSignatureForUnilateralExit(channelId string) (uint64, string, bool) {
	return 0, "", false
}

func (m *MockHost) GetActiveKeysetIds(mint, unit string) []string {
	return []string{}
}

func (m *MockHost) GetKeysetInfo(mint, keysetId string) (string, bool) {
	return "", false
}

func (m *MockHost) CallMintSwap(mintUrl, swapRequestJson string) (string, error) {
	return "", nil
}

func (m *MockHost) RefreshAllKeysets(mintUrl string) error {
	return nil
}

func (m *MockHost) MarkChannelClosed(channelId string, expiryTimestamp, balance uint64, receiverProofsJson, senderProofsJson string, receiverSum, senderSum uint64) error {
	return nil
}

func (m *MockHost) ComputeChannelSecret(senderPubkeyHex, receiverPubkeyHex string) (string, error) {
	return "", fmt.Errorf("not implemented in mock")
}

func (m *MockHost) SignWithTweakedKey(signerPubkeyHex, messageHex, tweakScalarHex string) (string, error) {
	return "", fmt.Errorf("not implemented in mock")
}

func TestNewBridge(t *testing.T) {
	_, pubkey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	host := &MockHost{receiverPubkey: pubkey}
	bridge := NewBridge(host)
	if bridge == nil {
		t.Fatal("NewBridge returned nil")
	}
	defer bridge.Free()

	if bridge.ptr == nil {
		t.Error("Bridge pointer should not be nil")
	}
}

func TestBridgeFree(t *testing.T) {
	_, pubkey, _ := GenerateKeypair()
	host := &MockHost{receiverPubkey: pubkey}
	bridge := NewBridge(host)

	// First free should work
	bridge.Free()

	// ptr should be nil after free
	if bridge.ptr != nil {
		t.Error("Bridge pointer should be nil after Free")
	}

	// Second free should be safe (no panic)
	bridge.Free()
}

func TestBridgeProcessPaymentRejectsInvalidJson(t *testing.T) {
	_, pubkey, _ := GenerateKeypair()
	host := &MockHost{receiverPubkey: pubkey}
	bridge := NewBridge(host)
	defer bridge.Free()

	// Invalid JSON should return error
	_, err := bridge.ProcessPayment("not valid json", "{}")
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestBridgeProcessPaymentRejectsMissingFields(t *testing.T) {
	_, pubkey, _ := GenerateKeypair()
	host := &MockHost{receiverPubkey: pubkey}
	bridge := NewBridge(host)
	defer bridge.Free()

	// Missing required fields
	_, err := bridge.ProcessPayment(`{"balance":0}`, "{}")
	if err == nil {
		t.Error("Expected error for missing fields")
	}
}

func TestBridgeFundChannelRejectsInvalidJson(t *testing.T) {
	_, pubkey, _ := GenerateKeypair()
	host := &MockHost{receiverPubkey: pubkey}
	bridge := NewBridge(host)
	defer bridge.Free()

	_, err := bridge.FundChannel("not valid json")
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestBridgeValidatePaymentRejectsInvalidJson(t *testing.T) {
	_, pubkey, _ := GenerateKeypair()
	host := &MockHost{receiverPubkey: pubkey}
	bridge := NewBridge(host)
	defer bridge.Free()

	_, err := bridge.ValidatePayment("not valid json", "{}")
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}
