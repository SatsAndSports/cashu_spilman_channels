//go:build spilman_dev

package spilman

import (
	"testing"
	"time"
)

func TestInMemoryClientHost_FundingStorage(t *testing.T) {
	secret, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	host := NewInMemoryClientHost(secret)

	channelID := "test-channel-123"
	fundingJSON := `{"params_json":"{}","funding_proofs_json":"[]"}`

	// GetChannelFunding returns empty string for unknown channel
	if got := host.GetChannelFunding("unknown"); got != "" {
		t.Errorf("GetChannelFunding(unknown) = %q, want empty string", got)
	}

	// SaveOpeningChannel stores data
	host.SaveOpeningChannel(channelID, fundingJSON)

	// GetChannelFunding retrieves it
	if got := host.GetChannelFunding(channelID); got != fundingJSON {
		t.Errorf("GetChannelFunding() = %q, want %q", got, fundingJSON)
	}

	// SaveOpeningChannel sets state to "opening"
	if got := host.GetChannelState(channelID); got != "opening" {
		t.Errorf("GetChannelState() after save = %q, want %q", got, "opening")
	}

	// MarkChannelOpen transitions state to "open"
	host.MarkChannelOpen(channelID, "[]")
	if got := host.GetChannelState(channelID); got != "open" {
		t.Errorf("GetChannelState() after MarkChannelOpen = %q, want %q", got, "open")
	}
}

func TestInMemoryClientHost_PaymentState(t *testing.T) {
	secret, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	host := NewInMemoryClientHost(secret)

	channelID := "test-channel-456"
	stateJSON := `{"balance":100,"signature":"abc123"}`

	// GetPaymentState returns empty string initially
	if got := host.GetPaymentState(channelID); got != "" {
		t.Errorf("GetPaymentState() initially = %q, want empty string", got)
	}

	// RecordPayment stores state
	host.RecordPayment(channelID, stateJSON)

	// GetPaymentState retrieves it
	if got := host.GetPaymentState(channelID); got != stateJSON {
		t.Errorf("GetPaymentState() = %q, want %q", got, stateJSON)
	}

	// Update with new state
	newStateJSON := `{"balance":200,"signature":"def456"}`
	host.RecordPayment(channelID, newStateJSON)

	if got := host.GetPaymentState(channelID); got != newStateJSON {
		t.Errorf("GetPaymentState() after update = %q, want %q", got, newStateJSON)
	}
}

func TestInMemoryClientHost_Lifecycle(t *testing.T) {
	secret, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	host := NewInMemoryClientHost(secret)

	channelID1 := "channel-1"
	channelID2 := "channel-2"

	// GetChannelState returns "open" for unknown channel
	if got := host.GetChannelState("unknown"); got != "open" {
		t.Errorf("GetChannelState(unknown) = %q, want %q", got, "open")
	}

	// Save two channels
	host.SaveOpeningChannel(channelID1, `{"id":1}`)
	host.MarkChannelOpen(channelID1, "[]")
	host.SaveOpeningChannel(channelID2, `{"id":2}`)
	host.MarkChannelOpen(channelID2, "[]")
	host.RecordPayment(channelID1, `{"balance":10}`)

	// ListChannelIDs returns all stored channels
	ids := host.ListChannelIDs()
	if len(ids) != 2 {
		t.Errorf("ListChannelIDs() returned %d items, want 2", len(ids))
	}

	// Both channels should be in the list (order not guaranteed)
	found1, found2 := false, false
	for _, id := range ids {
		if id == channelID1 {
			found1 = true
		}
		if id == channelID2 {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Errorf("ListChannelIDs() = %v, want both %q and %q", ids, channelID1, channelID2)
	}

	// MarkChannelClosed changes state to "closed"
	host.MarkChannelClosed(channelID1)
	if got := host.GetChannelState(channelID1); got != "closed" {
		t.Errorf("GetChannelState() after close = %q, want %q", got, "closed")
	}

	// Other channel still open
	if got := host.GetChannelState(channelID2); got != "open" {
		t.Errorf("GetChannelState(channel2) = %q, want %q", got, "open")
	}

	// DeleteChannel removes channel and all its data
	host.DeleteChannel(channelID1)

	if got := host.GetChannelFunding(channelID1); got != "" {
		t.Errorf("GetChannelFunding() after delete = %q, want empty", got)
	}
	if got := host.GetPaymentState(channelID1); got != "" {
		t.Errorf("GetPaymentState() after delete = %q, want empty", got)
	}

	// ListChannelIDs should only return channel2 now
	ids = host.ListChannelIDs()
	if len(ids) != 1 || ids[0] != channelID2 {
		t.Errorf("ListChannelIDs() after delete = %v, want [%q]", ids, channelID2)
	}
}

func TestInMemoryClientHost_NowSeconds(t *testing.T) {
	secret, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	host := NewInMemoryClientHost(secret)

	before := uint64(time.Now().Unix())
	got := host.NowSeconds()
	after := uint64(time.Now().Unix())

	if got < before || got > after {
		t.Errorf("NowSeconds() = %d, want between %d and %d", got, before, after)
	}
}

func TestInMemoryClientHost_Crypto(t *testing.T) {
	secret, pubkey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	host := NewInMemoryClientHost(secret)

	// Generate another keypair for the receiver
	_, receiverPubkey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (receiver) failed: %v", err)
	}

	// ComputeChannelSecret produces deterministic result
	secret1, err := host.ComputeChannelSecret(pubkey, receiverPubkey)
	if err != nil {
		t.Fatalf("ComputeChannelSecret failed: %v", err)
	}
	if len(secret1) != 64 { // 32 bytes hex encoded
		t.Errorf("ComputeChannelSecret returned %d chars, want 64", len(secret1))
	}

	// Same inputs produce same output
	secret2, err := host.ComputeChannelSecret(pubkey, receiverPubkey)
	if err != nil {
		t.Fatalf("ComputeChannelSecret (2nd call) failed: %v", err)
	}
	if secret1 != secret2 {
		t.Errorf("ComputeChannelSecret not deterministic: %q != %q", secret1, secret2)
	}

	// SignWithTweakedKey produces a signature
	messageHex := "0000000000000000000000000000000000000000000000000000000000000001"
	tweakHex := "0000000000000000000000000000000000000000000000000000000000000002"

	sig, err := host.SignWithTweakedKey(pubkey, messageHex, tweakHex)
	if err != nil {
		t.Fatalf("SignWithTweakedKey failed: %v", err)
	}
	if len(sig) != 128 { // 64 bytes hex encoded
		t.Errorf("SignWithTweakedKey returned %d chars, want 128", len(sig))
	}

	// Note: Schnorr signatures may use random nonces, so we just verify
	// that it produces a valid-looking signature (correct length, valid hex)
	for _, c := range sig {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("SignWithTweakedKey returned invalid hex character: %c", c)
		}
	}
}
