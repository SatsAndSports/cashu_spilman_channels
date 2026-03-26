package spilman

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	secret, pubkey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	// Secret should be 64 hex chars (32 bytes)
	if len(secret) != 64 {
		t.Errorf("Expected secret length 64, got %d", len(secret))
	}

	// Pubkey should be 66 hex chars (33 bytes compressed)
	if len(pubkey) != 66 {
		t.Errorf("Expected pubkey length 66, got %d", len(pubkey))
	}

	// Both should be valid hex
	if _, err := hex.DecodeString(secret); err != nil {
		t.Errorf("Secret is not valid hex: %v", err)
	}
	if _, err := hex.DecodeString(pubkey); err != nil {
		t.Errorf("Pubkey is not valid hex: %v", err)
	}

	// Pubkey should start with 02 or 03 (compressed format)
	if pubkey[0:2] != "02" && pubkey[0:2] != "03" {
		t.Errorf("Pubkey should start with 02 or 03, got %s", pubkey[0:2])
	}
}

func TestGenerateKeypairUniqueness(t *testing.T) {
	secret1, pubkey1, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	secret2, pubkey2, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	if secret1 == secret2 {
		t.Error("Two generated secrets should not be equal")
	}

	if pubkey1 == pubkey2 {
		t.Error("Two generated pubkeys should not be equal")
	}
}

func TestSecretKeyToPubkey(t *testing.T) {
	secret, expectedPubkey, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	pubkey, err := SecretKeyToPubkey(secret)
	if err != nil {
		t.Fatalf("SecretKeyToPubkey failed: %v", err)
	}

	if pubkey != expectedPubkey {
		t.Errorf("Pubkey mismatch: expected %s, got %s", expectedPubkey, pubkey)
	}
}

func TestSecretKeyToPubkeyInvalidHex(t *testing.T) {
	_, err := SecretKeyToPubkey("not-valid-hex")
	if err == nil {
		t.Error("Expected error for invalid hex input")
	}
}

func TestSecretKeyToPubkeyWrongLength(t *testing.T) {
	_, err := SecretKeyToPubkey("0123456789abcdef") // Too short
	if err == nil {
		t.Error("Expected error for wrong length input")
	}
}

func TestComputeChannelSecret(t *testing.T) {
	// Generate two keypairs
	secretA, pubkeyA, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair A failed: %v", err)
	}

	secretB, pubkeyB, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair B failed: %v", err)
	}

	// Compute channel secret from both sides
	channelAB, err := ComputeChannelSecret(secretA, pubkeyB)
	if err != nil {
		t.Fatalf("ComputeChannelSecret(A, B) failed: %v", err)
	}

	channelBA, err := ComputeChannelSecret(secretB, pubkeyA)
	if err != nil {
		t.Fatalf("ComputeChannelSecret(B, A) failed: %v", err)
	}

	// ECDH: both should produce the same channel secret
	if channelAB != channelBA {
		t.Errorf("Shared secrets should match: %s != %s", channelAB, channelBA)
	}

	// Shared secret should be 64 hex chars (32 bytes)
	if len(channelAB) != 64 {
		t.Errorf("Expected channel secret length 64, got %d", len(channelAB))
	}
}

func TestComputeChannelSecretInvalidInputs(t *testing.T) {
	secret, pubkey, _ := GenerateKeypair()

	// Invalid secret
	_, err := ComputeChannelSecret("invalid", pubkey)
	if err == nil {
		t.Error("Expected error for invalid secret")
	}

	// Invalid pubkey
	_, err = ComputeChannelSecret(secret, "invalid")
	if err == nil {
		t.Error("Expected error for invalid pubkey")
	}
}

// TestTypesJsonSerialization tests that our types serialize/deserialize correctly
func TestTypesJsonSerialization(t *testing.T) {
	t.Run("PaymentSuccess", func(t *testing.T) {
		original := PaymentSuccess{
			ChannelID: "abc123",
			Balance:   100,
			AmountDue: 50,
			Capacity:  1000,
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		var decoded PaymentSuccess
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}

		if decoded != original {
			t.Errorf("Mismatch: %+v != %+v", decoded, original)
		}
	})

	t.Run("CloseSuccess", func(t *testing.T) {
		original := CloseSuccess{
			ChannelID:     "def456",
			TotalValue:    500,
			ReceiverSum:   300,
			SenderSum:     200,
			SenderProofs:  `[{"amount":200}]`,
			AlreadyClosed: false,
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		var decoded CloseSuccess
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}

		if decoded != original {
			t.Errorf("Mismatch: %+v != %+v", decoded, original)
		}
	})

	t.Run("FundChannelResult", func(t *testing.T) {
		original := FundChannelResult{
			ChannelID:    "ghi789",
			Capacity:     1000,
			AlreadyKnown: true,
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		var decoded FundChannelResult
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}

		if decoded != original {
			t.Errorf("Mismatch: %+v != %+v", decoded, original)
		}
	})
}
