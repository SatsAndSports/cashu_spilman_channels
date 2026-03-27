//go:build integration

package spilmankit

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDemoMintPlainProofs(t *testing.T) {
	mintURL := os.Getenv("MINT_URL")
	if mintURL == "" {
		t.Skip("MINT_URL not set, skipping integration test")
	}

	// 1. Fetch keyset info
	ki, err := DemoFetchActiveKeysetInfo(mintURL, "sat")
	if err != nil {
		t.Fatalf("DemoFetchActiveKeysetInfo failed: %v", err)
	}

	kiJSON, err := json.Marshal(ki)
	if err != nil {
		t.Fatalf("json.Marshal keyset info failed: %v", err)
	}
	t.Logf("Using keyset: %s", ki["keysetId"])

	// 2. Mint plain proofs
	amount := uint64(100)
	proofsJSON, err := DemoMintPlainProofs(mintURL, amount, string(kiJSON), "sat")
	if err != nil {
		t.Fatalf("DemoMintPlainProofs failed: %v", err)
	}

	// 3. Parse result as JSON array
	var proofs []map[string]interface{}
	if err := json.Unmarshal([]byte(proofsJSON), &proofs); err != nil {
		t.Fatalf("Failed to parse proofs JSON: %v\nJSON: %s", err, proofsJSON)
	}

	if len(proofs) == 0 {
		t.Fatal("DemoMintPlainProofs returned empty proofs array")
	}
	t.Logf("Minted %d proofs", len(proofs))

	// 4. Verify proofs have expected fields
	totalAmount := uint64(0)
	for i, proof := range proofs {
		// Check required fields
		if _, ok := proof["amount"]; !ok {
			t.Errorf("Proof %d missing 'amount' field", i)
		}
		if _, ok := proof["id"]; !ok {
			t.Errorf("Proof %d missing 'id' field", i)
		}
		if _, ok := proof["secret"]; !ok {
			t.Errorf("Proof %d missing 'secret' field", i)
		}
		if _, ok := proof["C"]; !ok {
			t.Errorf("Proof %d missing 'C' field", i)
		}

		// Sum amounts
		if amt, ok := proof["amount"].(float64); ok {
			totalAmount += uint64(amt)
		}
	}

	// Total should be at least the requested amount (may be slightly more due to denomination)
	if totalAmount < amount {
		t.Errorf("Total proof amount %d < requested %d", totalAmount, amount)
	}
	t.Logf("Total proof amount: %d sat", totalAmount)
}

func TestDemoFetchActiveKeysetInfo(t *testing.T) {
	mintURL := os.Getenv("MINT_URL")
	if mintURL == "" {
		t.Skip("MINT_URL not set, skipping integration test")
	}

	ki, err := DemoFetchActiveKeysetInfo(mintURL, "sat")
	if err != nil {
		t.Fatalf("DemoFetchActiveKeysetInfo failed: %v", err)
	}

	// Verify required fields
	if _, ok := ki["keysetId"]; !ok {
		t.Error("Missing 'keysetId' field")
	}
	if _, ok := ki["unit"]; !ok {
		t.Error("Missing 'unit' field")
	}
	if _, ok := ki["keys"]; !ok {
		t.Error("Missing 'keys' field")
	}

	// inputFeePpk should be present (even if 0)
	if _, ok := ki["inputFeePpk"]; !ok {
		t.Error("Missing 'inputFeePpk' field")
	}

	t.Logf("Keyset ID: %s", ki["keysetId"])
	t.Logf("Unit: %s", ki["unit"])
	t.Logf("Input fee ppk: %v", ki["inputFeePpk"])

	// keys should be a map
	keys, ok := ki["keys"].(map[string]string)
	if !ok {
		t.Errorf("'keys' is not a map[string]string: %T", ki["keys"])
	} else {
		t.Logf("Number of keys: %d", len(keys))
	}
}
