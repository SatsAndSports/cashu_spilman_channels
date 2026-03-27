package spilmankit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cashubtc/spilman-go/spilman"
	"github.com/skip2/go-qrcode"
)

// DemoFetchActiveKeysetInfo fetches active keyset info from a mint.
func DemoFetchActiveKeysetInfo(mintUrl string, unit string) (map[string]interface{}, error) {
	resp, err := http.Get(mintUrl + "/v1/keysets")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var d struct {
		Keysets []struct {
			Id, Unit    string
			Active      bool
			InputFeePpk uint64 `json:"input_fee_ppk"`
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}

	for _, k := range d.Keysets {
		if k.Unit == unit && k.Active {
			rk, err := http.Get(fmt.Sprintf("%s/v1/keys/%s", mintUrl, k.Id))
			if err != nil {
				return nil, err
			}
			var kd struct {
				Keysets []struct{ Keys map[string]string }
			}
			json.NewDecoder(rk.Body).Decode(&kd)
			rk.Body.Close()
			return map[string]interface{}{
				"keysetId":    k.Id,
				"unit":        unit,
				"inputFeePpk": k.InputFeePpk,
				"keys":        kd.Keysets[0].Keys,
			}, nil
		}
	}
	return nil, fmt.Errorf("no active %s keyset found at %s", unit, mintUrl)
}

// DemoMintFundingToken handles the quote and wait process for funding a channel.
func DemoMintFundingToken(mintUrl string, amount uint64, blinded []interface{}, unit string) ([]interface{}, error) {
	qreq, _ := json.Marshal(map[string]interface{}{"amount": amount, "unit": unit})
	resp, err := http.Post(mintUrl+"/v1/mint/quote/bolt11", "application/json", strings.NewReader(string(qreq)))
	if err != nil {
		return nil, err
	}
	var q struct{ Quote, Request string }
	json.NewDecoder(resp.Body).Decode(&q)
	resp.Body.Close()

	if q.Request != "" {
		fmt.Printf("\n  " + strings.Repeat("=", 56))
		fmt.Printf("\n  PAY THIS INVOICE TO FUND THE CHANNEL\n")
		fmt.Printf("  " + strings.Repeat("=", 56) + "\n\n")
		fmt.Printf("  %s\n\n", q.Request)
		qr, _ := qrcode.New(q.Request, qrcode.Medium)
		fmt.Println(qr.ToSmallString(false))
		fmt.Printf("\n  " + strings.Repeat("=", 56) + "\n\n")
	}

	fmt.Println("  Waiting for payment...")
	for i := 0; i < 120; i++ {
		r, err := http.Get(fmt.Sprintf("%s/v1/mint/quote/bolt11/%s", mintUrl, q.Quote))
		if err != nil {
			return nil, err
		}
		var s struct {
			State string
			Paid  bool
		}
		json.NewDecoder(r.Body).Decode(&s)
		r.Body.Close()
		if s.State == "PAID" || s.Paid {
			fmt.Println("  Payment received!")
			break
		}
		if i == 119 {
			return nil, fmt.Errorf("quote not paid in time")
		}
		time.Sleep(500 * time.Millisecond)
	}

	mreq, _ := json.Marshal(map[string]interface{}{"quote": q.Quote, "outputs": blinded})
	resp, err = http.Post(mintUrl+"/v1/mint/bolt11", "application/json", strings.NewReader(string(mreq)))
	if err != nil {
		return nil, err
	}
	var mr struct{ Signatures []interface{} }
	json.NewDecoder(resp.Body).Decode(&mr)
	resp.Body.Close()
	return mr.Signatures, nil
}

// DemoMintPlainProofs mints plain proofs (not channel-locked) from a mint.
// This handles the full flow: create blinded messages, get quote,
// wait for payment, mint, and construct proofs.
//
// Returns JSON array of proofs ready for use in a token.
func DemoMintPlainProofs(mintUrl string, amount uint64, keysetInfoJson string, unit string) (string, error) {
	// 1. Create plain blinded messages using the spilman wrapper
	resultJson, err := spilman.CreatePlainBlindedMessages(amount, keysetInfoJson)
	if err != nil {
		return "", fmt.Errorf("failed to create blinded messages: %w", err)
	}

	// 2. Parse to extract blinded_messages and secrets_with_blinding
	var result struct {
		BlindedMessages     []interface{} `json:"blinded_messages"`
		SecretsWithBlinding interface{}   `json:"secrets_with_blinding"`
	}
	if err := json.Unmarshal([]byte(resultJson), &result); err != nil {
		return "", fmt.Errorf("failed to parse blinded messages: %w", err)
	}

	// 3. Use existing DemoMintFundingToken to handle quote/pay/mint
	sigs, err := DemoMintFundingToken(mintUrl, amount, result.BlindedMessages, unit)
	if err != nil {
		return "", err
	}

	// 4. Construct proofs
	sigsJson, _ := json.Marshal(sigs)
	swbJson, _ := json.Marshal(result.SecretsWithBlinding)
	return spilman.ConstructProofs(string(sigsJson), string(swbJson), keysetInfoJson)
}
