package spilmankit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/cashubtc/spilman-go/spilman"
)

type bridgeErrorPayload struct {
	Status int    `json:"status"`
	Reason string `json:"reason"`
	Error  string `json:"error"`
}

func parseBridgeErrorJSON(errorMsg string) (int, string, bool) {
	if errorMsg == "" {
		return 0, "", false
	}
	var payload bridgeErrorPayload
	if err := json.Unmarshal([]byte(errorMsg), &payload); err != nil {
		return 0, "", false
	}
	if payload.Status == 0 {
		return 0, "", false
	}
	reason := payload.Reason
	if reason == "" {
		reason = payload.Error
	}
	return payload.Status, reason, true
}

func MapErrorStatus(errorMsg string) int {
	if status, _, ok := parseBridgeErrorJSON(errorMsg); ok {
		return status
	}
	lower := strings.ToLower(errorMsg)
	if strings.Contains(lower, "unknown channel") {
		return 404
	}
	if strings.Contains(lower, "channel closed") {
		return 410
	}
	if strings.Contains(lower, "channel closing") {
		return 409
	}

	// Payment Required (402) cases
	isPaymentRequired := false
	paymentErrors := []string{
		"missing x-cashu-channel",
		"invalid signature",
		"missing header",
		"signature verification failed",
		"channel_id mismatch",
		"insufficient balance",
		"balance exceeds capacity",
		"expiry too soon",
		"mint or keyset not acceptable",
		"max_amount_per_output exceeded",
	}
	for _, e := range paymentErrors {
		if strings.Contains(lower, e) {
			isPaymentRequired = true
			break
		}
	}
	if isPaymentRequired {
		return 402
	}

	// Bad Request (400) cases
	isBadRequest := false
	badRequestErrors := []string{
		"invalid base64",
		"invalid utf8",
		"invalid json",
		"missing field",
		"missing channel_id",
		"missing signature",
	}
	for _, e := range badRequestErrors {
		if strings.Contains(lower, e) {
			isBadRequest = true
			break
		}
	}
	if !isBadRequest && strings.Contains(lower, "expected") &&
		(strings.Contains(lower, "string") || strings.Contains(lower, "integer") || strings.Contains(lower, "u64")) {
		isBadRequest = true
	}

	if isBadRequest {
		return 400
	}
	if strings.Contains(lower, "internal") || strings.Contains(lower, "misconfigured") {
		return 500
	}

	return 402 // Default
}

func (c *ConfigurableSpilman) decodePaymentHeader(r *http.Request) (string, error) {
	headerB64 := r.Header.Get("X-Cashu-Channel")
	if headerB64 == "" {
		return "", fmt.Errorf("Missing X-Cashu-Channel header")
	}
	paymentJsonBytes, err := base64.StdEncoding.DecodeString(headerB64)
	if err != nil {
		return "", fmt.Errorf("invalid base64 encoding")
	}
	return string(paymentJsonBytes), nil
}

func (c *ConfigurableSpilman) ProcessRequestPayment(r *http.Request, context interface{}) (*spilman.PaymentSuccess, error) {
	paymentJson, err := c.decodePaymentHeader(r)
	if err != nil {
		return nil, err
	}
	contextJsonBytes, _ := json.Marshal(context)
	return c.Bridge.ProcessPayment(paymentJson, string(contextJsonBytes))
}

// ProcessRequestPaymentNoUsage validates that the payment covers prior
// accumulated usage, tracks balance and signature, but does NOT increment
// any usage counters. Call RecordUsage after the work is done.
func (c *ConfigurableSpilman) ProcessRequestPaymentNoUsage(r *http.Request) (*spilman.PaymentSuccess, error) {
	return c.ProcessRequestPayment(r, struct{}{})
}

// RecordUsage records usage for the channel in the current request.
// It auto-reads the X-Cashu-Channel header to extract channel_id,
// balance, and signature, then calls Host.RecordPayment with the
// given usage increments. Does NOT re-validate the payment.
//
// This is the companion to ProcessRequestPaymentNoUsage.
func (c *ConfigurableSpilman) RecordUsage(r *http.Request, increments map[string]int) error {
	paymentJson, err := c.decodePaymentHeader(r)
	if err != nil {
		return err
	}
	var data struct {
		ChannelID string `json:"channel_id"`
		Balance   uint64 `json:"balance"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal([]byte(paymentJson), &data); err != nil {
		return fmt.Errorf("failed to parse payment header: %w", err)
	}
	incrementsJson, _ := json.Marshal(increments)
	c.Host.RecordPayment(data.ChannelID, data.Balance, data.Signature, string(incrementsJson))
	return nil
}

func (c *ConfigurableSpilman) PaymentCoversAmountDue(r *http.Request, context interface{}) (bool, error) {
	headerB64 := r.Header.Get("X-Cashu-Channel")
	if headerB64 == "" {
		return false, fmt.Errorf("Missing X-Cashu-Channel header")
	}

	paymentJsonBytes, err := base64.StdEncoding.DecodeString(headerB64)
	if err != nil {
		return false, fmt.Errorf("invalid base64 encoding")
	}

	contextJsonBytes, _ := json.Marshal(context)
	return c.Bridge.PaymentCoversAmountDue(string(paymentJsonBytes), string(contextJsonBytes))
}

func (c *ConfigurableSpilman) VerifyPaymentCoversAmountDue(r *http.Request, context interface{}) (uint64, error) {
	headerB64 := r.Header.Get("X-Cashu-Channel")
	if headerB64 == "" {
		return 0, fmt.Errorf("Missing X-Cashu-Channel header")
	}

	paymentJsonBytes, err := base64.StdEncoding.DecodeString(headerB64)
	if err != nil {
		return 0, fmt.Errorf("invalid base64 encoding")
	}

	contextJsonBytes, _ := json.Marshal(context)
	return c.Bridge.VerifyPaymentCoversAmountDue(string(paymentJsonBytes), string(contextJsonBytes))
}

func (c *ConfigurableSpilman) AttachPaymentHeader(w http.ResponseWriter, p *spilman.PaymentSuccess) {
	info := map[string]interface{}{
		"channel_id": p.ChannelID,
		"balance":    p.Balance,
		"amount_due": p.AmountDue,
		"capacity":   p.Capacity,
	}
	jsonBytes, _ := json.Marshal(info)
	w.Header().Set("X-Cashu-Channel", string(jsonBytes))
}

func (c *ConfigurableSpilman) HandleError(w http.ResponseWriter, err error) {
	msg := err.Error()
	status := MapErrorStatus(msg)
	reason := msg
	if _, parsedReason, ok := parseBridgeErrorJSON(msg); ok && parsedReason != "" {
		reason = parsedReason
	}

	errorName := "Payment failed"
	if status == 400 {
		errorName = "Bad request"
	} else if status == 404 {
		errorName = "Not found"
	}

	w.Header().Set("X-Cashu-Channel", fmt.Sprintf(`{"error":"%s"}`, reason))
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   errorName,
		"reason":  reason,
		"status":  status,
	})
}
