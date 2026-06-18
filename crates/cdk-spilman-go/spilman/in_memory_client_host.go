package spilman

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// InMemoryClientHost is a ready-to-use implementation of SpilmanClientHost
// that stores data in memory. Useful for prototyping and demos.
//
// For production, implement SpilmanClientHost with persistent storage.
type InMemoryClientHost struct {
	secretKeyHex string
	mu           sync.Mutex
	opening      map[string]string // channelID -> openingJSON (ClientChannelOpeningFromSwap)
	funding      map[string]string // channelID -> fundingJSON (ClientChannelFunding)
	paymentState map[string]string // channelID -> paymentStateJSON
	failures     map[string]string // channelID -> failureJSON (ClientOpeningFailure)
	channelState map[string]string // channelID -> lifecycle state
}

// NewInMemoryClientHost creates a new in-memory client host.
//
// secretKeyHex is the sender's secret key in hex format (64 chars).
func NewInMemoryClientHost(secretKeyHex string) *InMemoryClientHost {
	return &InMemoryClientHost{
		secretKeyHex: secretKeyHex,
		opening:      make(map[string]string),
		funding:      make(map[string]string),
		paymentState: make(map[string]string),
		failures:     make(map[string]string),
		channelState: make(map[string]string),
	}
}

// ============================================================================
// Channel Opening (two-phase)
// ============================================================================

func (h *InMemoryClientHost) SaveOpeningFromSwapChannel(channelID, openingJSON string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.opening[channelID] = openingJSON
	delete(h.failures, channelID)
	h.channelState[channelID] = "opening_from_swap"
	return nil
}

func (h *InMemoryClientHost) MarkChannelOpen(channelID, fundingProofsJSON string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Read opening data, construct funding, store in funding map, remove from opening map
	if openingJSON, ok := h.opening[channelID]; ok {
		var opening map[string]interface{}
		if json.Unmarshal([]byte(openingJSON), &opening) == nil {
			funding := map[string]interface{}{
				"params_json":          opening["params_json"],
				"funding_proofs_json":  fundingProofsJSON,
				"channel_secret_hex":   opening["channel_secret_hex"],
				"keyset_info_json":     opening["keyset_info_json"],
				"sender_pubkey_hex":    opening["sender_pubkey_hex"],
				"capacity":             opening["capacity"],
				"funding_token_amount": opening["funding_token_amount"],
				"mint_url":             opening["mint_url"],
				"created_at":           opening["created_at"],
			}
			if updated, err := json.Marshal(funding); err == nil {
				h.funding[channelID] = string(updated)
			}
		}
		delete(h.opening, channelID)
	}
	delete(h.failures, channelID)
	h.channelState[channelID] = "open"
	return nil
}

func (h *InMemoryClientHost) MarkChannelOpeningFailed(channelID, failureJSON string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.failures[channelID] = failureJSON
	h.channelState[channelID] = "opening_failed"
	return nil
}

func (h *InMemoryClientHost) GetChannelFunding(channelID string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.funding[channelID]
}

func (h *InMemoryClientHost) GetChannelOpeningFromSwap(channelID string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.channelState[channelID] != "opening_from_swap" {
		return ""
	}
	return h.opening[channelID]
}

// ============================================================================
// Payment State (mutable)
// ============================================================================

func (h *InMemoryClientHost) GetPaymentState(channelID string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.paymentState[channelID]
}

func (h *InMemoryClientHost) RecordPayment(channelID, stateJSON string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.paymentState[channelID] = stateJSON
	return nil
}

// ============================================================================
// Lifecycle
// ============================================================================

func (h *InMemoryClientHost) GetChannelState(channelID string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.channelState[channelID]
}

func (h *InMemoryClientHost) MarkChannelClosed(channelID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.channelState[channelID] = "closed"
	return nil
}

func (h *InMemoryClientHost) MarkChannelClosing(channelID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.channelState[channelID] = "closing"
	return nil
}

func (h *InMemoryClientHost) ListChannelIDs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	seen := make(map[string]bool)
	for id := range h.funding {
		seen[id] = true
	}
	for id := range h.opening {
		seen[id] = true
	}
	for id := range h.failures {
		seen[id] = true
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	return ids
}

func (h *InMemoryClientHost) DeleteChannel(channelID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.opening, channelID)
	delete(h.funding, channelID)
	delete(h.paymentState, channelID)
	delete(h.failures, channelID)
	delete(h.channelState, channelID)
	return nil
}

// ============================================================================
// Time
// ============================================================================

func (h *InMemoryClientHost) NowSeconds() uint64 {
	return uint64(time.Now().Unix())
}

// ============================================================================
// Crypto (uses Rust FFI)
// ============================================================================

func (h *InMemoryClientHost) SignWithTweakedKey(signerPubkeyHex, messageHex, tweakScalarHex string) (string, error) {
	return SignWithTweakedKeyUtil(h.secretKeyHex, messageHex, tweakScalarHex)
}

func (h *InMemoryClientHost) ComputeChannelSecret(senderPubkeyHex, receiverPubkeyHex string) (string, error) {
	return ComputeChannelSecret(h.secretKeyHex, receiverPubkeyHex)
}

// ============================================================================
// Networking (uses net/http)
// ============================================================================

func (h *InMemoryClientHost) CallMintSwap(mintURL, swapRequestJSON string) (string, error) {
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
			var errResp map[string]interface{}
			if json.Unmarshal(body, &errResp) == nil {
				return "", errors.New(string(body))
			}
			return "", errors.New(string(body))
		}
		return "", fmt.Errorf("swap failed with status %d", resp.StatusCode)
	}
	return string(body), nil
}

func (h *InMemoryClientHost) CallMintRestore(mintURL, restoreRequestJSON string) (string, error) {
	resp, err := http.Post(
		mintURL+"/v1/restore",
		"application/json",
		bytes.NewBufferString(restoreRequestJSON),
	)
	if err != nil {
		return "", fmt.Errorf("HTTP error: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		if len(body) > 0 {
			var errResp map[string]interface{}
			if json.Unmarshal(body, &errResp) == nil {
				return "", errors.New(string(body))
			}
			return "", errors.New(string(body))
		}
		return "", fmt.Errorf("restore failed with status %d", resp.StatusCode)
	}
	return string(body), nil
}

func (h *InMemoryClientHost) CallMintKeysets(mintURL string) (string, error) {
	resp, err := http.Get(mintURL + "/v1/keysets")
	if err != nil {
		return "", fmt.Errorf("HTTP error: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		if len(body) > 0 {
			return "", errors.New(string(body))
		}
		return "", fmt.Errorf("keysets failed with status %d", resp.StatusCode)
	}
	return string(body), nil
}

func (h *InMemoryClientHost) CallMintKeys(mintURL, keysetID string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("%s/v1/keys/%s", mintURL, keysetID))
	if err != nil {
		return "", fmt.Errorf("HTTP error: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		if len(body) > 0 {
			return "", errors.New(string(body))
		}
		return "", fmt.Errorf("keys failed with status %d", resp.StatusCode)
	}
	return string(body), nil
}
