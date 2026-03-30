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
	channelState map[string]string // channelID -> "open" or "closed"
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
		channelState: make(map[string]string),
	}
}

// ============================================================================
// Channel Opening (two-phase)
// ============================================================================

func (h *InMemoryClientHost) SaveOpeningFromSwapChannel(channelID, openingJSON string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.opening[channelID] = openingJSON
	h.channelState[channelID] = "opening_from_swap"
}

func (h *InMemoryClientHost) MarkChannelOpen(channelID, fundingProofsJSON string) {
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
	h.channelState[channelID] = "open"
}

func (h *InMemoryClientHost) GetChannelFunding(channelID string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.funding[channelID]
}

func (h *InMemoryClientHost) GetChannelOpeningFromSwap(channelID string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
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

func (h *InMemoryClientHost) RecordPayment(channelID, stateJSON string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.paymentState[channelID] = stateJSON
}

// ============================================================================
// Lifecycle
// ============================================================================

func (h *InMemoryClientHost) GetChannelState(channelID string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	state := h.channelState[channelID]
	if state == "" {
		return "open"
	}
	return state
}

func (h *InMemoryClientHost) MarkChannelClosed(channelID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.channelState[channelID] = "closed"
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
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	return ids
}

func (h *InMemoryClientHost) DeleteChannel(channelID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.opening, channelID)
	delete(h.funding, channelID)
	delete(h.paymentState, channelID)
	delete(h.channelState, channelID)
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
