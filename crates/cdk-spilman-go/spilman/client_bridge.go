package spilman

// Client bridge uses the Rust SpilmanClientBridge via CGO.
// C type CResult is already declared in bridge.go's CGO preamble.
// SpilmanClientHostCallbacks is declared in client_gateway.c.
// We declare only the new function prototypes here.

/*
#include <stdlib.h>
#include <stdint.h>
#include "client_bridge_types.h"

// From client_gateway.c
SpilmanClientHostCallbacks fill_client_callbacks(void* user_data);

// From Rust FFI (cdk-spilman-go/src/lib.rs)
void* spilman_client_bridge_new(SpilmanClientHostCallbacks callbacks);
void spilman_client_bridge_free(void* ptr);
void spilman_client_bridge_close_channel(void* ptr, const char* channel_id);
void spilman_client_bridge_delete_channel(void* ptr, const char* channel_id);
void spilman_free_string(char* ptr);
*/
import "C"
import (
	"encoding/json"
	"errors"
	"runtime/cgo"
	"unsafe"
)

// ClientBridge is the main entry point for client-side Spilman channel operations.
// It wraps the Rust SpilmanClientBridge and delegates storage/network to a SpilmanClientHost.
//
// The bridge never holds or sees Alice's secret key; all key operations are
// delegated to the host via callbacks. The caller passes sender_pubkey_hex
// per channel when opening channels.
type ClientBridge struct {
	ptr    unsafe.Pointer
	handle cgo.Handle
	freed  bool
}

// NewClientBridge creates a new ClientBridge with the given host implementation.
//
// The bridge is stateless and keyless — it delegates all key operations
// to the host. The caller passes senderPubkeyHex per channel when opening channels.
func NewClientBridge(host SpilmanClientHost) (*ClientBridge, error) {
	handle := cgo.NewHandle(host)
	callbacks := C.fill_client_callbacks(unsafe.Pointer(handle)) //nolint:govet

	ptr := C.spilman_client_bridge_new(callbacks)
	if ptr == nil {
		handle.Delete()
		return nil, errors.New("failed to create client bridge")
	}
	return &ClientBridge{ptr: ptr, handle: handle}, nil
}

// Free releases the resources held by the ClientBridge.
// Must be called when the ClientBridge is no longer needed.
// Safe to call multiple times.
func (b *ClientBridge) Free() {
	if b.freed {
		return
	}
	b.freed = true
	if b.ptr != nil {
		C.spilman_client_bridge_free(b.ptr)
		b.ptr = nil
	}
	b.handle.Delete()
}

// OpenChannelFromToken opens a new channel from a Cashu token.
//
// This performs the full funding flow:
//  1. Compute ECDH channel secret via host.ComputeChannelSecret()
//  2. Parse the token and compute channel parameters
//  3. Create a funding swap request (deterministic 2-of-2 locked outputs)
//  4. Submit the swap to the mint via host.CallMintSwap()
//  5. Unblind signatures and verify DLEQ proofs
//  6. Save the channel via host.SaveChannelFunding()
func (b *ClientBridge) OpenChannelFromToken(token, receiverPubkeyHex, senderPubkeyHex string, expiryTimestamp uint64, keysetInfoJSON string, maxAmount uint64) (*OpenChannelResult, error) {
	return clientBridgeOpenChannel(b.ptr, token, receiverPubkeyHex, senderPubkeyHex, expiryTimestamp, keysetInfoJSON, maxAmount)
}

// CreatePayment creates a payment for a channel (without funding data).
// Returns JSON with the Payment struct.
func (b *ClientBridge) CreatePayment(channelID string, balance uint64) (string, error) {
	return clientBridgeCreatePayment(b.ptr, channelID, balance)
}

// CreatePaymentWithFunding creates a payment with funding data (for first payment).
// Returns JSON with the Payment struct including params and funding_proofs.
func (b *ClientBridge) CreatePaymentWithFunding(channelID string, balance uint64) (string, error) {
	return clientBridgeCreatePaymentWithFunding(b.ptr, channelID, balance)
}

// BuildPaymentHeader builds a complete X-Cashu-Channel payment header value.
// Returns a base64-encoded JSON string ready to use as the header value.
//
// If includeFunding is true, the header includes params and funding_proofs
// (needed for the first request, or when the server doesn't know this channel yet).
func (b *ClientBridge) BuildPaymentHeader(channelID string, balance uint64, includeFunding bool) (string, error) {
	return clientBridgeBuildPaymentHeader(b.ptr, channelID, balance, includeFunding)
}

// GetChannelInfo returns information about a stored channel.
// Returns nil if the channel is not found.
func (b *ClientBridge) GetChannelInfo(channelID string) *ClientChannelInfo {
	return clientBridgeGetChannelInfo(b.ptr, channelID)
}

// ListChannels returns all stored channel IDs.
func (b *ClientBridge) ListChannels() []string {
	return clientBridgeListChannels(b.ptr)
}

// CloseChannel marks a channel as closed locally.
// The channel cannot accept new payments after this.
func (b *ClientBridge) CloseChannel(channelID string) {
	cID := C.CString(channelID)
	defer C.free(unsafe.Pointer(cID))
	C.spilman_client_bridge_close_channel(b.ptr, cID)
}

// DeleteChannel removes a channel from storage.
func (b *ClientBridge) DeleteChannel(channelID string) {
	cID := C.CString(channelID)
	defer C.free(unsafe.Pointer(cID))
	C.spilman_client_bridge_delete_channel(b.ptr, cID)
}

// CreateCooperativeCloseRequest creates a JSON request for cooperative closing.
func (b *ClientBridge) CreateCooperativeCloseRequest(channelID string, finalBalance uint64) (string, error) {
	return clientBridgeCreateCooperativeCloseRequest(b.ptr, channelID, finalBalance)
}

// ProcessCooperativeCloseResponse finalizes the channel closure based on server response.
func (b *ClientBridge) ProcessCooperativeCloseResponse(responseJSON string) error {
	return clientBridgeProcessCooperativeCloseResponse(b.ptr, responseJSON)
}

// --- Client Host Callbacks Implementation ---
// These are exported to C and called by the Rust client bridge via client_gateway.c

// Channel Opening (two-phase)

//export go_client_save_opening_channel
func go_client_save_opening_channel(userData unsafe.Pointer, channelID *C.char, fundingJSON *C.char) {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	host.SaveOpeningChannel(C.GoString(channelID), C.GoString(fundingJSON))
}

//export go_client_mark_channel_open
func go_client_mark_channel_open(userData unsafe.Pointer, channelID *C.char, fundingProofsJSON *C.char) {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	host.MarkChannelOpen(C.GoString(channelID), C.GoString(fundingProofsJSON))
}

//export go_client_get_channel_funding
func go_client_get_channel_funding(userData unsafe.Pointer, channelID *C.char) *C.char {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	result := host.GetChannelFunding(C.GoString(channelID))
	if result == "" {
		return nil
	}
	return C.CString(result)
}

// Payment State

//export go_client_get_payment_state
func go_client_get_payment_state(userData unsafe.Pointer, channelID *C.char) *C.char {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	result := host.GetPaymentState(C.GoString(channelID))
	if result == "" {
		return nil
	}
	return C.CString(result)
}

//export go_client_record_payment
func go_client_record_payment(userData unsafe.Pointer, channelID *C.char, stateJSON *C.char) {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	host.RecordPayment(C.GoString(channelID), C.GoString(stateJSON))
}

// Lifecycle

//export go_client_get_channel_state
func go_client_get_channel_state(userData unsafe.Pointer, channelID *C.char) *C.char {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	result := host.GetChannelState(C.GoString(channelID))
	if result == "" {
		return C.CString("open") // default
	}
	return C.CString(result)
}

//export go_client_mark_channel_closed
func go_client_mark_channel_closed(userData unsafe.Pointer, channelID *C.char) {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	host.MarkChannelClosed(C.GoString(channelID))
}

//export go_client_list_channel_ids
func go_client_list_channel_ids(userData unsafe.Pointer) *C.char {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	ids := host.ListChannelIDs()
	jsonBytes, err := json.Marshal(ids)
	if err != nil {
		return C.CString("[]")
	}
	return C.CString(string(jsonBytes))
}

//export go_client_delete_channel
func go_client_delete_channel(userData unsafe.Pointer, channelID *C.char) {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	host.DeleteChannel(C.GoString(channelID))
}

// Time

//export go_client_now_seconds
func go_client_now_seconds(userData unsafe.Pointer) C.uint64_t {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	return C.uint64_t(host.NowSeconds())
}

// Crypto

//export go_client_sign_with_tweaked_key
func go_client_sign_with_tweaked_key(userData unsafe.Pointer, signerPubkeyHex *C.char, messageHex *C.char, tweakScalarHex *C.char, responseOut **C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	resp, err := host.SignWithTweakedKey(C.GoString(signerPubkeyHex), C.GoString(messageHex), C.GoString(tweakScalarHex))
	if err != nil {
		*responseOut = C.CString(err.Error())
		return 0
	}
	*responseOut = C.CString(resp)
	return 1
}

//export go_client_compute_channel_secret
func go_client_compute_channel_secret(userData unsafe.Pointer, senderPubkeyHex *C.char, receiverPubkeyHex *C.char, responseOut **C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	resp, err := host.ComputeChannelSecret(C.GoString(senderPubkeyHex), C.GoString(receiverPubkeyHex))
	if err != nil {
		*responseOut = C.CString(err.Error())
		return 0
	}
	*responseOut = C.CString(resp)
	return 1
}

// Networking

//export go_client_call_mint_swap
func go_client_call_mint_swap(userData unsafe.Pointer, mintURL *C.char, swapRequestJSON *C.char, responseOut **C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	resp, err := host.CallMintSwap(C.GoString(mintURL), C.GoString(swapRequestJSON))
	if err != nil {
		*responseOut = C.CString(err.Error())
		return 0
	}
	*responseOut = C.CString(resp)
	return 1
}

//export go_client_call_mint_restore
func go_client_call_mint_restore(userData unsafe.Pointer, mintURL *C.char, restoreRequestJSON *C.char, responseOut **C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanClientHost)
	resp, err := host.CallMintRestore(C.GoString(mintURL), C.GoString(restoreRequestJSON))
	if err != nil {
		*responseOut = C.CString(err.Error())
		return 0
	}
	*responseOut = C.CString(resp)
	return 1
}
