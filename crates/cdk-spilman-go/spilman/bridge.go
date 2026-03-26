// Package spilman provides Go bindings for Spilman payment channels.
//
// Spilman channels are unidirectional payment channels for Cashu ecash.
// This package provides both server-side (Bridge) and client-side functions.
//
// For server implementation, create a type that implements SpilmanHost,
// then use NewBridge to create a Bridge instance.
//
// For client implementation, use the utility functions like GenerateKeypair,
// ComputeChannelSecret, and CreateSignedBalanceUpdate.
package spilman

// CGO LDFLAGS are defined in platform-specific files:
// - cgo_linux_amd64.go, cgo_linux_arm64.go
// - cgo_darwin_amd64.go, cgo_darwin_arm64.go
// - cgo_windows_amd64.go
// - cgo_dev.go (for development builds with -tags spilman_dev)

/*
#include <stdlib.h>
#include <stdint.h>

typedef struct {
    char* data;
    char* error;
} CResult;

typedef struct {
    void* user_data;
    int (*receiver_key_is_acceptable)(void*, const char*);
    int (*mint_and_keyset_is_acceptable)(void*, const char*, const char*);
    int (*get_funding_and_params)(void*, const char*, char**, char**, char**, char**);
    void (*save_funding)(void*, const char*, const char*, const char*, const char*, const char*, uint64_t, const char*);
    uint64_t (*get_amount_due)(void*, const char*, const char*);
    void (*record_payment)(void*, const char*, uint64_t, const char*, const char*);
    char* (*get_channel_state)(void*, const char*);
    int (*mark_channel_closing)(void*, const char*, uint64_t, uint64_t, const char*);
    int (*get_closing_data)(void*, const char*, uint64_t*, uint64_t*, char**);
    int (*get_channel_policy)(void*, const char*, uint64_t*, uint64_t*, int64_t*);
    uint64_t (*now_seconds)(void*);
    int (*get_balance_and_signature_for_unilateral_exit)(void*, const char*, uint64_t*, char**);
    char* (*get_active_keyset_ids)(void*, const char*, const char*);
    char* (*get_keyset_info)(void*, const char*, const char*);
    int (*call_mint_swap)(void*, const char*, const char*, char**);
    int (*refresh_all_keysets)(void*, const char*);
    int (*compute_channel_secret)(void*, const char*, const char*, char**);
    int (*sign_with_tweaked_key)(void*, const char*, const char*, const char*, char**);
    int (*mark_channel_closed)(void*, const char*, uint64_t, uint64_t, const char*, const char*, uint64_t, uint64_t);
} SpilmanHostCallbacks;

// Function declarations from gateway.c and Rust
SpilmanHostCallbacks fill_callbacks(void* user_data);
void* spilman_bridge_new(SpilmanHostCallbacks callbacks);
void spilman_bridge_free(void* ptr);
CResult spilman_bridge_process_payment(void* ptr, const char* payment_json, const char* context_json);
CResult spilman_bridge_validate_payment(void* ptr, const char* payment_json, const char* context_json);
CResult spilman_bridge_fund_channel(void* ptr, const char* payment_json);
CResult spilman_bridge_validate_and_prepare_cooperative_close(void* ptr, const char* payment_json);
CResult spilman_bridge_create_unilateral_close_data(void* ptr, const char* channel_id);
CResult spilman_bridge_execute_cooperative_close(void* ptr, const char* payment_json);
CResult spilman_bridge_execute_unilateral_close(void* ptr, const char* channel_id);
void spilman_free_string(char* ptr);
void spilman_free_cresult(CResult res);
*/
import "C"
import (
	"encoding/json"
	"errors"
	"runtime/cgo"
	"unsafe"
)

// Bridge is the main entry point for server-side Spilman channel operations.
// It wraps the Rust implementation and delegates policy decisions to a SpilmanHost.
type Bridge struct {
	ptr    unsafe.Pointer
	handle cgo.Handle
	freed  bool
}

// NewBridge creates a new Bridge with the given host implementation.
// The host must implement ComputeChannelSecret and SignWithTweakedKey
// for cryptographic operations (the bridge no longer holds the secret key).
func NewBridge(host SpilmanHost) *Bridge {
	handle := cgo.NewHandle(host)
	// Convert cgo.Handle to void* for C callback struct.
	// cgo.Handle is a uintptr type. We pass it to C as a void* (user_data),
	// and recover it in gateway.c callbacks via cgo.Handle(uintptr(user_data)).
	//
	// go vet reports "possible misuse of unsafe.Pointer" here, but this is a
	// false positive. This is the documented pattern for passing cgo.Handle
	// to C code (see: https://pkg.go.dev/runtime/cgo#Handle).
	// The warning cannot be suppressed with directives.
	callbacks := C.fill_callbacks(unsafe.Pointer(handle)) //nolint:govet

	ptr := C.spilman_bridge_new(callbacks)
	return &Bridge{ptr: ptr, handle: handle}
}

// Free releases the resources held by the Bridge.
// Must be called when the Bridge is no longer needed.
// Safe to call multiple times.
func (b *Bridge) Free() {
	if b.freed {
		return
	}
	b.freed = true
	if b.ptr != nil {
		C.spilman_bridge_free(b.ptr)
		b.ptr = nil
	}
	b.handle.Delete()
}

// ProcessPayment validates a payment and records usage.
// Returns PaymentSuccess on success, error on failure.
func (b *Bridge) ProcessPayment(paymentJson, contextJson string) (*PaymentSuccess, error) {
	cPayment := C.CString(paymentJson)
	defer C.free(unsafe.Pointer(cPayment))
	cContext := C.CString(contextJson)
	defer C.free(unsafe.Pointer(cContext))

	res := C.spilman_bridge_process_payment(b.ptr, cPayment, cContext)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return nil, errors.New(C.GoString(res.error))
	}

	var result PaymentSuccess
	if err := json.Unmarshal([]byte(C.GoString(res.data)), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ValidatePayment validates a payment without recording it.
// Performs all validation (parsing, channel verification, balance checks,
// signature verification) but does NOT call RecordPayment.
// For new channels, funding data IS saved (idempotent).
// Returns PaymentValidationResult on success, error on failure.
func (b *Bridge) ValidatePayment(paymentJson, contextJson string) (*PaymentValidationResult, error) {
	cPayment := C.CString(paymentJson)
	defer C.free(unsafe.Pointer(cPayment))
	cContext := C.CString(contextJson)
	defer C.free(unsafe.Pointer(cContext))

	res := C.spilman_bridge_validate_payment(b.ptr, cPayment, cContext)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return nil, errors.New(C.GoString(res.error))
	}

	var result PaymentValidationResult
	if err := json.Unmarshal([]byte(C.GoString(res.data)), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// VerifyPaymentCoversAmountDue validates a payment and returns the computed amount_due.
// It does NOT record usage, but may save funding data for new channels (same as ValidatePayment).
func (b *Bridge) VerifyPaymentCoversAmountDue(paymentJson, contextJson string) (uint64, error) {
	result, err := b.ValidatePayment(paymentJson, contextJson)
	if err != nil {
		return 0, err
	}
	return result.AmountDue, nil
}

// PaymentCoversAmountDue returns true if the payment covers the current amount due.
// Returns false only for insufficient balance. Other validation errors are returned.
func (b *Bridge) PaymentCoversAmountDue(paymentJson, contextJson string) (bool, error) {
	_, err := b.ValidatePayment(paymentJson, contextJson)
	if err == nil {
		return true, nil
	}
	if isInsufficientBalance(err) {
		return false, nil
	}
	return false, err
}

func isInsufficientBalance(err error) bool {
	var info struct {
		Code string `json:"code"`
	}
	if json.Unmarshal([]byte(err.Error()), &info) == nil && info.Code == "insufficient_balance" {
		return true
	}
	return false
}

// FundChannel registers/funds a channel without recording any usage.
// Validates the channel (params, funding proofs, signature for balance=0)
// and saves it to the funding store, but does NOT record any payment/usage.
// Returns FundChannelResult on success, error on failure.
func (b *Bridge) FundChannel(paymentJson string) (*FundChannelResult, error) {
	cPayment := C.CString(paymentJson)
	defer C.free(unsafe.Pointer(cPayment))

	res := C.spilman_bridge_fund_channel(b.ptr, cPayment)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return nil, errors.New(C.GoString(res.error))
	}

	var result FundChannelResult
	if err := json.Unmarshal([]byte(C.GoString(res.data)), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ValidateAndPrepareCooperativeClose validates a close request and prepares for swap.
// Returns the close data as JSON on success.
func (b *Bridge) ValidateAndPrepareCooperativeClose(paymentJson string) (string, error) {
	cPayment := C.CString(paymentJson)
	defer C.free(unsafe.Pointer(cPayment))

	res := C.spilman_bridge_validate_and_prepare_cooperative_close(b.ptr, cPayment)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// CreateUnilateralCloseData creates close data for a server-initiated close.
// Returns the close data as JSON on success.
func (b *Bridge) CreateUnilateralCloseData(channelId string) (string, error) {
	cId := C.CString(channelId)
	defer C.free(unsafe.Pointer(cId))

	res := C.spilman_bridge_create_unilateral_close_data(b.ptr, cId)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// ExecuteCooperativeClose orchestrates the full cooperative close flow:
// validate, submit swap to mint, retry on error, unblind, and mark closed.
// Returns CloseSuccess on success, error (with JSON-encoded CloseError) on failure.
func (b *Bridge) ExecuteCooperativeClose(paymentJson string) (*CloseSuccess, error) {
	cPayment := C.CString(paymentJson)
	defer C.free(unsafe.Pointer(cPayment))

	res := C.spilman_bridge_execute_cooperative_close(b.ptr, cPayment)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return nil, errors.New(C.GoString(res.error))
	}

	var result CloseSuccess
	if err := json.Unmarshal([]byte(C.GoString(res.data)), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ExecuteUnilateralClose orchestrates the full unilateral close flow:
// retrieve stored payment, submit swap to mint, retry on error, unblind, and mark closed.
// Returns CloseSuccess on success, error (with JSON-encoded CloseError) on failure.
func (b *Bridge) ExecuteUnilateralClose(channelId string) (*CloseSuccess, error) {
	cId := C.CString(channelId)
	defer C.free(unsafe.Pointer(cId))

	res := C.spilman_bridge_execute_unilateral_close(b.ptr, cId)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return nil, errors.New(C.GoString(res.error))
	}

	var result CloseSuccess
	if err := json.Unmarshal([]byte(C.GoString(res.data)), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// --- Callbacks Implementation ---
// These are exported to C and called by the Rust bridge via gateway.c

//export go_receiver_key_is_acceptable
func go_receiver_key_is_acceptable(userData unsafe.Pointer, pubkeyHex *C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	if host.ReceiverKeyIsAcceptable(C.GoString(pubkeyHex)) {
		return 1
	}
	return 0
}

//export go_mint_and_keyset_is_acceptable
func go_mint_and_keyset_is_acceptable(userData unsafe.Pointer, mint *C.char, keysetId *C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	if host.MintAndKeysetIsAcceptable(C.GoString(mint), C.GoString(keysetId)) {
		return 1
	}
	return 0
}

//export go_get_funding_and_params
func go_get_funding_and_params(userData unsafe.Pointer, channelId *C.char, paramsOut **C.char, proofsOut **C.char, secretOut **C.char, keysetOut **C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	p, pr, s, k, ok := host.GetFundingAndParams(C.GoString(channelId))
	if !ok {
		return 0
	}
	*paramsOut = C.CString(p)
	*proofsOut = C.CString(pr)
	*secretOut = C.CString(s)
	*keysetOut = C.CString(k)
	return 1
}

//export go_save_funding
func go_save_funding(userData unsafe.Pointer, channelId *C.char, paramsJson *C.char, fundingProofsJson *C.char, channelSecretHex *C.char, keysetInfoJson *C.char, initialBalance C.uint64_t, initialSignature *C.char) {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	host.SaveFunding(C.GoString(channelId), C.GoString(paramsJson), C.GoString(fundingProofsJson), C.GoString(channelSecretHex), C.GoString(keysetInfoJson), uint64(initialBalance), C.GoString(initialSignature))
}

//export go_get_amount_due
func go_get_amount_due(userData unsafe.Pointer, channelId *C.char, contextJson *C.char) C.uint64_t {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	var ctx *string
	if contextJson != nil {
		s := C.GoString(contextJson)
		ctx = &s
	}
	return C.uint64_t(host.GetAmountDue(C.GoString(channelId), ctx))
}

//export go_record_payment
func go_record_payment(userData unsafe.Pointer, channelId *C.char, balance C.uint64_t, signature *C.char, contextJson *C.char) {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	host.RecordPayment(C.GoString(channelId), uint64(balance), C.GoString(signature), C.GoString(contextJson))
}

//export go_get_channel_state
func go_get_channel_state(userData unsafe.Pointer, channelId *C.char) *C.char {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	return C.CString(host.GetChannelState(C.GoString(channelId)))
}

//export go_mark_channel_closing
func go_mark_channel_closing(userData unsafe.Pointer, channelId *C.char, expiryTimestamp C.uint64_t, balance C.uint64_t, signature *C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	err := host.MarkChannelClosing(C.GoString(channelId), uint64(expiryTimestamp), uint64(balance), C.GoString(signature))
	if err != nil {
		return 0
	}
	return 1
}

//export go_get_closing_data
func go_get_closing_data(userData unsafe.Pointer, channelId *C.char, expiryTimestampOut *C.uint64_t, balanceOut *C.uint64_t, signatureOut **C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	data := host.GetClosingData(C.GoString(channelId))
	if data == nil {
		return 0
	}
	*expiryTimestampOut = C.uint64_t(data.ExpiryTimestamp)
	*balanceOut = C.uint64_t(data.Balance)
	*signatureOut = C.CString(data.Signature)
	return 1
}

//export go_get_channel_policy
func go_get_channel_policy(userData unsafe.Pointer, unit *C.char, minExpiryOut *C.uint64_t, minCapacityOut *C.uint64_t, maxAmountOut *C.int64_t) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	policy := host.GetChannelPolicy(C.GoString(unit))
	if policy == nil {
		return 0
	}
	*minExpiryOut = C.uint64_t(policy.MinExpiryInSeconds)
	*minCapacityOut = C.uint64_t(policy.MinCapacity)
	if policy.MaxAmountPerOutput != nil {
		*maxAmountOut = C.int64_t(*policy.MaxAmountPerOutput)
	} else {
		*maxAmountOut = -1
	}
	return 1
}

//export go_now_seconds
func go_now_seconds(userData unsafe.Pointer) C.uint64_t {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	return C.uint64_t(host.NowSeconds())
}

//export go_get_balance_and_signature_for_unilateral_exit
func go_get_balance_and_signature_for_unilateral_exit(userData unsafe.Pointer, channelId *C.char, balanceOut *C.uint64_t, signatureOut **C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	balance, signature, ok := host.GetBalanceAndSignatureForUnilateralExit(C.GoString(channelId))
	if !ok {
		return 0
	}
	*balanceOut = C.uint64_t(balance)
	*signatureOut = C.CString(signature)
	return 1
}

//export go_get_active_keyset_ids
func go_get_active_keyset_ids(userData unsafe.Pointer, mint *C.char, unit *C.char) *C.char {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	ids := host.GetActiveKeysetIds(C.GoString(mint), C.GoString(unit))
	jsonBytes, _ := json.Marshal(ids)
	return C.CString(string(jsonBytes))
}

//export go_get_keyset_info
func go_get_keyset_info(userData unsafe.Pointer, mint *C.char, keysetId *C.char) *C.char {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	info, ok := host.GetKeysetInfo(C.GoString(mint), C.GoString(keysetId))
	if !ok {
		return nil
	}
	return C.CString(info)
}

//export go_call_mint_swap
func go_call_mint_swap(userData unsafe.Pointer, mintUrl *C.char, swapReqJson *C.char, responseOut **C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	resp, err := host.CallMintSwap(C.GoString(mintUrl), C.GoString(swapReqJson))
	if err != nil {
		*responseOut = C.CString(err.Error())
		return 0
	}
	*responseOut = C.CString(resp)
	return 1
}

//export go_refresh_all_keysets
func go_refresh_all_keysets(userData unsafe.Pointer, mintUrl *C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	err := host.RefreshAllKeysets(C.GoString(mintUrl))
	if err != nil {
		return 0
	}
	return 1
}

//export go_mark_channel_closed
func go_mark_channel_closed(userData unsafe.Pointer, channelId *C.char, expiryTimestamp C.uint64_t, balance C.uint64_t, receiverProofsJson *C.char, senderProofsJson *C.char, receiverSum C.uint64_t, senderSum C.uint64_t) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	err := host.MarkChannelClosed(
		C.GoString(channelId),
		uint64(expiryTimestamp),
		uint64(balance),
		C.GoString(receiverProofsJson),
		C.GoString(senderProofsJson),
		uint64(receiverSum),
		uint64(senderSum),
	)
	if err != nil {
		return 0
	}
	return 1
}

//export go_compute_channel_secret
func go_compute_channel_secret(userData unsafe.Pointer, receiverPubkeyHex *C.char, senderPubkeyHex *C.char, resultOut **C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	result, err := host.ComputeChannelSecret(C.GoString(senderPubkeyHex), C.GoString(receiverPubkeyHex))
	if err != nil {
		*resultOut = C.CString(err.Error())
		return 0
	}
	*resultOut = C.CString(result)
	return 1
}

//export go_sign_with_tweaked_key
func go_sign_with_tweaked_key(userData unsafe.Pointer, signerPubkeyHex *C.char, messageHex *C.char, tweakScalarHex *C.char, resultOut **C.char) C.int {
	h := cgo.Handle(userData)
	host := h.Value().(SpilmanHost)
	result, err := host.SignWithTweakedKey(C.GoString(signerPubkeyHex), C.GoString(messageHex), C.GoString(tweakScalarHex))
	if err != nil {
		*resultOut = C.CString(err.Error())
		return 0
	}
	*resultOut = C.CString(result)
	return 1
}
