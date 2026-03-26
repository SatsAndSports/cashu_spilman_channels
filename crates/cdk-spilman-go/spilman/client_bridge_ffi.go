package spilman

// This file provides Go wrappers for client bridge FFI functions that return CResult.
// CResult is defined in bridge.go's CGO preamble, so we declare the function prototypes
// here alongside the CResult type to avoid duplicate type definitions across files.

/*
#include <stdlib.h>
#include <stdint.h>

typedef struct {
    char* data;
    char* error;
} CResult;

// Client bridge FFI functions that return CResult
CResult spilman_client_bridge_open_channel_from_token(void* ptr, const char* token, const char* receiver_pubkey, const char* sender_pubkey, uint64_t expiry_timestamp, const char* keyset_info, uint64_t max_amount);
CResult spilman_client_bridge_sign_balance_update(void* ptr, const char* channel_id, uint64_t balance);
CResult spilman_client_bridge_build_payment_header(void* ptr, const char* channel_id, uint64_t balance, int include_funding);
CResult spilman_client_bridge_get_channel_info(void* ptr, const char* channel_id);
CResult spilman_client_bridge_list_channels(void* ptr);
CResult spilman_client_bridge_create_cooperative_close_request(void* ptr, const char* channel_id, uint64_t final_balance);
CResult spilman_client_bridge_process_cooperative_close_response(void* ptr, const char* response_json);
CResult spilman_sign_with_tweaked_key_util(const char* secret_key_hex, const char* message_hex, const char* tweak_scalar_hex);
void spilman_free_cresult(CResult res);
*/
import "C"
import (
	"encoding/json"
	"errors"
	"unsafe"
)

// clientBridgeOpenChannel calls the Rust FFI and returns the parsed result.
func clientBridgeOpenChannel(ptr unsafe.Pointer, token, receiverPubkeyHex, senderPubkeyHex string, expiryTimestamp uint64, keysetInfoJSON string, maxAmount uint64) (*OpenChannelResult, error) {
	cToken := C.CString(token)
	defer C.free(unsafe.Pointer(cToken))
	cCharlie := C.CString(receiverPubkeyHex)
	defer C.free(unsafe.Pointer(cCharlie))
	cAlice := C.CString(senderPubkeyHex)
	defer C.free(unsafe.Pointer(cAlice))
	cKeyset := C.CString(keysetInfoJSON)
	defer C.free(unsafe.Pointer(cKeyset))

	res := C.spilman_client_bridge_open_channel_from_token(
		ptr, cToken, cCharlie, cAlice, C.uint64_t(expiryTimestamp), cKeyset, C.uint64_t(maxAmount))
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return nil, errors.New(C.GoString(res.error))
	}

	var result OpenChannelResult
	if err := json.Unmarshal([]byte(C.GoString(res.data)), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// clientBridgeSignBalanceUpdate calls the Rust FFI and returns the JSON result.
func clientBridgeSignBalanceUpdate(ptr unsafe.Pointer, channelID string, balance uint64) (string, error) {
	cID := C.CString(channelID)
	defer C.free(unsafe.Pointer(cID))

	res := C.spilman_client_bridge_sign_balance_update(ptr, cID, C.uint64_t(balance))
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// clientBridgeBuildPaymentHeader calls the Rust FFI and returns the base64 header.
func clientBridgeBuildPaymentHeader(ptr unsafe.Pointer, channelID string, balance uint64, includeFunding bool) (string, error) {
	cID := C.CString(channelID)
	defer C.free(unsafe.Pointer(cID))

	var cInclude C.int
	if includeFunding {
		cInclude = 1
	}

	res := C.spilman_client_bridge_build_payment_header(ptr, cID, C.uint64_t(balance), cInclude)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// clientBridgeGetChannelInfo calls the Rust FFI and returns parsed channel info.
func clientBridgeGetChannelInfo(ptr unsafe.Pointer, channelID string) *ClientChannelInfo {
	cID := C.CString(channelID)
	defer C.free(unsafe.Pointer(cID))

	res := C.spilman_client_bridge_get_channel_info(ptr, cID)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return nil
	}

	var info ClientChannelInfo
	if err := json.Unmarshal([]byte(C.GoString(res.data)), &info); err != nil {
		return nil
	}
	return &info
}

// clientBridgeListChannels calls the Rust FFI and returns the channel ID list.
func clientBridgeListChannels(ptr unsafe.Pointer) []string {
	res := C.spilman_client_bridge_list_channels(ptr)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return nil
	}

	var channels []string
	if err := json.Unmarshal([]byte(C.GoString(res.data)), &channels); err != nil {
		return nil
	}
	return channels
}

// clientBridgeCreateCooperativeCloseRequest calls the Rust FFI and returns the JSON request.
func clientBridgeCreateCooperativeCloseRequest(ptr unsafe.Pointer, channelID string, finalBalance uint64) (string, error) {
	cID := C.CString(channelID)
	defer C.free(unsafe.Pointer(cID))

	res := C.spilman_client_bridge_create_cooperative_close_request(ptr, cID, C.uint64_t(finalBalance))
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// clientBridgeProcessCooperativeCloseResponse calls the Rust FFI to finalize the channel closure.
func clientBridgeProcessCooperativeCloseResponse(ptr unsafe.Pointer, responseJSON string) error {
	cRes := C.CString(responseJSON)
	defer C.free(unsafe.Pointer(cRes))

	res := C.spilman_client_bridge_process_cooperative_close_response(ptr, cRes)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return errors.New(C.GoString(res.error))
	}
	return nil
}

// SignWithTweakedKeyUtil is a convenience function for SpilmanClientHost implementations.
//
// Given a secret key, message hash, and tweak scalar, computes (secret + tweak)
// with BIP-340 parity handling and produces a BIP-340 Schnorr signature.
//
// Hosts that hold raw secret keys can call this from their SignWithTweakedKey method.
func SignWithTweakedKeyUtil(secretKeyHex, messageHex, tweakScalarHex string) (string, error) {
	cSecret := C.CString(secretKeyHex)
	defer C.free(unsafe.Pointer(cSecret))
	cMsg := C.CString(messageHex)
	defer C.free(unsafe.Pointer(cMsg))
	cTweak := C.CString(tweakScalarHex)
	defer C.free(unsafe.Pointer(cTweak))

	res := C.spilman_sign_with_tweaked_key_util(cSecret, cMsg, cTweak)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}
