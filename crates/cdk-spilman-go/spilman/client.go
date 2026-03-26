package spilman

// Client utility functions for Spilman payment channels.
// These functions are used by clients (senders) to:
// - Generate keypairs for channel funding
// - Compute shared secrets for deterministic blinding
// - Create and sign balance updates
// - Construct proofs from mint responses

/*
#include <stdlib.h>
#include <stdint.h>

typedef struct {
    char* data;
    char* error;
} CResult;

// Client function declarations from Rust FFI
CResult spilman_generate_keypair();
CResult spilman_secret_key_to_pubkey(const char* secret_hex);
CResult spilman_compute_channel_secret(const char* my_secret_hex, const char* their_pubkey_hex);
CResult spilman_compute_funding_token_amount(uint64_t capacity, const char* keyset_info_json, uint64_t maximum_amount);
CResult spilman_create_signed_balance_update(const char* params, const char* keyset, const char* secret, const char* proofs, uint64_t balance);
CResult spilman_channel_parameters_get_channel_id(const char* params, const char* channel_secret, const char* keyset);
CResult spilman_create_plain_blinded_messages(uint64_t amount_sat, const char* keyset_info_json);
CResult spilman_create_funding_outputs(const char* params, const char* alice_secret, const char* keyset);
CResult spilman_construct_proofs(const char* blind_signatures, const char* secrets_with_blinding, const char* keyset);
CResult spilman_build_cashu_a_token(const char* mint_url, const char* proofs_json);

typedef char* (*http_callback_fn)(void*, const char*, const char*, const char*, char**);
CResult spilman_mint_proofs_from_mint(const char* mint_url, uint64_t amount_sat, const char* keyset_info_json, http_callback_fn call_http, void* user_data);
void spilman_free_cresult(CResult res);

// Go export for HTTP callback - gateway through C
extern char* go_mint_http_callback(void* user_data, const char* method, const char* url, const char* body, char** response_out);

static inline CResult call_mint_proofs(const char* mint_url, uint64_t amount_sat, const char* keyset_info_json, void* user_data) {
    return spilman_mint_proofs_from_mint(mint_url, amount_sat, keyset_info_json, go_mint_http_callback, user_data);
}
*/
import "C"
import (
	"encoding/json"
	"errors"
	"runtime/cgo"
	"unsafe"
)

// GenerateKeypair generates a new secp256k1 keypair for channel funding.
// Returns the secret key and public key as hex strings.
func GenerateKeypair() (secret, pubkey string, err error) {
	res := C.spilman_generate_keypair()
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", "", errors.New(C.GoString(res.error))
	}

	var data struct {
		Secret string `json:"secret"`
		Pubkey string `json:"pubkey"`
	}
	if err := json.Unmarshal([]byte(C.GoString(res.data)), &data); err != nil {
		return "", "", err
	}
	return data.Secret, data.Pubkey, nil
}

// SecretKeyToPubkey derives the public key from a secret key.
// Both are hex-encoded strings.
func SecretKeyToPubkey(secretHex string) (string, error) {
	cSecret := C.CString(secretHex)
	defer C.free(unsafe.Pointer(cSecret))

	res := C.spilman_secret_key_to_pubkey(cSecret)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// ComputeChannelSecret computes the ECDH shared secret between two parties.
// Used for deterministic blinding in P2BK (Pay-to-Blinded-Key) outputs.
func ComputeChannelSecret(mySecretHex, theirPubkeyHex string) (string, error) {
	cSecret := C.CString(mySecretHex)
	defer C.free(unsafe.Pointer(cSecret))
	cPubkey := C.CString(theirPubkeyHex)
	defer C.free(unsafe.Pointer(cPubkey))

	res := C.spilman_compute_channel_secret(cSecret, cPubkey)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// ComputeFundingTokenAmount computes the minimum funding_token_amount needed for a given capacity.
// Uses the double-inverse computation to determine the minimum funding token
// nominal value that will yield at least `capacity` after both fee stages.
func ComputeFundingTokenAmount(capacity uint64, keysetInfoJson string, maximumAmount uint64) (uint64, error) {
	cKeyset := C.CString(keysetInfoJson)
	defer C.free(unsafe.Pointer(cKeyset))

	res := C.spilman_compute_funding_token_amount(C.uint64_t(capacity), cKeyset, C.uint64_t(maximumAmount))
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return 0, errors.New(C.GoString(res.error))
	}

	var amount uint64
	if err := json.Unmarshal([]byte(C.GoString(res.data)), &amount); err != nil {
		return 0, err
	}
	return amount, nil
}

// CreateSignedBalanceUpdate creates a signed balance update for payment.
// The signature commits to the new balance and allows the receiver to claim funds.
func CreateSignedBalanceUpdate(params, keyset, secret, proofs string, balance uint64) (string, error) {
	cParams := C.CString(params)
	defer C.free(unsafe.Pointer(cParams))
	cKeyset := C.CString(keyset)
	defer C.free(unsafe.Pointer(cKeyset))
	cSecret := C.CString(secret)
	defer C.free(unsafe.Pointer(cSecret))
	cProofs := C.CString(proofs)
	defer C.free(unsafe.Pointer(cProofs))

	res := C.spilman_create_signed_balance_update(cParams, cKeyset, cSecret, cProofs, C.uint64_t(balance))
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// ChannelParametersGetChannelId computes the channel ID from parameters.
// The channel ID uniquely identifies a channel based on its parameters and shared secret.
func ChannelParametersGetChannelId(params, channelSecret, keyset string) (string, error) {
	cParams := C.CString(params)
	defer C.free(unsafe.Pointer(cParams))
	cSecret := C.CString(channelSecret)
	defer C.free(unsafe.Pointer(cSecret))
	cKeyset := C.CString(keyset)
	defer C.free(unsafe.Pointer(cKeyset))

	res := C.spilman_channel_parameters_get_channel_id(cParams, cSecret, cKeyset)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// CreatePlainBlindedMessages creates plain (non-P2PK) blinded messages for a given amount.
// These are standard blinded messages with random secrets, suitable for minting
// via /v1/mint/bolt11. The resulting proofs can then be wrapped in a Cashu token
// and passed to ClientBridge.OpenChannelFromToken for funding.
//
// Returns JSON with:
//   - blinded_messages: Array of blinded messages (ready for mint request)
//   - secrets_with_blinding: Array of {secret, blinding_factor, amount} for unblinding later
func CreatePlainBlindedMessages(amountSat uint64, keysetInfoJson string) (string, error) {
	cKeyset := C.CString(keysetInfoJson)
	defer C.free(unsafe.Pointer(cKeyset))

	res := C.spilman_create_plain_blinded_messages(C.uint64_t(amountSat), cKeyset)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// CreateFundingOutputs creates the blinded outputs for channel funding.
// These outputs are sent to the mint for signing during the swap that funds the channel.
func CreateFundingOutputs(params, aliceSecret, keyset string) (string, error) {
	cParams := C.CString(params)
	defer C.free(unsafe.Pointer(cParams))
	cSecret := C.CString(aliceSecret)
	defer C.free(unsafe.Pointer(cSecret))
	cKeyset := C.CString(keyset)
	defer C.free(unsafe.Pointer(cKeyset))

	res := C.spilman_create_funding_outputs(cParams, cSecret, cKeyset)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// ConstructProofs constructs proofs from blind signatures returned by the mint.
// Used to convert mint responses into spendable proofs.
func ConstructProofs(blindSignatures, secretsWithBlinding, keyset string) (string, error) {
	cSigs := C.CString(blindSignatures)
	defer C.free(unsafe.Pointer(cSigs))
	cSecrets := C.CString(secretsWithBlinding)
	defer C.free(unsafe.Pointer(cSecrets))
	cKeyset := C.CString(keyset)
	defer C.free(unsafe.Pointer(cKeyset))

	res := C.spilman_construct_proofs(cSigs, cSecrets, cKeyset)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// BuildCashuAToken builds a cashuA token string from proofs JSON and a mint URL.
// The token format is: "cashuA" + base64url({ token: [{ mint, proofs }], unit: "sat" })
func BuildCashuAToken(mintURL, proofsJSON string) (string, error) {
	cMint := C.CString(mintURL)
	defer C.free(unsafe.Pointer(cMint))
	cProofs := C.CString(proofsJSON)
	defer C.free(unsafe.Pointer(cProofs))

	res := C.spilman_build_cashu_a_token(cMint, cProofs)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}

// HTTPCallback is a function that performs HTTP requests.
// method is "GET" or "POST", url is the endpoint, body is the request body
// (empty string for GET). Returns the response body as a string.
type HTTPCallback func(method, url, body string) (string, error)

// MintProofsFromMint mints plain proofs via the mint HTTP API.
// This performs the full minting flow: create blinded messages, request a mint
// quote, poll until paid, mint tokens, and construct proofs.
//
// The callHTTP callback is used for all HTTP communication with the mint.
// This function is intended for tests and demos (especially with fakewallet).
func MintProofsFromMint(mintURL string, amountSat uint64, keysetInfoJSON string, callHTTP HTTPCallback) (string, error) {
	cMint := C.CString(mintURL)
	defer C.free(unsafe.Pointer(cMint))
	cKeyset := C.CString(keysetInfoJSON)
	defer C.free(unsafe.Pointer(cKeyset))

	handle := cgo.NewHandle(callHTTP)
	defer handle.Delete()

	res := C.call_mint_proofs(
		cMint,
		C.uint64_t(amountSat),
		cKeyset,
		//nolint:govet // cgo.Handle -> unsafe.Pointer is the documented pattern
		unsafe.Pointer(handle),
	)
	defer C.spilman_free_cresult(res)

	if res.error != nil {
		return "", errors.New(C.GoString(res.error))
	}
	return C.GoString(res.data), nil
}
