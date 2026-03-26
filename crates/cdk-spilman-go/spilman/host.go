package spilman

// SpilmanHost is the interface that the Go application must implement to handle
// channel persistence and policy decisions.
//
// The bridge calls these methods to:
// - Validate incoming requests (ReceiverKeyIsAcceptable, MintAndKeysetIsAcceptable)
// - Store and retrieve channel data (GetFundingAndParams, SaveFunding, etc.)
// - Determine pricing (GetAmountDue, GetChannelPolicy)
// - Communicate with the mint (CallMintSwap, RefreshAllKeysets)
// - Track channel lifecycle (GetChannelState, MarkChannelClosing, MarkChannelClosed)
type SpilmanHost interface {
	// ReceiverKeyIsAcceptable returns true if the given receiver public key is acceptable.
	// Typically, you would check if the pubkey matches your server's expected receiver key.
	ReceiverKeyIsAcceptable(pubkeyHex string) bool

	// MintAndKeysetIsAcceptable returns true if the given mint URL and keyset ID are acceptable.
	// Use this to restrict which mints and keysets your server will accept payments from.
	MintAndKeysetIsAcceptable(mint string, keysetId string) bool

	// GetFundingAndParams retrieves stored channel data for an existing channel.
	// Returns (paramsJson, proofsJson, channelSecretHex, keysetInfoJson, true) if found,
	// or ("", "", "", "", false) if the channel is not known.
	GetFundingAndParams(channelId string) (paramsJson, proofsJson, channelSecretHex, keysetInfoJson string, ok bool)

	// SaveFunding stores channel data when a new channel is registered.
	// Called after validating the initial funding (balance=0 signature).
	SaveFunding(channelId, paramsJson, proofsJson, channelSecretHex, keysetInfoJson string, initialBalance uint64, initialSignature string)

	// GetAmountDue returns the amount owed for a request on the given channel.
	// contextJson contains request-specific data (e.g., the requested resource).
	// This is where you implement your pricing logic.
	GetAmountDue(channelId string, contextJson *string) uint64

	// RecordPayment is called after a payment is validated and accepted.
	// Store the new balance and signature for potential unilateral close.
	RecordPayment(channelId string, balance uint64, signature, contextJson string)

	// GetChannelState returns the current state of a channel.
	// Must return one of: "open", "closing", or "closed".
	GetChannelState(channelId string) string

	// MarkChannelClosing marks a channel as being in the CLOSING state (pre-swap).
	// This is called when a cooperative close is initiated but before the swap completes.
	MarkChannelClosing(channelId string, expiryTimestamp, balance uint64, signature string) error

	// GetClosingData returns the closing data for a channel in CLOSING state.
	// Returns nil if the channel is not in CLOSING state.
	GetClosingData(channelId string) *ClosingData

	// GetChannelPolicy returns the channel policy for a given unit.
	// Returns nil if the unit is not supported.
	GetChannelPolicy(unit string) *ChannelPolicy

	// NowSeconds returns the current Unix timestamp in seconds.
	// Used for expiry timestamp validation.
	NowSeconds() uint64

	// GetBalanceAndSignatureForUnilateralExit retrieves the last recorded payment
	// for unilateral close. Returns (balance, signature, true) if available.
	GetBalanceAndSignatureForUnilateralExit(channelId string) (balance uint64, signature string, ok bool)

	// GetActiveKeysetIds returns the active keyset IDs for the given mint and unit.
	// Used to validate that incoming payments use acceptable keysets.
	GetActiveKeysetIds(mint, unit string) []string

	// GetKeysetInfo returns the keyset info JSON for the given mint and keyset ID.
	// Returns ("", false) if the keyset is not known.
	GetKeysetInfo(mint, keysetId string) (string, bool)

	// CallMintSwap submits a swap request to the mint and returns the response.
	// This is called during channel close to exchange the channel proofs for new proofs.
	CallMintSwap(mintUrl, swapRequestJson string) (string, error)

	// RefreshAllKeysets re-fetches ALL keysets (active and inactive) from the mint.
	// Called when a swap fails, possibly due to stale keyset data.
	// The host should retain inactive keyset data because existing channels
	// may have been funded with a now-deactivated keyset.
	RefreshAllKeysets(mintUrl string) error

	// MarkChannelClosed marks a channel as fully CLOSED after a successful swap.
	// Called with the final proof distribution for record-keeping.
	MarkChannelClosed(channelId string, expiryTimestamp, balance uint64, receiverProofsJson, senderProofsJson string, receiverSum, senderSum uint64) error

	// ComputeChannelSecret computes the hashed ECDH channel secret.
	//
	// The host performs ECDH between the receiver's secret key (identified by
	// receiverPubkeyHex) and the sender's public key, then hashes the result:
	//   SHA256("Cashu_Spilman_channel_secret_v1" || ECDH(receiver_secret, sender_pubkey))
	//
	// For hosts that hold raw secret keys, use the standalone ComputeChannelSecret()
	// function (wraps the Rust utility).
	//
	// Returns the hashed channel secret as a 64-char hex string (32 bytes).
	ComputeChannelSecret(senderPubkeyHex, receiverPubkeyHex string) (string, error)

	// SignWithTweakedKey signs a message with a tweaked key (BIP-340 Schnorr).
	//
	// The bridge computes the tweak (P2BK blinding scalar) and message hash,
	// then asks the host to produce a signature using (secret + tweak) where
	// secret is the key corresponding to signerPubkeyHex.
	//
	// For hosts that hold raw secret keys, use SignWithTweakedKeyUtil() as
	// a convenience implementation.
	//
	// Arguments:
	//   signerPubkeyHex: identifies which key to use (receiver pubkey for server-side)
	//   messageHex: SHA-256 hash of the SIG_ALL message (32 bytes, hex)
	//   tweakScalarHex: P2BK blinding scalar to add to secret key (32 bytes, hex)
	//
	// Returns the BIP-340 Schnorr signature (64 bytes, hex).
	SignWithTweakedKey(signerPubkeyHex, messageHex, tweakScalarHex string) (string, error)
}

// ChannelPolicy holds the funding-time validation thresholds for a given unit.
type ChannelPolicy struct {
	MinExpiryInSeconds uint64
	MinCapacity        uint64
	MaxAmountPerOutput *uint64 // nil means no limit
}

// ClosingData holds the pre-swap state for a channel in CLOSING state.
// This is used to resume a close operation if the initial swap attempt failed.
type ClosingData struct {
	ExpiryTimestamp uint64
	Balance         uint64
	Signature       string
}
