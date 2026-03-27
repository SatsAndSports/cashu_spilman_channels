package spilman

// SpilmanClientHost is the interface that client applications must implement
// to provide storage, time, crypto, and networking for the client bridge.
//
// This is the client-side counterpart of the server-side SpilmanHost interface.
// Funding data and payment state are stored separately, with payment state
// serialized as JSON.
type SpilmanClientHost interface {
	// ========================================================================
	// Funding Data (immutable after creation)
	// ========================================================================

	// SaveChannelFunding persists immutable channel funding data.
	// fundingJSON is a JSON-serialized ClientChannelFunding struct.
	SaveChannelFunding(channelID, fundingJSON string)

	// GetChannelFunding retrieves channel funding data.
	// Returns empty string if the channel doesn't exist.
	GetChannelFunding(channelID string) string

	// ========================================================================
	// Payment State (mutable)
	// ========================================================================

	// GetPaymentState retrieves the current payment state.
	// Returns empty string if no payments have been made.
	// The return value is a JSON-serialized ClientPaymentState.
	GetPaymentState(channelID string) string

	// RecordPayment stores a new payment state.
	// stateJSON is a JSON-serialized ClientPaymentState.
	RecordPayment(channelID, stateJSON string)

	// ========================================================================
	// Channel Lifecycle
	// ========================================================================

	// GetChannelState returns the lifecycle state of a channel.
	// Returns "open" or "closed".
	GetChannelState(channelID string) string

	// MarkChannelClosed marks a channel as closed.
	MarkChannelClosed(channelID string)

	// ListChannelIDs returns all stored channel IDs.
	ListChannelIDs() []string

	// DeleteChannel removes a channel and all its data.
	DeleteChannel(channelID string)

	// ========================================================================
	// Time
	// ========================================================================

	// NowSeconds returns the current Unix timestamp in seconds.
	NowSeconds() uint64

	// ========================================================================
	// Crypto (delegated to host)
	// ========================================================================

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
	//   signerPubkeyHex: identifies which key to use (sender pubkey for this channel)
	//   messageHex: SHA-256 hash of the SIG_ALL message (32 bytes, hex)
	//   tweakScalarHex: P2BK blinding scalar to add to secret key (32 bytes, hex)
	//
	// Returns the BIP-340 Schnorr signature (64 bytes, hex).
	SignWithTweakedKey(signerPubkeyHex, messageHex, tweakScalarHex string) (string, error)

	// ComputeChannelSecret computes the hashed ECDH channel secret.
	//
	// The host performs ECDH between the sender's secret key (identified by
	// senderPubkeyHex) and the receiver's public key, then hashes the result:
	//   SHA256("Cashu_Spilman_channel_secret_v1" || ECDH(sender_secret, receiver_pubkey))
	//
	// For hosts that hold raw secret keys, use ComputeChannelSecret() from
	// the standalone functions (wraps the Rust utility).
	//
	// Returns the hashed channel secret as a 64-char hex string (32 bytes).
	ComputeChannelSecret(senderPubkeyHex, receiverPubkeyHex string) (string, error)

	// ========================================================================
	// Networking
	// ========================================================================

	// CallMintSwap executes a swap with the mint.
	// Posts swapRequestJSON to {mintURL}/v1/swap and returns the response body.
	// Returns the response JSON string on success, or an error.
	CallMintSwap(mintURL, swapRequestJSON string) (string, error)
}

// OpenChannelResult contains the result of opening a new channel.
type OpenChannelResult struct {
	ChannelID          string `json:"channel_id"`
	Capacity           uint64 `json:"capacity"`
	FundingTokenAmount uint64 `json:"funding_token_amount"`
	MintURL            string `json:"mint_url"`
	SenderPubkeyHex    string `json:"sender_pubkey_hex"`
}

// ClientChannelInfo contains information about a stored channel.
type ClientChannelInfo struct {
	ChannelID          string `json:"channel_id"`
	Capacity           uint64 `json:"capacity"`
	FundingTokenAmount uint64 `json:"funding_token_amount"`
	MintURL            string `json:"mint_url"`
	CurrentBalance     uint64 `json:"current_balance"`
	PaymentCount       uint64 `json:"payment_count"`
	State              string `json:"state"` // "Open" or "Closed"
}
