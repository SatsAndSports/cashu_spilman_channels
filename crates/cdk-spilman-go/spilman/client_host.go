package spilman

// ChannelData holds channel state returned by GetChannel.
// Separates the opaque channel JSON from the sensitive channel secret.
type ChannelData struct {
	ChannelJSON      string
	ChannelSecretHex string
}

// SpilmanClientHost is the interface that client applications must implement
// to provide mint communication and channel storage for the client bridge.
//
// This is the client-side counterpart of the server-side SpilmanHost interface.
// It has only 5 methods compared to the server's 17, because clients don't need
// pricing policy, payment validation, or close orchestration.
type SpilmanClientHost interface {
	// CallMintSwap executes a swap with the mint.
	// Posts swapRequestJSON to {mintURL}/v1/swap and returns the response body.
	// Returns the response JSON string on success, or an error.
	CallMintSwap(mintURL, swapRequestJSON string) (string, error)

	// SaveChannel persists channel state.
	// The channelJSON is an opaque JSON blob managed by the bridge.
	// The channelSecretHex is the hashed ECDH secret (32 bytes, hex),
	// passed separately so the host can store it with appropriate protection.
	SaveChannel(channelID, channelJSON, channelSecretHex string)

	// GetChannel retrieves channel state by channel ID.
	// Returns nil if the channel is not found.
	// The returned ChannelData contains both the opaque channel JSON
	// and the channel secret, matching what was passed to SaveChannel.
	GetChannel(channelID string) *ChannelData

	// ListChannelIDs returns all stored channel IDs.
	ListChannelIDs() []string

	// DeleteChannel removes a channel from storage.
	DeleteChannel(channelID string)

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
	ParamsJSON         string `json:"params_json"`
}
