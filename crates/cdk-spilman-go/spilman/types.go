package spilman

// PaymentSuccess is returned by ProcessPayment on success.
// Contains the channel state after the payment was processed.
type PaymentSuccess struct {
	ChannelID string `json:"channel_id"`
	Balance   uint64 `json:"balance"`
	AmountDue uint64 `json:"amount_due"`
	Capacity  uint64 `json:"capacity"`
}

// PaymentValidationResult is returned by ValidatePayment on success.
// Similar to PaymentSuccess but also includes the sender's signature,
// and does not record the payment (useful for pre-validation).
type PaymentValidationResult struct {
	ChannelID       string `json:"channel_id"`
	Balance         uint64 `json:"balance"`
	AmountDue       uint64 `json:"amount_due"`
	Capacity        uint64 `json:"capacity"`
	SenderSignature string `json:"sender_signature"`
}

// FundChannelResult is returned by FundChannel on success.
// Indicates whether the channel was newly registered or already known.
type FundChannelResult struct {
	ChannelID    string `json:"channel_id"`
	Capacity     uint64 `json:"capacity"`
	AlreadyKnown bool   `json:"already_known"`
}

// CloseSuccess is returned by ExecuteCooperativeClose and ExecuteUnilateralClose on success.
// Contains the final distribution of funds after the channel is closed.
type CloseSuccess struct {
	ChannelID     string `json:"channel_id"`
	TotalValue    uint64 `json:"total_value"`
	ReceiverSum   uint64 `json:"receiver_sum"`
	SenderSum     uint64 `json:"sender_sum"`
	SenderProofs  string `json:"sender_proofs"`
	AlreadyClosed bool   `json:"already_closed"`
}
