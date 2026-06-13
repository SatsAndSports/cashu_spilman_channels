# CDK Spilman Go Bindings

Go bindings for Spilman payment channels, compiled from the core Rust implementation using CGO.

## Installation

```bash
go get github.com/SatsAndSports/demo_of_spillman_cashu_channel/crates/cdk-spilman-go/spilman
```

**Note**: This package requires CGO and links against a native Rust library.

## Usage

### Server-Side: Bridge

The `Bridge` handles payment validation and channel registration. It delegates storage and policy to a `SpilmanHost` interface.

```go
package main

import "github.com/SatsAndSports/demo_of_spillman_cashu_channel/crates/cdk-spilman-go/spilman"

type MyHost struct {
    // Implement spilman.SpilmanHost interface
}

func main() {
    host := &MyHost{}
    bridge := spilman.NewBridge(host)
    defer bridge.Free()

    // Process a payment
    result, err := bridge.ProcessPayment(paymentJson, contextJson)
    if err != nil {
        // err contains structured JSON error
    }
}
```

### Client-Side: Setup

```go
import "github.com/SatsAndSports/demo_of_spillman_cashu_channel/crates/cdk-spilman-go/spilman"

host := spilman.NewInMemoryClientHost(senderSecret)
bridge := spilman.NewClientBridge(host)

// Simplified channel opening
result, err := bridge.OpenChannelFromToken(
    token, receiverPubkey, senderPubkey, expiry, keysetInfo, maxAmount
)

// Create signed payment
payment, err := bridge.CreatePayment(result.ChannelID, balance)
```

## API Reference

### Core Functions
- `GenerateKeypair()` - Generate a new secp256k1 keypair
- `ComputeChannelSecret(secret, pubkey)` - Derive `_channel secret_`
- `BuildCashuBToken(mint, proofs)` - Build a Cashu B token

### Bridge Methods
- `OpenChannelFromToken(...)` - Full two-phase funding flow
- `RestoreFundingProofs(channelId)` - NUT-09 recovery
- `CreatePayment(channelId, balance)`
- `CreatePaymentWithFunding(channelId, balance)`
- `ExecuteCooperativeClose(channelId, finalBalance)`
