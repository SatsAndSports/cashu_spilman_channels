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

// Derive `_channel secret_` with receiver
channelSecret, _ := spilman.ComputeChannelSecret(senderSecret, receiverPubkey)

// Create funding outputs for minting
funding, _ := spilman.CreateFundingOutputs(paramsJson, senderSecret, keysetJson)

// Create signed payment
signature, _ := spilman.CreateSignedBalanceUpdate(paramsJson, keysetJson, senderSecret, proofsJson, balance)
```

## API Reference

### Core Functions
- `GenerateKeypair()` - Generate a new secp256k1 keypair
- `ComputeChannelSecret(secret, pubkey)` - Derive `_channel secret_`
- `CreateFundingOutputs(params, secret, keyset)` - Create blinded outputs for funding
- `CreateSignedBalanceUpdate(...)` - Sign a payment

### Bridge Methods
- `ProcessPayment(payment, context)`
- `FundChannel(payment)`
- `ExecuteCooperativeClose(payment)`
- `ExecuteUnilateralClose(channelId)`
