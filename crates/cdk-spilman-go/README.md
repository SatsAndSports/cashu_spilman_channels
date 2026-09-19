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

Server hosts must persist funding, balances, usage state, and keyset metadata. The current Go binding adapter derives keyset-cache presence from the active-keyset callback; Rust hosts can expose an inactive-inclusive cache-presence check for more precise cache-first retry behavior.

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
bridge, err := spilman.NewClientBridge(host)
if err != nil {
    panic(err)
}
defer bridge.Free()

// Simplified channel opening
result, err := bridge.OpenChannelFromToken(
    token, receiverPubkey, senderPubkey, expiry, keysetInfo, maxAmount
)

// Create signed payment
payment, err := bridge.SignPayment(result.ChannelID, balance)
```

## API Reference

### Core Functions
- `GenerateKeypair()` - Generate a new secp256k1 keypair
- `ComputeChannelSecret(secret, pubkey)` - Derive `_channel secret_`
- `BuildCashuBToken(mint, proofs)` - Build a Cashu B token

### Client Bridge Methods
- `OpenChannelFromToken(...)` - Full two-phase funding flow
- `SignPayment(channelId, balance)`
- `SignAndRecordPayment(channelId, balance)`
- `SignChannelRegistration(channelId)`
- `SignCooperativeCloseRequest(channelId, finalBalance)`

### Server Bridge Methods
- `ExecuteCooperativeClose(paymentJson)` - Execute a server close using payment JSON created by the client's `SignCooperativeCloseRequest(channelId, finalBalance)`

The Go bridge does not currently expose the Rust client's NUT-09 opening-recovery
methods. Applications must not assume that querying restored proofs would also
persist the channel's transition to `Open`.
