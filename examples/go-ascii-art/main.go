package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	spilmankit "github.com/cashubtc/cdk-spilman-kit-go"
	"github.com/cashubtc/spilman-go/spilman"
	"github.com/common-nighthawk/go-figure"
)

var (
	SECRET_KEY  = getEnv("SERVER_SECRET_KEY", "0000000000000000000000000000000000000000000000000000000000000001")
	CONFIG_PATH = getEnv("CONFIG_PATH", "config.yaml")
	PORT        = getEnv("PORT", "5001")
	SERVER_URL  = getEnv("SERVER_URL", "http://localhost:5001")
)

func getEnv(k, fb string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return fb
}

func runServer() {
	ctx, _ := spilmankit.LoadFromYaml(CONFIG_PATH, SECRET_KEY)
	defer ctx.Free()

	spilmankit.RegisterManagementRoutes(http.DefaultServeMux, ctx)

	http.HandleFunc("/ascii", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Message string }
		json.NewDecoder(r.Body).Decode(&req)

		fmt.Printf("\n[Request] ASCII art for '%s'\n", req.Message)
		payment, err := ctx.ProcessRequestPayment(r, map[string]uint64{"chars": uint64(len(req.Message))})
		if err != nil {
			ctx.HandleError(w, err)
			return
		}

		art := figure.NewFigure(req.Message, "", true).String()
		ctx.AttachPaymentHeader(w, payment)
		json.NewEncoder(w).Encode(map[string]interface{}{"art": art, "message": req.Message, "payment": payment})
	})

	http.HandleFunc("/ascii/preflight", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Message string }
		json.NewDecoder(r.Body).Decode(&req)
		if req.Message == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing 'message'"})
			return
		}

		ok, err := ctx.PaymentCoversAmountDue(r, map[string]uint64{"chars": uint64(len(req.Message))})
		if err != nil {
			ctx.HandleError(w, err)
			return
		}
		if !ok {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false})
			return
		}

		amountDue, err := ctx.VerifyPaymentCoversAmountDue(r, map[string]uint64{"chars": uint64(len(req.Message))})
		if err != nil {
			ctx.HandleError(w, err)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "amount_due": amountDue})
	})

	log.Printf("Go Server listening on :%s (Pubkey: %s)\n", PORT, spilmankit.GetServerPubkey(SECRET_KEY))
	fmt.Println("Server is ready.")
	http.ListenAndServe(":"+PORT, nil)
}

func runClient(args []string) {
	shouldClose := false
	messages := []string{}
	for _, a := range args {
		if a == "--close" {
			shouldClose = true
		} else {
			messages = append(messages, a)
		}
	}
	if len(messages) == 0 {
		messages = []string{"Hello", "Cashu", "World"}
	}

	// 1. Connect to server and get params
	fmt.Printf("Connecting to %s...\n", SERVER_URL)
	resp, _ := http.Get(SERVER_URL + "/channel/params")
	var sp struct {
		ReceiverPubkey string                         `json:"receiver_pubkey"`
		Mints          map[string]map[string][]string `json:"mints_units_keysets"`
	}
	json.NewDecoder(resp.Body).Decode(&sp)

	var mintUrl string
	for m := range sp.Mints {
		mintUrl = m
		break
	}

	// 2. Setup client with InMemoryClientHost
	aliceSecret, alicePub, _ := spilman.GenerateKeypair()
	host := spilman.NewInMemoryClientHost(aliceSecret)
	bridge, _ := spilman.NewClientBridge(host)
	defer bridge.Free()

	// 3. Fetch keyset info
	ki, _ := spilmankit.DemoFetchActiveKeysetInfo(mintUrl, "sat")
	kiJ, _ := json.Marshal(ki)

	// 4. Mint proofs and build token
	fmt.Println("Minting tokens...")
	total := 0
	for _, m := range messages {
		total += len(m)
	}
	mintAmount := uint64(total + 60) // Extra for capacity overhead

	// Use DemoMintPlainProofs to get plain proofs
	proofsJSON, err := spilmankit.DemoMintPlainProofs(mintUrl, mintAmount, string(kiJ), "sat")
	if err != nil {
		fmt.Printf("Failed to mint proofs: %v\n", err)
		return
	}

	// Build a cashuB token from the proofs
	token, err := spilman.BuildCashuBToken(mintUrl, "sat", proofsJSON)
	if err != nil {
		fmt.Printf("Failed to build token: %v\n", err)
		return
	}

	// 5. Open channel from token (the simplified way!)
	fmt.Println("Opening channel...")
	expiry := uint64(time.Now().Unix() + 7200) // 2 hours from now
	result, err := bridge.OpenChannelFromToken(
		token,
		sp.ReceiverPubkey,
		alicePub,
		expiry,
		string(kiJ),
		64, // max_amount per output
	)
	if err != nil {
		fmt.Printf("Failed to open channel: %v\n", err)
		return
	}

	cid := result.ChannelID
	fmt.Printf("Full channel ID: %s\n", cid)
	fmt.Printf("Capacity: %d sat\n", result.Capacity)

	// 6. Make requests
	fmt.Println("Channel ready! Sending requests...")
	balance := uint64(0)
	for i, msg := range messages {
		balance += uint64(len(msg))
		header, _ := bridge.BuildPaymentHeader(cid, balance, i == 0)
		reqB, _ := json.Marshal(map[string]string{"message": msg})
		req, _ := http.NewRequest("POST", SERVER_URL+"/ascii", strings.NewReader(string(reqB)))
		req.Header.Set("X-Cashu-Channel", header)
		r, _ := (&http.Client{}).Do(req)
		var res struct{ Art string }
		json.NewDecoder(r.Body).Decode(&res)
		r.Body.Close()
		fmt.Printf("\n[%d/%d] Accepted:\n%s\n", i+1, len(messages), res.Art)
	}

	// 7. Optional close
	if shouldClose {
		fmt.Println("\nClosing channel...")
		sResp, _ := http.Get(fmt.Sprintf("%s/channel/%s/status", SERVER_URL, cid))
		var st struct{ Amount_due uint64 }
		json.NewDecoder(sResp.Body).Decode(&st)
		closeReqJ, _ := bridge.CreateCooperativeCloseRequest(cid, st.Amount_due)
		cResp, _ := http.Post(fmt.Sprintf("%s/channel/%s/close", SERVER_URL, cid), "application/json", strings.NewReader(closeReqJ))
		body, _ := io.ReadAll(cResp.Body)
		bridge.ProcessCooperativeCloseResponse(string(body))
		var cr struct{ Receiver_sum, Sender_sum uint64 }
		json.Unmarshal(body, &cr)
		fmt.Printf("Closed! Earned: %d sat, Refunded: %d sat\n", cr.Receiver_sum, cr.Sender_sum)
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "client" {
		runClient(os.Args[2:])
	} else {
		fmt.Println("Usage:")
		fmt.Println("  go run main.go server              # Start server")
		fmt.Println("  go run main.go client [msg] [--close] # Run client")
		runServer()
	}
}
