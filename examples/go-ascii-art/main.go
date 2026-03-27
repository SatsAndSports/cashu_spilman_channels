package main

import (
	"encoding/json"
	"errors"
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

type DemoClientHost struct {
	aliceSecret  string
	funding      map[string]string // channel_id -> funding_json
	paymentState map[string]string // channel_id -> payment_state_json
	channelState map[string]string // channel_id -> "open" or "closed"
}

// Networking
func (h *DemoClientHost) CallMintSwap(url, req string) (string, error) {
	resp, _ := http.Post(url+"/v1/swap", "application/json", strings.NewReader(req))
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		if len(body) > 0 {
			return "", errors.New(string(body))
		}
		return "", fmt.Errorf("mint rejected swap with status %d", resp.StatusCode)
	}
	return string(body), nil
}

// Funding Data
func (h *DemoClientHost) SaveChannelFunding(id, fundingJSON string) {
	h.funding[id] = fundingJSON
	h.channelState[id] = "open"
}
func (h *DemoClientHost) GetChannelFunding(id string) string {
	return h.funding[id]
}

// Payment State
func (h *DemoClientHost) GetPaymentState(id string) string {
	return h.paymentState[id]
}
func (h *DemoClientHost) RecordPayment(id, stateJSON string) {
	h.paymentState[id] = stateJSON
}

// Lifecycle
func (h *DemoClientHost) GetChannelState(id string) string {
	state := h.channelState[id]
	if state == "" {
		return "open"
	}
	return state
}
func (h *DemoClientHost) MarkChannelClosed(id string) {
	h.channelState[id] = "closed"
}
func (h *DemoClientHost) ListChannelIDs() []string {
	ids := []string{}
	for id := range h.funding {
		ids = append(ids, id)
	}
	return ids
}
func (h *DemoClientHost) DeleteChannel(id string) {
	delete(h.funding, id)
	delete(h.paymentState, id)
	delete(h.channelState, id)
}

// Time
func (h *DemoClientHost) NowSeconds() uint64 {
	return uint64(time.Now().Unix())
}

// Crypto
func (h *DemoClientHost) SignWithTweakedKey(pk, msg, tw string) (string, error) {
	return spilman.SignWithTweakedKeyUtil(h.aliceSecret, msg, tw)
}
func (h *DemoClientHost) ComputeChannelSecret(apk, cpk string) (string, error) {
	return spilman.ComputeChannelSecret(h.aliceSecret, cpk)
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
	aliceSecret, alicePub, _ := spilman.GenerateKeypair()
	ki, _ := spilmankit.DemoFetchActiveKeysetInfo(mintUrl, "sat")
	kiJ, _ := json.Marshal(ki)

	host := &DemoClientHost{
		aliceSecret:  aliceSecret,
		funding:      make(map[string]string),
		paymentState: make(map[string]string),
		channelState: make(map[string]string),
	}
	bridge, _ := spilman.NewClientBridge(host)
	defer bridge.Free()

	// Funding
	fmt.Println("Funding channel...")
	total := 0
	for _, m := range messages {
		total += len(m)
	}
	cap := uint64(total + 50)
	fta, _ := spilman.ComputeFundingTokenAmount(cap, string(kiJ), 64)
	ss, _ := spilman.ComputeChannelSecret(aliceSecret, sp.ReceiverPubkey)
	cpJ, _ := json.Marshal(map[string]interface{}{
		"sender_pubkey": alicePub, "receiver_pubkey": sp.ReceiverPubkey, "mint": mintUrl, "unit": "sat", "capacity": cap,
		"funding_token_amount": fta, "maximum_amount": 64, "expiry_timestamp": time.Now().Unix() + 7200, "setup_timestamp": time.Now().Unix(),
		"keyset_id": ki["keysetId"], "input_fee_ppk": ki["inputFeePpk"],
	})
	cid, _ := spilman.ChannelParametersGetChannelId(string(cpJ), ss, string(kiJ))
	fJ, _ := spilman.CreateFundingOutputs(string(cpJ), aliceSecret, string(kiJ))
	var f struct {
		Funding_token_nominal uint64
		Blinded_messages      []interface{}
		Secrets_with_blinding []interface{}
	}
	json.Unmarshal([]byte(fJ), &f)
	sigs, _ := spilmankit.DemoMintFundingToken(mintUrl, f.Funding_token_nominal, f.Blinded_messages, "sat")
	sigsJ, _ := json.Marshal(sigs)
	swbJ, _ := json.Marshal(f.Secrets_with_blinding)
	proofsJ, _ := spilman.ConstructProofs(string(sigsJ), string(swbJ), string(kiJ))
	// ClientChannelFunding structure - field names must match Rust struct
	fundingJ, _ := json.Marshal(map[string]interface{}{
		"params_json":          string(cpJ),
		"funding_proofs_json":  proofsJ,
		"channel_secret_hex":   ss,
		"keyset_info_json":     string(kiJ),
		"sender_pubkey_hex":    alicePub,
		"capacity":             cap,
		"funding_token_amount": fta,
		"mint_url":             mintUrl,
		"created_at":           time.Now().Unix(),
	})
	host.SaveChannelFunding(cid, string(fundingJ))

	fmt.Printf("Full channel ID: %s\nChannel ready! Sending requests...\n", cid)
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
