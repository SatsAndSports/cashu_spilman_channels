package spilmankit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/cashubtc/spilman-go/spilman"
)

func GetServerPubkey(secretKeyHex string) string {
	p, _ := spilman.SecretKeyToPubkey(secretKeyHex)
	return p
}

func RegisterManagementRoutes(mux *http.ServeMux, ctx *ConfigurableSpilman) {
	mux.HandleFunc("/channel/register", func(w http.ResponseWriter, r *http.Request) {
		HandleRegister(w, r, ctx)
	})
	mux.HandleFunc("/channel/params", func(w http.ResponseWriter, r *http.Request) {
		HandleParams(w, r, ctx)
	})
	// Pattern for /channel/{id}/{action}
	mux.HandleFunc("/channel/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		parts := strings.Split(strings.TrimPrefix(path, "/channel/"), "/")
		if len(parts) < 2 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		id := parts[0]
		action := parts[1]

		switch action {
		case "status":
			HandleStatus(w, r, ctx, id)
		case "close":
			HandleClose(w, r, ctx, id)
		case "unilateral-close":
			HandleUnilateralClose(w, r, ctx, id)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func HandleParams(w http.ResponseWriter, r *http.Request, ctx *ConfigurableSpilman) {
	activeUnits := ctx.Stores.GetActiveUnits()
	pricing := make(map[string]interface{})
	for unit, entry := range ctx.Config.Pricing {
		if _, ok := activeUnits[unit]; !ok {
			continue
		}
		data := map[string]interface{}{
			"min_capacity": entry.MinCapacity,
			"variables":    entry.Variables,
		}
		if entry.MaxAmountPerOutput != nil {
			data["max_amount_per_output"] = *entry.MaxAmountPerOutput
		}
		pricing[unit] = data
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"receiver_pubkey":       GetServerPubkey(ctx.Host.SecretKey),
		"pricing":               pricing,
		"pricing_scale":         ctx.Config.PricingScale,
		"mints_units_keysets":   ctx.Stores.GetMintsUnitsKeysets(),
		"min_expiry_in_seconds": ctx.Config.MinExpirySeconds,
	})
}

func HandleRegister(w http.ResponseWriter, r *http.Request, ctx *ConfigurableSpilman) {
	if r.Method != http.MethodPost {
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if b, ok := body["balance"].(float64); ok && b != 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Bad request", "reason": fmt.Sprintf("funding requires balance=0, got %v", b),
		})
		return
	}

	jsonStr, _ := json.Marshal(body)
	result, err := ctx.Bridge.FundChannel(string(jsonStr))
	if err != nil {
		ctx.HandleError(w, err)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true, "channel_id": result.ChannelID, "capacity": result.Capacity, "already_known": result.AlreadyKnown,
	})
}

func HandleStatus(w http.ResponseWriter, r *http.Request, ctx *ConfigurableSpilman, id string) {
	funding, ok := ctx.Stores.GetFunding(id)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "unknown channel"})
		return
	}
	var params struct{ Capacity uint64 }
	json.Unmarshal([]byte(funding.ParamsJson), &params)
	balance, _ := ctx.Stores.GetBalance(id)
	closedData, isClosed := ctx.Stores.GetClosedData(id)
	usage := ctx.Stores.GetUsage(id)

	res := map[string]interface{}{
		"channel_id": id, "capacity": params.Capacity, "balance": uint64(0),
		"usage": usage, "amount_due": ctx.Host.GetAmountDue(id, nil),
		"closed": isClosed,
	}

	if balance != nil {
		res["balance"] = balance.Balance
	}
	if isClosed {
		res["closed_amount"] = closedData.ClosedAmount
	}
	json.NewEncoder(w).Encode(res)
}

func HandleClose(w http.ResponseWriter, r *http.Request, ctx *ConfigurableSpilman, id string) {
	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	balanceRaw, ok := data["balance"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing balance"})
		return
	}
	balance := uint64(balanceRaw.(float64))

	// Check if already closed
	if closedInfo, ok := ctx.Stores.GetClosedData(id); ok {
		if closedInfo.ClosedAmount == balance {
			var sp interface{}
			json.Unmarshal([]byte(closedInfo.SenderProofsJson), &sp)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "channel_id": id, "already_closed": true,
				"total_value":  closedInfo.ReceiverSum + closedInfo.SenderSum,
				"receiver_sum": closedInfo.ReceiverSum, "sender_sum": closedInfo.SenderSum,
				"sender_proofs": sp,
			})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":         "channel already closed at different balance",
			"closed_amount": closedInfo.ClosedAmount, "requested_amount": balance,
		})
		return
	}

	data["channel_id"] = id
	jsonStr, _ := json.Marshal(data)
	res, err := ctx.Bridge.ExecuteCooperativeClose(string(jsonStr))
	if err != nil {
		ctx.HandleError(w, err)
		return
	}
	var sp interface{}
	json.Unmarshal([]byte(res.SenderProofs), &sp)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true, "channel_id": res.ChannelID, "total_value": res.TotalValue,
		"receiver_sum": res.ReceiverSum, "sender_sum": res.SenderSum, "sender_proofs": sp,
		"already_closed": res.AlreadyClosed,
	})
}

func HandleUnilateralClose(w http.ResponseWriter, r *http.Request, ctx *ConfigurableSpilman, id string) {
	// Check if already closed
	if closedInfo, ok := ctx.Stores.GetClosedData(id); ok {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true, "channel_id": id, "earnedBeforeStage2Fees": closedInfo.ReceiverSum, "already_closed": true,
		})
		return
	}

	if _, ok := ctx.Stores.GetFunding(id); !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "unknown channel"})
		return
	}

	res, err := ctx.Bridge.ExecuteUnilateralClose(id)
	if err != nil {
		ctx.HandleError(w, err)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true, "channel_id": id, "earnedBeforeStage2Fees": res.ReceiverSum, "already_closed": res.AlreadyClosed,
	})
}
