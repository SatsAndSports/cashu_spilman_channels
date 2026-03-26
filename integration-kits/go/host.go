package spilmankit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cashubtc/spilman-go/spilman"
)

type PricingEntry struct {
	MinCapacity        uint64            `yaml:"min_capacity" json:"min_capacity"`
	MaxAmountPerOutput *uint64           `yaml:"max_amount_per_output" json:"max_amount_per_output,omitempty"`
	Variables          map[string]uint64 `yaml:"variables" json:"variables"`
}

type PricingTable map[string]PricingEntry

type BaseSpilmanHost struct {
	SecretKey        string
	Pubkey           string
	mints            map[string][]string
	pricing          PricingTable
	stores           SpilmanStores
	minExpirySeconds uint64
	pricingScale     uint64
}

func NewBaseSpilmanHost(secretKey string, mints map[string][]string, pricing PricingTable, stores SpilmanStores, minExpiry uint64, pricingScale uint64) *BaseSpilmanHost {
	pubkey, _ := spilman.SecretKeyToPubkey(secretKey)

	// Normalize mint URLs
	normMints := make(map[string][]string)
	for url, units := range mints {
		normMints[strings.TrimSuffix(url, "/")] = units
	}

	if pricingScale == 0 {
		pricingScale = 1
	}

	return &BaseSpilmanHost{
		SecretKey:        secretKey,
		Pubkey:           pubkey,
		mints:            normMints,
		pricing:          pricing,
		stores:           stores,
		minExpirySeconds: minExpiry,
		pricingScale:     pricingScale,
	}
}

func (h *BaseSpilmanHost) ReceiverKeyIsAcceptable(pubkeyHex string) bool {
	return strings.ToLower(pubkeyHex) == strings.ToLower(h.Pubkey)
}

func (h *BaseSpilmanHost) MintAndKeysetIsAcceptable(mint string, keysetId string) bool {
	normMint := strings.TrimSuffix(mint, "/")
	trustedUnits, ok := h.mints[normMint]
	if !ok {
		return false
	}

	entry, ok := h.stores.GetKeyset(mint, keysetId)
	if !ok {
		return false
	}

	if !entry.Active {
		return false
	}

	for _, u := range trustedUnits {
		if u == entry.Unit {
			return true
		}
	}
	return false
}

func (h *BaseSpilmanHost) GetFundingAndParams(channelId string) (string, string, string, string, bool) {
	d, ok := h.stores.GetFunding(channelId)
	if !ok {
		return "", "", "", "", false
	}
	return d.ParamsJson, d.FundingProofsJson, d.ChannelSecret, d.KeysetInfoJson, true
}

func (h *BaseSpilmanHost) SaveFunding(channelId, paramsJson, proofsJson, secret, keyset string, initialBalance uint64, initialSignature string) {
	h.stores.InsertFunding(channelId, ChannelFundingData{
		ParamsJson:        paramsJson,
		FundingProofsJson: proofsJson,
		ChannelSecret:     secret,
		KeysetInfoJson:    keyset,
	})
	// Update balance store
	h.stores.UpdateBalance(channelId, initialBalance, initialSignature)
}

func (h *BaseSpilmanHost) GetAmountDue(channelId string, contextJson *string) uint64 {
	accumulated := h.stores.GetUsage(channelId)
	pending := make(UsageMap)
	if contextJson != nil {
		json.Unmarshal([]byte(*contextJson), &pending)
	}

	funding, ok := h.stores.GetFunding(channelId)
	if !ok {
		return 0
	}

	var params struct {
		Unit string `json:"unit"`
	}
	json.Unmarshal([]byte(funding.ParamsJson), &params)

	unitPricing, ok := h.pricing[params.Unit]
	if !ok {
		return 0
	}

	var total uint64
	for varName, price := range unitPricing.Variables {
		acc := accumulated[varName]
		pend := pending[varName]
		total += (acc + pend) * price
	}
	if total == 0 {
		return 0
	}
	scale := h.pricingScale
	if scale == 0 {
		scale = 1
	}
	return (total + scale - 1) / scale
}

func (h *BaseSpilmanHost) RecordPayment(channelId string, balance uint64, signature, contextJson string) {
	var increments UsageMap
	json.Unmarshal([]byte(contextJson), &increments)
	h.stores.IncrementUsage(channelId, increments)
	h.stores.UpdateBalance(channelId, balance, signature)
}

func (h *BaseSpilmanHost) GetChannelState(channelId string) string {
	if h.stores.IsClosed(channelId) {
		return "closed"
	}
	if h.stores.IsClosing(channelId) {
		return "closing"
	}
	return "open"
}

func (h *BaseSpilmanHost) MarkChannelClosing(channelId string, expiryTimestamp, balance uint64, signature string) error {
	if h.stores.IsClosed(channelId) {
		return fmt.Errorf("channel already closed")
	}

	// Mirror TS/Python fix: Update balance store during closing
	h.stores.UpdateBalance(channelId, balance, signature)
	h.stores.MarkClosing(channelId, expiryTimestamp, balance, signature)
	return nil
}

func (h *BaseSpilmanHost) GetClosingData(channelId string) *spilman.ClosingData {
	d, ok := h.stores.GetClosingData(channelId)
	if !ok {
		return nil
	}
	return &spilman.ClosingData{
		ExpiryTimestamp: d.ExpiryTimestamp,
		Balance:         d.Balance,
		Signature:       d.Signature,
	}
}

func (h *BaseSpilmanHost) GetChannelPolicy(unit string) *spilman.ChannelPolicy {
	p, ok := h.pricing[unit]
	if !ok {
		return nil
	}
	policy := &spilman.ChannelPolicy{
		MinExpiryInSeconds: h.minExpirySeconds,
		MinCapacity:        p.MinCapacity,
	}
	if p.MaxAmountPerOutput != nil {
		v := *p.MaxAmountPerOutput
		policy.MaxAmountPerOutput = &v
	}
	return policy
}

func (h *BaseSpilmanHost) NowSeconds() uint64 {
	return uint64(time.Now().Unix())
}

func (h *BaseSpilmanHost) GetBalanceAndSignatureForUnilateralExit(channelId string) (uint64, string, bool) {
	b, ok := h.stores.GetBalance(channelId)
	if !ok {
		return 0, "", false
	}
	return b.Balance, b.Signature, true
}

func (h *BaseSpilmanHost) GetActiveKeysetIds(mint, unit string) []string {
	return h.stores.GetActiveKeysetIds(mint, unit)
}

func (h *BaseSpilmanHost) GetKeysetInfo(mint, keysetId string) (string, bool) {
	e, ok := h.stores.GetKeyset(mint, keysetId)
	if !ok {
		return "", false
	}
	return e.InfoJson, true
}

func (h *BaseSpilmanHost) CallMintSwap(mintUrl, swapRequestJson string) (string, error) {
	resp, err := http.Post(mintUrl+"/v1/swap", "application/json", bytes.NewBufferString(swapRequestJson))
	if err != nil {
		return "", err
	}
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

func (h *BaseSpilmanHost) RefreshAllKeysets(mintUrl string) error {
	// Standard fetch logic mirrored from main.go but improved for multi-mint
	keysets, err := h.fetchAllKeysets(mintUrl)
	if err != nil {
		return err
	}
	for _, k := range keysets {
		h.stores.SetKeyset(mintUrl, k.Id, KeysetCacheEntry{
			InfoJson: k.InfoJson,
			Active:   k.Active,
			Unit:     k.Unit,
		})
	}
	return nil
}

func (h *BaseSpilmanHost) MarkChannelClosed(channelId string, expiryTimestamp, balance uint64, receiverProofs, senderProofs string, receiverSum, senderSum uint64) error {
	if h.stores.IsClosed(channelId) {
		return fmt.Errorf("channel already closed")
	}
	h.stores.MarkClosed(channelId, ClosedData{
		ExpiryTimestamp:    expiryTimestamp,
		ClosedAmount:       balance,
		ValueAfterStage1:   receiverSum + senderSum,
		ReceiverSum:        receiverSum,
		SenderSum:          senderSum,
		ReceiverProofsJson: receiverProofs,
		SenderProofsJson:   senderProofs,
	})
	return nil
}

func (h *BaseSpilmanHost) ComputeChannelSecret(alicePub, charliePub string) (string, error) {
	return spilman.ComputeChannelSecret(h.SecretKey, alicePub)
}

func (h *BaseSpilmanHost) SignWithTweakedKey(signerPub, msg, tweak string) (string, error) {
	return spilman.SignWithTweakedKeyUtil(h.SecretKey, msg, tweak)
}

// Keyset fetching logic
type mintKeysetInfo struct {
	Id       string
	Unit     string
	Active   bool
	InfoJson string
}

func (h *BaseSpilmanHost) fetchAllKeysets(mintUrl string) ([]mintKeysetInfo, error) {
	// Implementation similar to main.go's fetchAllKeysetsFromMint
	// I'll simplify for brevity but keep the essential steps
	resp, err := http.Get(mintUrl + "/v1/keysets")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var data struct {
		Keysets []struct {
			Id, Unit    string
			Active      bool
			InputFeePpk uint64 `json:"input_fee_ppk"`
		}
	}
	json.NewDecoder(resp.Body).Decode(&data)

	var res []mintKeysetInfo
	for _, k := range data.Keysets {
		// Filter by units we have pricing for
		if _, ok := h.pricing[k.Unit]; !ok {
			continue
		}

		kresp, _ := http.Get(fmt.Sprintf("%s/v1/keys/%s", mintUrl, k.Id))
		if kresp == nil {
			continue
		}
		var kdata struct {
			Keysets []struct{ Keys map[string]string }
		}
		json.NewDecoder(kresp.Body).Decode(&kdata)
		kresp.Body.Close()
		if len(kdata.Keysets) == 0 {
			continue
		}

		info := map[string]interface{}{
			"keysetId": k.Id, "unit": k.Unit, "keys": kdata.Keysets[0].Keys, "inputFeePpk": k.InputFeePpk,
		}
		infoJson, _ := json.Marshal(info)
		res = append(res, mintKeysetInfo{Id: k.Id, Unit: k.Unit, Active: k.Active, InfoJson: string(infoJson)})
	}
	return res, nil
}
