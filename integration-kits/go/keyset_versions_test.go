package spilmankit

import (
	"encoding/json"
	"fmt"
	"github.com/cashubtc/spilman-go/spilman"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestFutureKeysetDiscovery(t *testing.T) {
	v1 := "0000000000000001"
	v2 := "01" + strings.Repeat("ab", 32)
	future := map[string]interface{}{"id": "02future", "unit": "sat", "active": true, "keys": false}
	for position := 0; position < 3; position++ {
		entries := []interface{}{
			map[string]interface{}{"id": v1, "unit": "sat", "active": false},
			map[string]interface{}{"id": v2, "unit": "sat", "active": true},
		}
		entries = append(entries, nil)
		copy(entries[position+1:], entries[position:])
		entries[position] = future
		var keysCalls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/keysets" {
				json.NewEncoder(w).Encode(map[string]interface{}{"keysets": entries})
				return
			}
			id := strings.TrimPrefix(r.URL.Path, "/v1/keys/")
			if id != v1 && id != v2 {
				t.Errorf("unexpected key fetch %s", id)
				http.Error(w, "unexpected", 500)
				return
			}
			keysCalls.Add(1)
			json.NewEncoder(w).Encode(map[string]interface{}{"keysets": []interface{}{future, map[string]interface{}{"id": id, "unit": "sat", "keys": map[string]string{"1": "key"}}}})
		}))
		host := &BaseSpilmanHost{pricing: PricingTable{"sat": {}}}
		result, err := host.fetchAllKeysets(server.URL)
		if err != nil || len(result) != 2 {
			t.Fatalf("discovery: %+v %v", result, err)
		}
		if result[0].Active || !result[1].Active || keysCalls.Load() != 2 {
			t.Fatal("lost activity or fetched unsupported keys")
		}
		info, err := DemoFetchActiveKeysetInfo(server.URL, "sat", spilman.KeysetSelectionPolicy{AllowedVersions: spilman.KeysetVersionsV2()})
		if err != nil || info["keysetId"] != v2 {
			t.Fatalf("selection: %+v %v", info, err)
		}
		server.Close()
	}
	_, err := spilman.MatchKeysetKeys(fmt.Sprintf(`{"keysets":[{"id":%q,"unit":"msat","keys":{}}]}`, v2), v2, "sat", 0, nil)
	if err == nil {
		t.Fatal("accepted unit mismatch")
	}
}
