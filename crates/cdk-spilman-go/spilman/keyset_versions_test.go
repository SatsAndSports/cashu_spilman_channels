package spilman

import (
	"fmt"
	"strings"
	"testing"
)

func TestKeysetDiscoveryAndSelection(t *testing.T) {
	v1 := `{"id":"0000000000000001","unit":"sat","active":false}`
	v2ID := "01" + strings.Repeat("ab", 32)
	v2 := fmt.Sprintf(`{"id":%q,"unit":"sat","active":true}`, v2ID)
	future := `{"id":"02opaque","unit":"sat","active":true,"keys":false}`
	for _, entries := range []string{future + "," + v1 + "," + v2, v1 + "," + future + "," + v2, v1 + "," + v2 + "," + future} {
		report, err := DiscoverKeysets(`{"keysets":[` + entries + `]}`)
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Keysets) != 2 || len(report.Skipped) != 1 || len(report.UnsupportedActiveUnits) != 0 {
			t.Fatalf("unexpected report: %+v", report)
		}
		id, err := report.SelectActive("sat", KeysetSelectionPolicy{KeysetVersionsV2()})
		if err != nil || id != v2ID {
			t.Fatalf("selection: %s, %v", id, err)
		}
		if _, err := report.SelectActive("sat", KeysetSelectionPolicy{KeysetVersionsV1()}); err == nil {
			t.Fatal("selected disallowed V2")
		}
	}
	report, err := DiscoverKeysets(`{"keysets":[` + future + `]}`)
	if err != nil || len(report.UnsupportedActiveUnits) != 1 {
		t.Fatalf("diagnostics: %+v %v", report, err)
	}
	for _, response := range []string{`{"keysets":[{"id":"00bad"}]}`, `{"keysets":[{"id":"zzbad"}]}`, `{"keysets":[{"id":null}]}`} {
		if _, err := DiscoverKeysets(response); err == nil {
			t.Fatalf("accepted malformed entry: %s", response)
		}
	}
	versions := KeysetVersionsV1AndV2()
	versions[0] = "v3"
	if KeysetVersionsV1AndV2()[0] != "v1" {
		t.Fatal("mutable shared preset")
	}
	if _, err := report.SelectActive("sat", KeysetSelectionPolicy{versions}); err == nil {
		t.Fatal("accepted unsupported policy")
	}
}
