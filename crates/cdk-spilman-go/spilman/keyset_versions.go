package spilman

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// KeysetVersions is an explicit output-selection set, not a cache/input filter.
type KeysetVersions []string

// Fixed convenience sets return fresh slices and never expand on upgrades.
func KeysetVersionsV1() KeysetVersions               { return KeysetVersions{"v1"} }
func KeysetVersionsV2() KeysetVersions               { return KeysetVersions{"v2"} }
func KeysetVersionsV1AndV2() KeysetVersions          { return KeysetVersions{"v1", "v2"} }
func LibrarySupportedKeysetVersions() KeysetVersions { return KeysetVersionsV1AndV2() }

type KeysetSelectionPolicy struct {
	AllowedVersions KeysetVersions `json:"allowed_versions"`
}

type SkippedKeysetVersion struct {
	VersionByte byte    `json:"version_byte"`
	Unit        *string `json:"unit"`
	Active      bool    `json:"active"`
}

type KeysetDiscovery struct {
	Keysets                []json.RawMessage      `json:"keysets"`
	Skipped                []SkippedKeysetVersion `json:"skipped"`
	UnsupportedActiveUnits []*string              `json:"unsupported_active_units"`
}

// Classify only the first byte for unknown versions; fully validate supported IDs.
func supportedKeysetID(id string) (bool, error) {
	if len(id) < 2 {
		return false, fmt.Errorf("keyset ID must start with a hex version byte")
	}
	prefix, err := hex.DecodeString(id[:2])
	if err != nil {
		return false, err
	}
	if prefix[0] > 1 {
		return false, nil
	}
	expected := 16
	if prefix[0] == 1 {
		expected = 66
	}
	if len(id) != expected {
		return false, fmt.Errorf("invalid supported keyset ID length")
	}
	_, err = hex.DecodeString(id)
	return err == nil, err
}

// DiscoverKeysets preserves all understood metadata, including inactive entries.
// Version classification follows the same first-byte rule as the Rust API.
func DiscoverKeysets(response string) (KeysetDiscovery, error) {
	report := KeysetDiscovery{Keysets: []json.RawMessage{}, Skipped: []SkippedKeysetVersion{}, UnsupportedActiveUnits: []*string{}}
	var listing struct {
		Keysets []json.RawMessage `json:"keysets"`
	}
	if err := json.Unmarshal([]byte(response), &listing); err != nil {
		return report, err
	}
	if listing.Keysets == nil {
		return report, fmt.Errorf("missing keysets array")
	}
	supportedActive, unsupportedActive := map[string]bool{}, map[string]*string{}
	for _, raw := range listing.Keysets {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return report, err
		}
		var id string
		if err := json.Unmarshal(fields["id"], &id); err != nil {
			return report, err
		}
		supported, err := supportedKeysetID(id)
		if err != nil {
			return report, err
		}
		var unit *string
		var active bool
		// Unknown metadata is advisory only.
		if err := json.Unmarshal(fields["unit"], &unit); err != nil {
			unit = nil
		}
		_ = json.Unmarshal(fields["active"], &active)
		key := ""
		if unit != nil {
			key = "unit:" + *unit
		}
		if !supported {
			prefix, _ := hex.DecodeString(id[:2])
			report.Skipped = append(report.Skipped, SkippedKeysetVersion{prefix[0], unit, active})
			if active {
				unsupportedActive[key] = unit
			}
			continue
		}
		if unit == nil {
			return report, fmt.Errorf("missing supported keyset unit")
		}
		if _, ok := fields["active"]; !ok || string(fields["active"]) == "null" {
			return report, fmt.Errorf("missing supported keyset active flag")
		}
		if err := json.Unmarshal(fields["active"], &active); err != nil {
			return report, err
		}
		for _, field := range []string{"input_fee_ppk", "final_expiry"} {
			if value, ok := fields[field]; ok {
				if field == "final_expiry" && string(value) == "null" {
					continue
				}
				var n uint64
				if string(value) == "null" {
					return report, fmt.Errorf("invalid %s", field)
				}
				if err := json.Unmarshal(value, &n); err != nil {
					return report, err
				}
			}
		}
		report.Keysets = append(report.Keysets, raw)
		if active {
			supportedActive[key] = true
		}
	}
	keys := []string{}
	for key := range unsupportedActive {
		if !supportedActive[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		report.UnsupportedActiveUnits = append(report.UnsupportedActiveUnits, unsupportedActive[key])
	}
	return report, nil
}

// SelectActive chooses metadata for new outputs; callers still enforce expiry.
func (d KeysetDiscovery) SelectActive(unit string, policy KeysetSelectionPolicy) (string, error) {
	allowed := map[string]bool{}
	for _, v := range policy.AllowedVersions {
		if v != "v1" && v != "v2" {
			return "", fmt.Errorf("unsupported policy version %q", v)
		}
		allowed[v] = true
	}
	for _, raw := range d.Keysets {
		var k struct {
			ID, Unit string
			Active   bool
		}
		if err := json.Unmarshal(raw, &k); err != nil {
			return "", err
		}
		supported, err := supportedKeysetID(k.ID)
		if err != nil {
			return "", err
		}
		if !supported {
			continue
		}
		version := "v1"
		if k.ID[:2] == "01" {
			version = "v2"
		}
		if k.Active && k.Unit == unit && allowed[version] {
			return k.ID, nil
		}
	}
	return "", fmt.Errorf("no compatible active keyset for unit %q with allowed versions %v", unit, policy.AllowedVersions)
}

// MatchKeysetKeys matches a requested supported ID and checks response metadata.
// Cryptographic channel/keyset verification remains in the Rust channel APIs.
func MatchKeysetKeys(response string, id, unit string, fee uint64, expiry *uint64) (map[string]string, error) {
	supported, err := supportedKeysetID(id)
	if err != nil {
		return nil, err
	}
	if !supported {
		return nil, fmt.Errorf("unsupported requested keyset version")
	}
	var listing struct{ Keysets []json.RawMessage }
	if err := json.Unmarshal([]byte(response), &listing); err != nil {
		return nil, err
	}
	var matched map[string]string
	for _, raw := range listing.Keysets {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, err
		}
		var entryID string
		if err := json.Unmarshal(fields["id"], &entryID); err != nil {
			return nil, err
		}
		supported, err := supportedKeysetID(entryID)
		if err != nil {
			return nil, err
		}
		if !supported || entryID != id {
			continue
		}
		var entryUnit string
		if err := json.Unmarshal(fields["unit"], &entryUnit); err != nil {
			return nil, err
		}
		if matched != nil || entryUnit != unit {
			return nil, fmt.Errorf("duplicate keyset or keys unit mismatch")
		}
		if rawFee, ok := fields["input_fee_ppk"]; ok {
			var responseFee *uint64
			if err := json.Unmarshal(rawFee, &responseFee); err != nil {
				return nil, err
			}
			if responseFee == nil || *responseFee != fee {
				return nil, fmt.Errorf("keyset fee mismatch")
			}
		}
		if rawExpiry, ok := fields["final_expiry"]; ok {
			var responseExpiry *uint64
			if err := json.Unmarshal(rawExpiry, &responseExpiry); err != nil {
				return nil, err
			}
			if (responseExpiry == nil) != (expiry == nil) || (responseExpiry != nil && *responseExpiry != *expiry) {
				return nil, fmt.Errorf("keyset expiry mismatch")
			}
		}
		if err := json.Unmarshal(fields["keys"], &matched); err != nil {
			return nil, err
		}
		if matched == nil {
			return nil, fmt.Errorf("missing requested key material")
		}
	}
	if matched == nil {
		return nil, fmt.Errorf("requested keyset missing from keys response")
	}
	return matched, nil
}
