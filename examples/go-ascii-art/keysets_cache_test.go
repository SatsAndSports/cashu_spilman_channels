package main

import "testing"

func resetKeysetCache() {
	keysetCacheMu.Lock()
	defer keysetCacheMu.Unlock()
	keysetCache = make(map[string]KeysetCacheEntry)
}

func getKeysetEntry(keysetId string) (KeysetCacheEntry, bool) {
	keysetCacheMu.RLock()
	defer keysetCacheMu.RUnlock()
	entry, ok := keysetCache[keysetId]
	return entry, ok
}

func TestRefreshAllKeysetsRetainsInactive(t *testing.T) {
	resetKeysetCache()
	keysetCache["A"] = KeysetCacheEntry{
		InfoJson: "infoA",
		Active:   true,
		Unit:     "sat",
	}

	oldFetch := fetchAllKeysetsFromMint
	fetchAllKeysetsFromMint = func(_ string) ([]MintKeysetWithKeys, error) {
		return []MintKeysetWithKeys{
			{Id: "A", Unit: "sat", Active: false, InputFeePpk: 0, Keys: map[string]string{"1": "keyA"}},
			{Id: "B", Unit: "sat", Active: true, InputFeePpk: 0, Keys: map[string]string{"1": "keyB"}},
		}, nil
	}
	defer func() { fetchAllKeysetsFromMint = oldFetch }()

	refreshAllKeysets("http://mint.test")

	entryA, ok := getKeysetEntry("A")
	if !ok {
		t.Fatalf("expected keyset A to be present")
	}
	if entryA.Active {
		t.Fatalf("expected keyset A to be inactive after refresh")
	}

	if _, ok := getKeysetEntry("B"); !ok {
		t.Fatalf("expected keyset B to be present")
	}
}

func TestRefreshAllKeysetsDoesNotDropMissing(t *testing.T) {
	resetKeysetCache()
	keysetCache["A"] = KeysetCacheEntry{
		InfoJson: "infoA",
		Active:   true,
		Unit:     "sat",
	}

	oldFetch := fetchAllKeysetsFromMint
	fetchAllKeysetsFromMint = func(_ string) ([]MintKeysetWithKeys, error) {
		return []MintKeysetWithKeys{
			{Id: "B", Unit: "sat", Active: true, InputFeePpk: 0, Keys: map[string]string{"1": "keyB"}},
		}, nil
	}
	defer func() { fetchAllKeysetsFromMint = oldFetch }()

	refreshAllKeysets("http://mint.test")

	if _, ok := getKeysetEntry("A"); !ok {
		t.Fatalf("expected keyset A to remain in cache")
	}
	if _, ok := getKeysetEntry("B"); !ok {
		t.Fatalf("expected keyset B to be added to cache")
	}
}
