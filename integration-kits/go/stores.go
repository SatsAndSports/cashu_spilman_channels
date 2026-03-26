package spilmankit

import (
	"database/sql"
	"encoding/json"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type UsageMap map[string]uint64

type ChannelFundingData struct {
	ParamsJson        string
	FundingProofsJson string
	ChannelSecret     string
	KeysetInfoJson    string
}

type ChannelBalance struct {
	Balance   uint64
	Signature string
}

type ClosingData struct {
	ExpiryTimestamp uint64
	Balance         uint64
	Signature       string
}

type ClosedData struct {
	ExpiryTimestamp    uint64
	ClosedAmount       uint64
	ValueAfterStage1   uint64
	ReceiverSum        uint64
	SenderSum          uint64
	ReceiverProofsJson string
	SenderProofsJson   string
}

type KeysetCacheEntry struct {
	InfoJson string
	Active   bool
	Unit     string
}

type KeysetKey struct {
	Mint     string
	KeysetId string
}

type SpilmanStores interface {
	GetFunding(channelId string) (*ChannelFundingData, bool)
	InsertFunding(channelId string, data ChannelFundingData)
	AllFunding() map[string]ChannelFundingData

	GetBalance(channelId string) (*ChannelBalance, bool)
	UpdateBalance(channelId string, balance uint64, signature string)

	GetUsage(channelId string) UsageMap
	IncrementUsage(channelId string, increments UsageMap)

	IsClosing(channelId string) bool
	MarkClosing(channelId string, expiryTimestamp, balance uint64, signature string)
	GetClosingData(channelId string) (*ClosingData, bool)

	IsClosed(channelId string) bool
	MarkClosed(channelId string, data ClosedData)
	GetClosedData(channelId string) (*ClosedData, bool)

	GetKeyset(mint, keysetId string) (*KeysetCacheEntry, bool)
	SetKeyset(mint, keysetId string, entry KeysetCacheEntry)
	GetActiveKeysetIds(mint, unit string) []string
	GetMintsUnitsKeysets() map[string]map[string][]string
	GetActiveUnits() map[string]struct{}
}

// In-Memory implementation
type memoryStores struct {
	funding map[string]ChannelFundingData
	balance map[string]ChannelBalance
	usage   map[string]UsageMap
	closing map[string]ClosingData
	closed  map[string]ClosedData
	keysets map[KeysetKey]KeysetCacheEntry
	mu      sync.RWMutex
}

func NewInMemoryStores() SpilmanStores {
	return &memoryStores{
		funding: make(map[string]ChannelFundingData),
		balance: make(map[string]ChannelBalance),
		usage:   make(map[string]UsageMap),
		closing: make(map[string]ClosingData),
		closed:  make(map[string]ClosedData),
		keysets: make(map[KeysetKey]KeysetCacheEntry),
	}
}

func (s *memoryStores) GetFunding(id string) (*ChannelFundingData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.funding[id]
	return &d, ok
}
func (s *memoryStores) InsertFunding(id string, d ChannelFundingData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.funding[id]; !ok {
		s.funding[id] = d
	}
}
func (s *memoryStores) AllFunding() map[string]ChannelFundingData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make(map[string]ChannelFundingData)
	for k, v := range s.funding {
		res[k] = v
	}
	return res
}
func (s *memoryStores) GetBalance(id string) (*ChannelBalance, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.balance[id]
	return &d, ok
}
func (s *memoryStores) UpdateBalance(id string, b uint64, sig string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	curr, ok := s.balance[id]
	if !ok || b > curr.Balance || curr.Signature == "" {
		s.balance[id] = ChannelBalance{Balance: b, Signature: sig}
	}
}
func (s *memoryStores) GetUsage(id string) UsageMap {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.usage[id]
	if !ok {
		return make(UsageMap)
	}
	res := make(UsageMap)
	for k, v := range u {
		res[k] = v
	}
	return res
}
func (s *memoryStores) IncrementUsage(id string, incs UsageMap) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usage[id]
	if !ok {
		u = make(UsageMap)
		s.usage[id] = u
	}
	for k, v := range incs {
		u[k] += v
	}
}
func (s *memoryStores) IsClosing(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.closing[id]
	return ok
}
func (s *memoryStores) MarkClosing(id string, lt, b uint64, sig string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.closed[id]; !ok {
		s.closing[id] = ClosingData{ExpiryTimestamp: lt, Balance: b, Signature: sig}
	}
}
func (s *memoryStores) GetClosingData(id string) (*ClosingData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.closing[id]
	return &d, ok
}
func (s *memoryStores) IsClosed(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.closed[id]
	return ok
}
func (s *memoryStores) MarkClosed(id string, d ClosedData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.closed[id]; !ok {
		s.closed[id] = d
		delete(s.closing, id)
	}
}
func (s *memoryStores) GetClosedData(id string) (*ClosedData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.closed[id]
	return &d, ok
}
func (s *memoryStores) GetKeyset(mint, kid string) (*KeysetCacheEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.keysets[KeysetKey{mint, kid}]
	return &d, ok
}
func (s *memoryStores) SetKeyset(mint, kid string, e KeysetCacheEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keysets[KeysetKey{mint, kid}] = e
}
func (s *memoryStores) GetActiveKeysetIds(mint, unit string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var res []string
	for k, v := range s.keysets {
		if k.Mint == mint && v.Unit == unit && v.Active {
			res = append(res, k.KeysetId)
		}
	}
	return res
}
func (s *memoryStores) GetMintsUnitsKeysets() map[string]map[string][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make(map[string]map[string][]string)
	for k, v := range s.keysets {
		if !v.Active {
			continue
		}
		if res[k.Mint] == nil {
			res[k.Mint] = make(map[string][]string)
		}
		res[k.Mint][v.Unit] = append(res[k.Mint][v.Unit], k.KeysetId)
	}
	return res
}
func (s *memoryStores) GetActiveUnits() map[string]struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make(map[string]struct{})
	for _, v := range s.keysets {
		if v.Active {
			res[v.Unit] = struct{}{}
		}
	}
	return res
}

type sqliteStores struct {
	db           *sql.DB
	fundingCache map[string]*ChannelFundingData
	mu           sync.RWMutex
}

func NewSqliteStores(dbPath string) (SpilmanStores, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS spilman_channels (
        channel_id    TEXT NOT NULL PRIMARY KEY,
        funding_json  TEXT NOT NULL,
        balance       INTEGER NOT NULL DEFAULT 0,
        signature     TEXT NOT NULL DEFAULT '',
        state         TEXT NOT NULL DEFAULT 'Open',
        closing_json  TEXT,
        closed_json   TEXT
    );

    CREATE TABLE IF NOT EXISTS spilman_usage (
        channel_id TEXT NOT NULL,
        var_name   TEXT NOT NULL,
        count      INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (channel_id, var_name)
    );

    CREATE TABLE IF NOT EXISTS spilman_keysets (
        mint_url   TEXT NOT NULL,
        keyset_id  TEXT NOT NULL,
        entry_json TEXT NOT NULL,
        PRIMARY KEY (mint_url, keyset_id)
    );
	`)
	if err != nil {
		return nil, err
	}

	return &sqliteStores{
		db:           db,
		fundingCache: make(map[string]*ChannelFundingData),
	}, nil
}

func (s *sqliteStores) GetFunding(id string) (*ChannelFundingData, bool) {
	s.mu.RLock()
	if d, ok := s.fundingCache[id]; ok {
		s.mu.RUnlock()
		return d, true
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Double check
	if d, ok := s.fundingCache[id]; ok {
		return d, true
	}

	var f string
	err := s.db.QueryRow("SELECT funding_json FROM spilman_channels WHERE channel_id = ?", id).Scan(&f)
	if err != nil {
		return nil, false
	}
	var d struct{ Params, Proofs, Secret, Keyset string }
	json.Unmarshal([]byte(f), &d)
	res := &ChannelFundingData{ParamsJson: d.Params, FundingProofsJson: d.Proofs, ChannelSecret: d.Secret, KeysetInfoJson: d.Keyset}

	s.fundingCache[id] = res

	return res, true
}

func (s *sqliteStores) InsertFunding(id string, data ChannelFundingData) {
	d := struct{ Params, Proofs, Secret, Keyset string }{
		Params: data.ParamsJson, Proofs: data.FundingProofsJson, Secret: data.ChannelSecret, Keyset: data.KeysetInfoJson,
	}
	b, _ := json.Marshal(d)
	res, _ := s.db.Exec("INSERT INTO spilman_channels (channel_id, funding_json) VALUES (?, ?) ON CONFLICT DO NOTHING", id, string(b))

	s.mu.Lock()
	defer s.mu.Unlock()

	if res != nil {
		if n, _ := res.RowsAffected(); n > 0 {
			s.fundingCache[id] = &data
			return
		}
	}
	// If conflict occurred or error, invalidate cache so next Get gets the truth from DB
	delete(s.fundingCache, id)
}

func (s *sqliteStores) AllFunding() map[string]ChannelFundingData {
	rows, _ := s.db.Query("SELECT channel_id, funding_json FROM spilman_channels")
	if rows == nil {
		return make(map[string]ChannelFundingData)
	}
	defer rows.Close()
	res := make(map[string]ChannelFundingData)

	s.mu.Lock()
	defer s.mu.Unlock()

	for rows.Next() {
		var id, f string
		rows.Scan(&id, &f)
		var d struct{ Params, Proofs, Secret, Keyset string }
		json.Unmarshal([]byte(f), &d)
		fd := ChannelFundingData{ParamsJson: d.Params, FundingProofsJson: d.Proofs, ChannelSecret: d.Secret, KeysetInfoJson: d.Keyset}
		res[id] = fd

		// Populate cache
		cached := fd
		s.fundingCache[id] = &cached
	}
	return res
}

func (s *sqliteStores) GetBalance(id string) (*ChannelBalance, bool) {
	var b uint64
	var sig string
	err := s.db.QueryRow("SELECT balance, signature FROM spilman_channels WHERE channel_id = ? AND signature != ''", id).Scan(&b, &sig)
	if err != nil {
		return nil, false
	}
	return &ChannelBalance{b, sig}, true
}

func (s *sqliteStores) UpdateBalance(id string, b uint64, sig string) {
	s.db.Exec("UPDATE spilman_channels SET balance = ?, signature = ? WHERE channel_id = ? AND (balance < ? OR signature = '')", b, sig, id, b)
}

func (s *sqliteStores) GetUsage(id string) UsageMap {
	rows, _ := s.db.Query("SELECT var_name, count FROM spilman_usage WHERE channel_id = ?", id)
	defer rows.Close()
	res := make(UsageMap)
	for rows.Next() {
		var n string
		var c uint64
		rows.Scan(&n, &c)
		res[n] = c
	}
	return res
}

func (s *sqliteStores) IncrementUsage(id string, incs UsageMap) {
	tx, _ := s.db.Begin()
	for n, d := range incs {
		tx.Exec("INSERT INTO spilman_usage (channel_id, var_name, count) VALUES (?, ?, ?) ON CONFLICT(channel_id, var_name) DO UPDATE SET count = spilman_usage.count + excluded.count", id, n, d)
	}
	tx.Commit()
}

func (s *sqliteStores) IsClosing(id string) bool {
	var st string
	s.db.QueryRow("SELECT state FROM spilman_channels WHERE channel_id = ?", id).Scan(&st)
	return st == "Closing"
}

func (s *sqliteStores) MarkClosing(id string, lt, b uint64, sig string) {
	d, _ := json.Marshal(ClosingData{ExpiryTimestamp: lt, Balance: b, Signature: sig})
	s.db.Exec("UPDATE spilman_channels SET state = 'Closing', closing_json = ? WHERE channel_id = ? AND state != 'Closed'", string(d), id)
}

func (s *sqliteStores) GetClosingData(id string) (*ClosingData, bool) {
	var j string
	err := s.db.QueryRow("SELECT closing_json FROM spilman_channels WHERE channel_id = ? AND state = 'Closing'", id).Scan(&j)
	if err != nil || j == "" {
		return nil, false
	}
	var d ClosingData
	json.Unmarshal([]byte(j), &d)
	return &d, true
}

func (s *sqliteStores) IsClosed(id string) bool {
	var st string
	s.db.QueryRow("SELECT state FROM spilman_channels WHERE channel_id = ?", id).Scan(&st)
	return st == "Closed"
}

func (s *sqliteStores) MarkClosed(id string, data ClosedData) {
	b, _ := json.Marshal(data)
	s.db.Exec("UPDATE spilman_channels SET state = 'Closed', closed_json = ?, closing_json = NULL WHERE channel_id = ? AND state != 'Closed'", string(b), id)

	s.mu.Lock()
	delete(s.fundingCache, id)
	s.mu.Unlock()
}

func (s *sqliteStores) GetClosedData(id string) (*ClosedData, bool) {
	var j string
	err := s.db.QueryRow("SELECT closed_json FROM spilman_channels WHERE channel_id = ? AND state = 'Closed'", id).Scan(&j)
	if err != nil || j == "" {
		return nil, false
	}
	var d ClosedData
	json.Unmarshal([]byte(j), &d)
	return &d, true
}

func (s *sqliteStores) GetKeyset(mint, kid string) (*KeysetCacheEntry, bool) {
	var j string
	err := s.db.QueryRow("SELECT entry_json FROM spilman_keysets WHERE mint_url = ? AND keyset_id = ?", mint, kid).Scan(&j)
	if err != nil {
		return nil, false
	}
	var e KeysetCacheEntry
	json.Unmarshal([]byte(j), &e)
	return &e, true
}

func (s *sqliteStores) SetKeyset(mint, kid string, e KeysetCacheEntry) {
	j, _ := json.Marshal(e)
	s.db.Exec("INSERT INTO spilman_keysets (mint_url, keyset_id, entry_json) VALUES (?, ?, ?) ON CONFLICT(mint_url, keyset_id) DO UPDATE SET entry_json = excluded.entry_json", mint, kid, string(j))
}

func (s *sqliteStores) GetActiveKeysetIds(mint, unit string) []string {
	rows, _ := s.db.Query("SELECT entry_json, keyset_id FROM spilman_keysets WHERE mint_url = ?", mint)
	defer rows.Close()
	var res []string
	for rows.Next() {
		var j, kid string
		rows.Scan(&j, &kid)
		var e KeysetCacheEntry
		json.Unmarshal([]byte(j), &e)
		if e.Active && e.Unit == unit {
			res = append(res, kid)
		}
	}
	return res
}

func (s *sqliteStores) GetMintsUnitsKeysets() map[string]map[string][]string {
	rows, _ := s.db.Query("SELECT mint_url, entry_json, keyset_id FROM spilman_keysets")
	defer rows.Close()
	res := make(map[string]map[string][]string)
	for rows.Next() {
		var m, j, kid string
		rows.Scan(&m, &j, &kid)
		var e KeysetCacheEntry
		json.Unmarshal([]byte(j), &e)
		if !e.Active {
			continue
		}
		if res[m] == nil {
			res[m] = make(map[string][]string)
		}
		res[m][e.Unit] = append(res[m][e.Unit], kid)
	}
	return res
}

func (s *sqliteStores) GetActiveUnits() map[string]struct{} {
	rows, _ := s.db.Query("SELECT entry_json FROM spilman_keysets")
	defer rows.Close()
	res := make(map[string]struct{})
	for rows.Next() {
		var j string
		rows.Scan(&j)
		var e KeysetCacheEntry
		json.Unmarshal([]byte(j), &e)
		if e.Active {
			res[e.Unit] = struct{}{}
		}
	}
	return res
}
