package rig

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
)

// A state seed: ledger entries as an RPC's getLedgerEntries returns them, kept in <dir>/entries.jsonl (one
// protocol.LedgerEntryResult per line, `key` set). It stands in for the history-archive checkpoint a fresh
// service loads first: the entries are the network's state when they were fetched, not at the replayed ledger.

// SeedFile is the seed's file name inside its directory.
const SeedFile = "entries.jsonl"

// LoadSeed reads a seed directory; a missing directory or file is an empty seed.
func LoadSeed(dir string) (map[string]protocol.LedgerEntryResult, error) {
	out := map[string]protocol.LedgerEntryResult{}
	if dir == "" {
		return out, nil
	}
	f, err := os.Open(filepath.Join(dir, SeedFile))
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 512<<20)
	for sc.Scan() {
		var e protocol.LedgerEntryResult
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("%s: %v", SeedFile, err)
		}
		out[e.KeyXDR] = e
	}
	return out, sc.Err()
}

// SaveSeed writes a seed directory (sorted by key).
func SaveSeed(dir string, seed map[string]protocol.LedgerEntryResult) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	keys := make([]string, 0, len(seed))
	for k := range seed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for _, k := range keys {
		e := seed[k]
		e.KeyXDR = k
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	tmp := filepath.Join(dir, SeedFile+".tmp")
	if err := os.WriteFile(tmp, b.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, SeedFile))
}

// FetchEntries asks an RPC for ledger entries (getLedgerEntries, 200 keys per call). header is one optional
// "Name: value" request header (for an RPC that needs a key); it is never logged. Keys the RPC does not return
// are absent from the result.
func FetchEntries(ctx context.Context, url, header string, keys []string) (map[string]protocol.LedgerEntryResult, error) {
	out := map[string]protocol.LedgerEntryResult{}
	hc := &http.Client{Timeout: 60 * time.Second}
	for i := 0; i < len(keys); i += 200 {
		batch := keys[i:min(i+200, len(keys))]
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": i, "method": protocol.GetLedgerEntriesMethodName,
			"params": protocol.GetLedgerEntriesRequest{Keys: batch}})
		var res struct {
			Result *protocol.GetLedgerEntriesResponse `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		var last error
		for attempt := 0; attempt < 5; attempt++ {
			if attempt > 0 {
				time.Sleep(time.Duration(attempt) * time.Second)
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")
			if name, value, ok := strings.Cut(header, ":"); ok {
				req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
			}
			resp, err := hc.Do(req)
			if err != nil {
				last = err
				continue
			}
			data, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
			resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK {
				last = fmt.Errorf("getLedgerEntries: HTTP %d %v", resp.StatusCode, err)
				continue
			}
			res.Result, res.Error = nil, nil
			if err := json.Unmarshal(data, &res); err != nil {
				last = err
				continue
			}
			if res.Error != nil {
				last = fmt.Errorf("getLedgerEntries: %d %s", res.Error.Code, res.Error.Message)
				continue
			}
			last = nil
			break
		}
		if last != nil {
			return nil, last
		}
		for _, e := range res.Result.Entries {
			out[e.KeyXDR] = e
		}
	}
	return out, nil
}
