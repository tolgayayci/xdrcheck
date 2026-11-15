package dataset

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
	"github.com/tolgayayci/xdrcheck/go/internal/lake"
)

// Passphrases of the two public networks.
const (
	PubnetPassphrase  = "Public Global Stellar Network ; September 2015"
	TestnetPassphrase = "Test SDF Network ; September 2015"
)

// PublicLakeURL is the public SEP-54 data lake of pubnet (one zstd LedgerCloseMetaBatch per ledger).
const PublicLakeURL = "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/v1.1/stellar/ledgers/pubnet/"

// Passphrase returns the passphrase of a network name.
func Passphrase(network string) (string, error) {
	switch network {
	case "pubnet", "":
		return PubnetPassphrase, nil
	case "testnet":
		return TestnetPassphrase, nil
	}
	return "", fmt.Errorf("unknown network %q (pubnet or testnet)", network)
}

// IndexFile is a lake directory's index: seq<TAB>path<TAB>size[<TAB>md5], with a header line.
const IndexFile = "index.tsv"

// Lake finds ledger objects in local lake-layout directories: read-only ones first (the dataset's kept set),
// then the writable cache that Fetch fills.
type Lake struct {
	ReadOnly []string
	Cache    string
	Network  string
}

// LakeDir returns the writable ledger cache: --lake, else $<TOOL>_LAKE, else <dataset dir>/lake.
func LakeDir(flag, datasetDir string) string {
	if flag != "" {
		return flag
	}
	if d := hunt.Env("LAKE"); d != "" {
		return d
	}
	return filepath.Join(datasetDir, "lake")
}

// NewLake returns the lake of a dataset (its read-only lakes, when m is not nil) with the cache dir.
func NewLake(m *Manifest, cache, network string) *Lake {
	l := &Lake{Cache: cache, Network: network}
	if m != nil && (network == "" || network == m.Network) {
		for _, p := range m.Lakes {
			l.ReadOnly = append(l.ReadOnly, m.Resolve(p))
		}
	}
	return l
}

// Key returns the lake object key of a ledger.
func (l *Lake) Key(seq uint32) string {
	pass, _ := Passphrase(l.Network)
	return lake.NewConfig(pass).ObjectKey(seq)
}

// Locate returns the path of a ledger's object, or "" when no local lake holds it.
func (l *Lake) Locate(seq uint32) string {
	key := l.Key(seq)
	for _, d := range append(append([]string{}, l.ReadOnly...), l.Cache) {
		if d == "" {
			continue
		}
		p := filepath.Join(d, key)
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return p
		}
	}
	return ""
}

// FetchOptions configure Fetch.
type FetchOptions struct {
	BaseURL  string  // lake URL ending in "/"; default PublicLakeURL for pubnet
	Parallel int     // requests in flight, at most 256
	Rate     float64 // GET requests per second, 0 = no cap
	Local    bool    // copy ledgers a read-only lake already holds instead of downloading them
	Progress func(done, total int, counts map[string]int)
	Client   *http.Client
	Retries  int // attempts per ledger (default 8), with exponential back-off between them
}

// FetchResult counts what Fetch did per ledger: ok (downloaded), have (already in the cache), local (copied
// from a read-only lake), and failures by kind.
type FetchResult struct {
	Counts map[string]int
	Failed map[uint32]string
	Bytes  int64
}

// Fetch puts every ledger of seqs into the cache directory, laid out like the lake, and checks each download's
// size against Content-Length and its MD5 against the ETag (the public lake's objects are single-part, so the
// ETag is their MD5). It is resumable: an object already in the cache with its recorded size and MD5 is kept.
// It writes <cache>/index.tsv at the end.
func (l *Lake) Fetch(ctx context.Context, seqs []uint32, o FetchOptions) (*FetchResult, error) {
	if l.Cache == "" {
		return nil, fmt.Errorf("no cache directory")
	}
	if o.BaseURL == "" {
		if l.Network != "pubnet" && l.Network != "" {
			return nil, fmt.Errorf("no public lake URL for %s: pass --lake-url", l.Network)
		}
		o.BaseURL = PublicLakeURL
	}
	if !strings.HasSuffix(o.BaseURL, "/") {
		o.BaseURL += "/"
	}
	if o.Parallel <= 0 {
		o.Parallel = 64
	}
	if o.Parallel > 256 {
		o.Parallel = 256
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 120 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: o.Parallel, MaxConnsPerHost: o.Parallel}}
	}
	if err := os.MkdirAll(l.Cache, 0o755); err != nil {
		return nil, err
	}
	known := readIndex(filepath.Join(l.Cache, IndexFile))
	var limiter <-chan time.Time
	if o.Rate > 0 {
		t := time.NewTicker(time.Duration(float64(time.Second) / o.Rate))
		defer t.Stop()
		limiter = t.C
	}
	res := &FetchResult{Counts: map[string]int{}, Failed: map[uint32]string{}}
	var mu sync.Mutex
	rows := map[uint32]indexRow{}
	for s, r := range known {
		rows[s] = r
	}
	jobs := make(chan uint32)
	var wg sync.WaitGroup
	var done atomic.Int64
	record := func(seq uint32, state string, r *indexRow, n int64) {
		mu.Lock()
		defer mu.Unlock()
		res.Counts[state]++
		res.Bytes += n
		if r != nil {
			rows[seq] = *r
		} else {
			res.Failed[seq] = state
		}
		d := int(done.Add(1))
		if o.Progress != nil && (d%500 == 0 || d == len(seqs)) {
			o.Progress(d, len(seqs), res.Counts)
		}
	}
	for w := 0; w < o.Parallel; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := range jobs {
				key := l.Key(seq)
				dst := filepath.Join(l.Cache, key)
				if r, ok := known[seq]; ok && fileMatches(dst, r.size, r.md5) {
					rr := r
					record(seq, "have", &rr, 0)
					continue
				}
				if o.Local {
					if src := l.locateReadOnly(seq); src != "" {
						if r, err := copyFile(src, dst); err == nil {
							r.path = key
							record(seq, "local", &r, 0)
							continue
						}
					}
				}
				r, state, n := l.download(ctx, o, limiter, key, dst)
				if r != nil {
					r.path = key
				}
				record(seq, state, r, n)
			}
		}()
	}
	for _, s := range seqs {
		select {
		case jobs <- s:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(jobs)
	wg.Wait()
	if err := writeIndex(filepath.Join(l.Cache, IndexFile), rows); err != nil {
		return res, err
	}
	return res, ctx.Err()
}

func (l *Lake) locateReadOnly(seq uint32) string {
	key := l.Key(seq)
	for _, d := range l.ReadOnly {
		p := filepath.Join(d, key)
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			return p
		}
	}
	return ""
}

func (l *Lake) download(ctx context.Context, o FetchOptions, limiter <-chan time.Time, key, dst string) (*indexRow, string, int64) {
	var last string
	tries := o.Retries
	if tries <= 0 {
		tries = 8
	}
	for attempt := 0; attempt < tries; attempt++ {
		if attempt > 0 {
			back := time.Duration(min(60, 1<<attempt)) * time.Second
			time.Sleep(time.Duration(float64(back) * (0.5 + rand.Float64())))
		}
		if limiter != nil {
			select {
			case <-limiter:
			case <-ctx.Done():
				return nil, "cancelled", 0
			}
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, o.BaseURL+key, nil)
		req.Header.Set("User-Agent", "lake-fetch/1")
		resp, err := o.Client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, "cancelled", 0
			}
			last = "network"
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch {
		case err != nil:
			last = "network"
			continue
		case resp.StatusCode == http.StatusNotFound:
			return nil, "not-found", 0
		case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
			last = "http" + strconv.Itoa(resp.StatusCode)
			continue
		case resp.StatusCode != http.StatusOK:
			return nil, "http" + strconv.Itoa(resp.StatusCode), 0
		}
		if resp.ContentLength >= 0 && int64(len(body)) != resp.ContentLength {
			last = "size-mismatch"
			continue
		}
		sum := md5.Sum(body)
		md := hex.EncodeToString(sum[:])
		etag := strings.Trim(resp.Header.Get("ETag"), `"`)
		if etag != "" && !strings.Contains(etag, "-") && etag != md {
			last = "md5-mismatch"
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, "write-error", 0
		}
		tmp := dst + ".tmp"
		if err := os.WriteFile(tmp, body, 0o644); err != nil {
			return nil, "write-error", 0
		}
		if err := os.Rename(tmp, dst); err != nil {
			return nil, "write-error", 0
		}
		return &indexRow{size: int64(len(body)), md5: md}, "ok", int64(len(body))
	}
	return nil, last, 0
}

type indexRow struct {
	path string
	size int64
	md5  string
}

func readIndex(path string) map[uint32]indexRow {
	out := map[uint32]indexRow{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), "\t")
		if len(p) < 3 {
			continue
		}
		s, err := strconv.ParseUint(p[0], 10, 32)
		if err != nil {
			continue
		}
		n, _ := strconv.ParseInt(p[2], 10, 64)
		r := indexRow{path: p[1], size: n}
		if len(p) > 3 {
			r.md5 = p[3]
		}
		out[uint32(s)] = r
	}
	return out
}

func writeIndex(path string, rows map[uint32]indexRow) error {
	seqs := make([]uint32, 0, len(rows))
	for s := range rows {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	var b strings.Builder
	b.WriteString("seq\tpath\tsize\tmd5\n")
	for _, s := range seqs {
		r := rows[s]
		fmt.Fprintf(&b, "%d\t%s\t%d\t%s\n", s, r.path, r.size, r.md5)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func fileMatches(path string, size int64, md string) bool {
	st, err := os.Stat(path)
	if err != nil || st.Size() != size {
		return false
	}
	if md == "" {
		return true
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	s := md5.Sum(b)
	return hex.EncodeToString(s[:]) == md
}

func copyFile(src, dst string) (indexRow, error) {
	b, err := os.ReadFile(src)
	if err != nil {
		return indexRow{}, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return indexRow{}, err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return indexRow{}, err
	}
	s := md5.Sum(b)
	return indexRow{size: int64(len(b)), md5: hex.EncodeToString(s[:])}, os.Rename(tmp, dst)
}
