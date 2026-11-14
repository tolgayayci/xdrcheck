package rig

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tolgayayci/xdrcheck/go/internal/lake"
)

// PublicLake is the public SEP-54 data lake of the main network, the default source of neighbour ledgers.
const PublicLake = "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/v1.1/stellar/ledgers/pubnet"

// Lake reads ledgers from a directory in the public lake's layout (`<partition>/<file>.xdr.zst`, one ledger per
// file, optionally with an `index.tsv` of seq, path, size). Ledgers it does not hold are fetched from Fetch
// into Cache when both are set, so a rig can read a sparse sample's neighbours.
type Lake struct {
	Dir   string
	Cfg   lake.Config
	Fetch string // base URL of a lake with the same layout; empty: never fetch
	Cache string // where fetched objects are kept, in the same layout

	index map[uint32]string
	mu    sync.Mutex
	hc    *http.Client
}

// OpenLake opens a lake directory for a network passphrase.
func OpenLake(dir, passphrase, fetch, cache string) (*Lake, error) {
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("lake %s is not a directory", dir)
	}
	l := &Lake{Dir: dir, Cfg: lake.NewConfig(passphrase), Fetch: strings.TrimRight(fetch, "/"), Cache: cache,
		index: map[uint32]string{}, hc: &http.Client{Timeout: 60 * time.Second}}
	if f, err := os.Open(filepath.Join(dir, "index.tsv")); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fs := strings.Split(sc.Text(), "\t")
			if len(fs) < 2 {
				continue
			}
			n, err := strconv.ParseUint(fs[0], 10, 32)
			if err != nil {
				continue
			}
			l.index[uint32(n)] = fs[1]
		}
	}
	return l, nil
}

// Has reports whether the lake directory itself holds a ledger (without fetching).
func (l *Lake) Has(seq uint32) bool {
	_, err := os.Stat(l.local(seq))
	return err == nil
}

func (l *Lake) local(seq uint32) string {
	if p, ok := l.index[seq]; ok {
		return filepath.Join(l.Dir, p)
	}
	return filepath.Join(l.Dir, l.Cfg.ObjectKey(seq))
}

// Path returns the file holding a ledger, fetching it into the cache when the lake does not hold it.
func (l *Lake) Path(ctx context.Context, seq uint32) (string, error) {
	if p := l.local(seq); fileExists(p) {
		return p, nil
	}
	if l.Cache == "" || l.Fetch == "" {
		return "", fmt.Errorf("ledger %d is not in %s and no fetch source is set", seq, l.Dir)
	}
	key := l.Cfg.ObjectKey(seq)
	dst := filepath.Join(l.Cache, key)
	if fileExists(dst) {
		return dst, nil
	}
	if err := l.fetch(ctx, key, dst, seq); err != nil {
		return "", err
	}
	return dst, nil
}

// Load returns a ledger's LedgerCloseMeta bytes.
func (l *Lake) Load(ctx context.Context, seq uint32) ([]byte, error) {
	p, err := l.Path(ctx, seq)
	if err != nil {
		return nil, err
	}
	got, lcm, err := lake.ReadObject(p)
	if err != nil {
		return nil, fmt.Errorf("ledger %d (%s): %w", seq, p, err)
	}
	if got != seq {
		return nil, fmt.Errorf("ledger %d: %s holds ledger %d", seq, p, got)
	}
	return lcm, nil
}

func (l *Lake) fetch(ctx context.Context, key, dst string, seq uint32) error {
	var last error
	for attempt := 0; attempt < 6; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * 500 * time.Millisecond):
			}
		}
		last = l.fetchOnce(ctx, key, dst, seq)
		if last == nil {
			return nil
		}
	}
	return fmt.Errorf("fetch ledger %d: %w", seq, last)
}

func (l *Lake) fetchOnce(ctx context.Context, key, dst string, seq uint32) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.Fetch+"/"+key, nil)
	if err != nil {
		return err
	}
	resp, err := l.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", key, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.part-%d", dst, os.Getpid())
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	got, _, err := lake.ReadObject(tmp)
	if err == nil && got != seq {
		err = fmt.Errorf("object %s holds ledger %d", key, got)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// View writes a lake directory holding exactly the given ledgers (symbolic links to the source files) and the
// layout manifest, for a pipeline that reads a datastore.
func (l *Lake) View(ctx context.Context, dir string, seqs []uint32) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, lake.ConfigFile), l.Cfg.Bytes(), 0o644); err != nil {
		return err
	}
	for _, s := range seqs {
		src, err := l.Path(ctx, s)
		if err != nil {
			return err
		}
		abs, err := filepath.Abs(src)
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, l.Cfg.ObjectKey(s))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.Symlink(abs, dst); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	return nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}
