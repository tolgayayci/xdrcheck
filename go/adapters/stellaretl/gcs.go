package stellaretl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsouza/fake-gcs-server/fakestorage"
)

// Bucket and prefix under which a session's ledgers are served. stellar-etl reads
// `<--datastore-path>/<network>/`, so a layout is published at `xdrcheck/lake/<network>/…` and stellar-etl is started
// with `--datastore-path xdrcheck/lake`.
const (
	gcsBucket    = "xdrcheck"
	gcsPathRoot  = "lake"
	datastoreArg = gcsBucket + "/" + gcsPathRoot
)

// emulator is a GCS-compatible endpoint on loopback serving one SEP-54 directory: fake-gcs-server's library
// (the emulator go-stellar-sdk's own datastore tests use) behind a listener of our own, so every request is
// logged as delivery evidence. stellar-etl reaches it through STORAGE_EMULATOR_HOST, which makes the Google
// storage client skip authentication.
type emulator struct {
	host string // host:port, the value of STORAGE_EMULATOR_HOST
	srv  *fakestorage.Server
	http *http.Server
	ln   net.Listener

	mu  sync.Mutex
	log []gcsRequest
}

// gcsRequest is one request the emulator answered.
type gcsRequest struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}

// startEmulator publishes the SEP-54 directory dir (`.config.json` plus `<partition>/<object>.xdr.zst`) under
// network's prefix and listens on addr (host:port; port 0 picks one).
func startEmulator(dir, network, addr string) (*emulator, error) {
	var objs []fakestorage.Object
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name := gcsPathRoot + "/" + network + "/" + filepath.ToSlash(rel)
		objs = append(objs, fakestorage.Object{ObjectAttrs: fakestorage.ObjectAttrs{BucketName: gcsBucket, Name: name}, Content: b})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read the ledger layout: %w", err)
	}
	if len(objs) == 0 {
		return nil, fmt.Errorf("the ledger layout %s holds no objects", dir)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	host := ln.Addr().String()
	srv, err := fakestorage.NewServerWithOptions(fakestorage.Options{
		InitialObjects: objs, NoListener: true, Scheme: "http", PublicHost: host, ExternalURL: "http://" + host,
		Writer: io.Discard,
	})
	if err != nil {
		ln.Close()
		return nil, err
	}
	e := &emulator{host: host, srv: srv, ln: ln}
	h := srv.HTTPHandler()
	e.http = &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(sw, r)
		e.mu.Lock()
		e.log = append(e.log, gcsRequest{Method: r.Method, Path: r.URL.EscapedPath(), Status: sw.status})
		e.mu.Unlock()
	})}
	go e.http.Serve(ln)
	return e, nil
}

// requests returns the requests answered so far.
func (e *emulator) requests() []gcsRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]gcsRequest(nil), e.log...)
}

// servedLedgers lists the ledger objects read with status 200, by the sequence in their file name
// (`<hex>--<seq>.xdr.zst`, or `<hex>--<first>-<last>.xdr.zst` for a batch).
func (e *emulator) servedLedgers() []string {
	var out []string
	for _, r := range e.requests() {
		if r.Status != http.StatusOK || !strings.HasSuffix(r.Path, ".xdr.zst") {
			continue
		}
		p := strings.ReplaceAll(r.Path, "%2F", "/")
		base := p[strings.LastIndex(p, "/")+1:]
		_, seq, ok := strings.Cut(strings.TrimSuffix(base, ".xdr.zst"), "--")
		if ok {
			out = append(out, seq)
		}
	}
	return out
}

func (e *emulator) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := e.http.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		e.http.Close()
	}
	e.srv.Stop()
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// listenAddr is the loopback address for a session: the first port of the harness's range, else any port.
func listenAddr(first int) string {
	if first > 0 {
		return "127.0.0.1:" + strconv.Itoa(first)
	}
	return "127.0.0.1:0"
}
