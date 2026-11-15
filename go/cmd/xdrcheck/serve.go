package main

// xdrcheck serve: plan one pass of the corpus and serve its replay units until interrupted.
//
//	xdrcheck serve --corpus DIR --network testnet|pubnet|core-test
//	          [--entries GLOB | --chain ID | --ledgers S..E] [--unit single|chain|stream]
//	          (--sep54-dir OUT | --s3 ADDR | --gcs ADDR | --rpc ADDR)...
//	          [--proxy-to URL] [--delivery-log FILE] [--stream-base N]
//
// Each unit is served on its own: under --sep54-dir OUT as the layout OUT/<unit>/; over --rpc ADDR as the
// JSON-RPC endpoint http://ADDR/<unit> (and http://ADDR/ when there is one unit); over --s3 ADDR as the store
// root <bucket>/<unit> of a SeaweedFS store whose logging proxy listens on ADDR. One JSON line per served view
// goes to stdout, then {"ready":true}. --gcs and --proxy-to are the optional, unbuilt modes of
// replay-harness.md §2.2 and exit 2.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
	"github.com/tolgayayci/xdrcheck/go/internal/objstore"
	"github.com/tolgayayci/xdrcheck/go/internal/pins"
	"github.com/tolgayayci/xdrcheck/go/internal/replay/plan"
)

func init() {
	register("serve", "serve corpus ledgers as a SEP-54 layout, an object store, or a mock getLedgers", func(args []string) int {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return serve(ctx, args, os.Stdout, os.Stderr)
	})
}

// served is one line of serve's stdout.
type served struct {
	Unit        string   `json:"unit"`
	Kind        string   `json:"kind"`
	Network     string   `json:"network"`
	First       uint32   `json:"first"`
	Last        uint32   `json:"last"`
	Transformed bool     `json:"transformed,omitempty"`
	Entries     []string `json:"entries"`
	View        string   `json:"view"` // sep54-dir, rpc, s3
	Dir         string   `json:"dir,omitempty"`
	URL         string   `json:"url,omitempty"`
	Bucket      string   `json:"bucket,omitempty"`
	Path        string   `json:"path,omitempty"` // s3: <bucket>/<prefix>, the datastore's bucket path
	StoreMode   string   `json:"store_mode,omitempty"`
}

func serve(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xdrcheck serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		corpus   = fs.String("corpus", "corpus", "corpus root")
		network  = fs.String("network", "", "pass to serve: testnet, pubnet or core-test (required)")
		entries  = fs.String("entries", "", "entry ID glob")
		chain    = fs.String("chain", "", "serve this chain run as one chain unit")
		ledgers  = fs.String("ledgers", "", "S..E: only ledgers in this range")
		unit     = fs.String("unit", "", "single, chain or stream (default: what each entry needs)")
		sep54Dir = fs.String("sep54-dir", "", "write each unit's SEP-54 layout under this directory")
		s3Addr   = fs.String("s3", "", "serve the layouts from an S3 store whose logging proxy listens here")
		gcsAddr  = fs.String("gcs", "", "GCS endpoint (not built)")
		rpcAddr  = fs.String("rpc", "", "serve the mock getLedgers here")
		proxyTo  = fs.String("proxy-to", "", "log and forward to an external emulator (not built)")
		delivery = fs.String("delivery-log", "", "append one JSON line per request to this file")
		base     = fs.Uint("stream-base", 1000, "first sequence of a stream unit")
		pinsFile = fs.String("pins", "pins.toml", "pins file (for the object-store image)")
		overlay  = fs.String("overlay", os.Getenv("XDRCHECK_OVERLAY"), "private overlay (not supported by serve yet)")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "xdrcheck serve: "+format+"\n", a...)
		return 2
	}
	if fs.NArg() > 0 {
		return fail("unexpected arguments %v", fs.Args())
	}
	switch *network {
	case "testnet", "pubnet", "core-test":
	default:
		return fail("--network must be testnet, pubnet or core-test")
	}
	if *gcsAddr != "" || *proxyTo != "" {
		return fail("--gcs and --proxy-to are optional serving modes that are not built (replay-harness.md §2.2)")
	}
	if *overlay != "" {
		return fail("--overlay is not supported by serve")
	}
	if *sep54Dir == "" && *s3Addr == "" && *rpcAddr == "" {
		return fail("give at least one of --sep54-dir, --s3, --rpc")
	}
	n := 0
	for _, s := range []string{*entries, *chain, *ledgers} {
		if s != "" {
			n++
		}
	}
	if n > 1 {
		return fail("--entries, --chain and --ledgers are alternatives")
	}
	o := plan.Options{Networks: []string{*network}, Chain: *chain, Unit: *unit, StreamBase: uint32(*base)}
	if *entries != "" {
		o.Entries = strings.Split(*entries, ",")
	}
	if *ledgers != "" {
		lo, hi, ok := strings.Cut(*ledgers, "..")
		a, err1 := strconv.ParseUint(lo, 10, 32)
		b, err2 := strconv.ParseUint(hi, 10, 32)
		if !ok || err1 != nil || err2 != nil || a > b || b == 0 {
			return fail("--ledgers must be S..E")
		}
		o.Ledgers = [2]uint32{uint32(a), uint32(b)}
	}

	c, err := manifest.Load(*corpus, manifest.Options{})
	if err != nil {
		return fail("%v", err)
	}
	p, err := plan.Build(c, o)
	if err != nil {
		return fail("%v", err)
	}
	for _, it := range p.Items {
		if it.Status != plan.StatusRun {
			fmt.Fprintf(stderr, "not served: %s %s: %s · %s (%s)\n", it.Entry, it.Variant, it.Status, it.Qualifier, it.Detail)
		}
	}
	if len(p.Passes) == 0 || len(p.Passes[0].Units) == 0 {
		return fail("nothing to serve on %s with these filters", *network)
	}
	units := p.Passes[0].Units

	var logOut io.Writer
	if *delivery != "" {
		f, err := os.OpenFile(*delivery, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fail("%v", err)
		}
		defer f.Close()
		logOut = f
	}
	dlog := lake.NewDeliveryLog(logOut)
	nonce := randomHex(8)
	enc := json.NewEncoder(stdout)
	line := func(u *plan.Unit, s served) {
		s.Unit, s.Kind, s.Network, s.First, s.Last, s.Transformed = u.ID, u.Kind, u.Network, u.First(), u.Last(), u.Transformed
		for _, e := range u.Entries {
			if len(s.Entries) == 0 || s.Entries[len(s.Entries)-1] != e.Entry {
				s.Entries = append(s.Entries, e.Entry)
			}
		}
		enc.Encode(s)
	}

	// SEP-54 layouts: in --sep54-dir, or in a temporary directory when only --s3 needs them.
	layouts := map[string]*lake.Layout{}
	if *sep54Dir != "" || *s3Addr != "" {
		root := *sep54Dir
		if root == "" {
			tmp, err := os.MkdirTemp("", "xdrcheck-serve-")
			if err != nil {
				return fail("%v", err)
			}
			defer os.RemoveAll(tmp)
			root = tmp
		}
		for _, u := range units {
			l, err := u.WriteLayout(filepath.Join(root, u.ID))
			if err != nil {
				return fail("unit %s: %v", u.ID, err)
			}
			layouts[u.ID] = l
			if *sep54Dir != "" {
				abs, _ := filepath.Abs(l.Dir)
				line(u, served{View: "sep54-dir", Dir: abs})
			}
		}
	}

	if *rpcAddr != "" {
		mux := http.NewServeMux()
		for _, u := range units {
			srv, err := u.RPCServer(nonce, dlog)
			if err != nil {
				return fail("unit %s: %v", u.ID, err)
			}
			mux.Handle("/"+u.ID, srv)
			if len(units) == 1 {
				mux.Handle("/", srv)
			}
		}
		ln, err := net.Listen("tcp", *rpcAddr)
		if err != nil {
			return fail("--rpc: %v", err)
		}
		hs := &http.Server{Handler: mux}
		go hs.Serve(ln)
		defer hs.Close()
		for _, u := range units {
			line(u, served{View: "rpc", URL: "http://" + ln.Addr().String() + "/" + u.ID})
		}
	}

	if *s3Addr != "" {
		pinsPath := *pinsFile
		if _, err := os.Stat(pinsPath); errors.Is(err, os.ErrNotExist) && !filepath.IsAbs(pinsPath) {
			pinsPath = filepath.Join(filepath.Dir(filepath.Clean(*corpus)), *pinsFile)
		}
		pn, err := pins.Load(pinsPath)
		if err != nil {
			return fail("--s3 needs the pinned store image: %v", err)
		}
		st, err := objstore.Launch(ctx, objstore.Options{Image: pn.Images["seaweedfs"], ProxyAddr: *s3Addr, Log: dlog})
		if err != nil {
			return fail("--s3: %v", err)
		}
		defer st.Close()
		for _, note := range st.Notes {
			fmt.Fprintln(stderr, "s3:", note)
		}
		for _, u := range units {
			if err := st.Upload(ctx, u.ID, layouts[u.ID]); err != nil {
				return fail("--s3: unit %s: %v", u.ID, err)
			}
			if err := st.ReadBack(ctx, u.ID, layouts[u.ID]); err != nil {
				return fail("--s3: unit %s: %v", u.ID, err)
			}
			line(u, served{View: "s3", URL: st.Endpoint, Bucket: st.Bucket, Path: st.Bucket + "/" + u.ID, StoreMode: st.Mode})
		}
	}

	enc.Encode(map[string]any{"ready": true, "units": len(units), "nonce": nonce})
	<-ctx.Done()
	return 0
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
