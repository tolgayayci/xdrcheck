package walletbackend

// `wallet-backend-adapter fetch`: the adapter's only networked step. It clones (or updates) the repository
// named in pins.toml into the cache, builds the requested commits with the pinned Go toolchain (downloading the
// toolchain and the modules into the cache's module cache), and checks that the pinned database image and the
// pinned object-store image (which the harness serves the sep54-s3 input from) are present locally, pulling
// each by digest when it is not. Afterwards every run works offline.

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
)

func fetchMain(args []string) int {
	fs := flag.NewFlagSet("wallet-backend-adapter fetch", flag.ContinueOnError)
	pinsPath := fs.String("pins", "", "pins.toml (default: found upwards from the working directory)")
	cache := fs.String("cachedir", "", "cache root (default <user cache>/xdrcheck/adapters)")
	from := fs.String("from", "", "clone from this URL or path instead of the repository in pins.toml")
	commits := fs.String("commits", "", "comma-separated commits to build (default: every pinned acceptance commit and the current one)")
	noImage := fs.Bool("no-image", false, "do not check or pull the database image")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*pinsPath, *cache, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "fetch:", err)
		return 2
	}
	if err := fetch(context.Background(), cfg, *from, *commits, !*noImage); err != nil {
		fmt.Fprintln(os.Stderr, "fetch:", err)
		return 1
	}
	return 0
}

// pinnedCommits lists the acceptance commits and the current commit of pins.toml.
func pinnedCommits(cfg *config) []string {
	wb := cfg.pins.Pipelines.WalletBackend
	var out []string
	for _, a := range wb.Acceptance {
		out = append(out, a.Prefix, a.Fixed)
	}
	return append(out, wb.Current)
}

func fetch(ctx context.Context, cfg *config, from, commits string, image bool) error {
	r := cfg.repo(true)
	url := from
	if url == "" {
		url = cfg.pins.Pipelines.WalletBackend.Repo
	}
	list := pinnedCommits(cfg)
	if commits != "" {
		list = strings.Split(commits, ",")
	}
	need := !r.present()
	for _, c := range list {
		if need {
			break
		}
		if _, err := r.resolve(ctx, c); err != nil {
			need = true
		}
	}
	if need {
		fmt.Fprintf(os.Stderr, "fetch: cloning %s into %s\n", url, r.gitDir())
		if err := r.clone(ctx, url); err != nil {
			return err
		}
	}
	for _, c := range list {
		full, err := r.resolve(ctx, c)
		if err != nil {
			return err
		}
		b, err := r.build(ctx, full, os.Stderr)
		if err != nil {
			return err
		}
		state := "built"
		if b.Cached {
			state = "cached"
		}
		fmt.Fprintf(os.Stderr, "fetch: %s %s sha256 %s (%s)\n", full, state, b.SHA256, b.Wall.Round(1e6))
	}
	if !image {
		return nil
	}
	// The database image, and the object store the harness serves the sep54-s3 input from.
	for _, key := range []string{"timescaledb", "seaweedfs"} {
		img := cfg.pins.Images[key]
		if img == "" {
			return fmt.Errorf("pins.toml [images] has no %s", key)
		}
		if _, err := docker(ctx, nil, "image", "inspect", "--format", "{{.Id}}", img); err != nil {
			fmt.Fprintf(os.Stderr, "fetch: pulling %s\n", img)
			if _, err := docker(ctx, nil, "pull", "--quiet", img); err != nil {
				return err
			}
		}
		fmt.Fprintf(os.Stderr, "fetch: image present: %s\n", img)
	}
	return nil
}
