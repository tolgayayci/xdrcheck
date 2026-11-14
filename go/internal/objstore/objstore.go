// Package objstore puts a SEP-54 layout behind an S3 endpoint: it launches SeaweedFS (the emulator
// wallet-backend's own tests use) by the image digest pinned in pins.toml, uploads layouts into a bucket, and
// fronts the store with a small logging reverse proxy, so the harness has its own record of every request a
// consumer makes (replay-harness.md §2.2, §2.5).
//
// Consumers are pointed at the proxy. Uploads and the read-back check go to the store directly and are not
// delivery records. The container is named `<prefix>-<n>` (default prefix `xdrcheck-serve`) and removed by Close;
// nothing is pulled (`--pull never`), so an image missing offline is an error, not a download.
//
// Where the container cannot be created (no container runtime rights, or a full snapshot disk), the store runs
// the image's own statically linked `weed` executable as a local process instead: it is extracted from the same
// pinned image with `docker save`, so the software is the same digest. Store.Mode says which was used, and every
// port is bound on loopback only.
package objstore

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/tolgayayci/xdrcheck/go/internal/lake"
	"github.com/tolgayayci/xdrcheck/go/internal/proc"
	"github.com/tolgayayci/xdrcheck/go/internal/userdir"
)

// Static dummy credentials and region. Without them the AWS SDK probes the instance-metadata address.
const (
	AccessKey = "test"
	SecretKey = "test"
	Region    = "us-east-1"
)

// Modes of running the store.
const (
	ModeAuto   = ""       // docker, falling back to the binary when the container cannot be created
	ModeDocker = "docker" // a container from the pinned image
	ModeBinary = "binary" // the image's own `weed` executable, extracted with `docker save`, run as a local process
)

// Options configure Launch.
type Options struct {
	Image        string // image reference with digest, from pins.toml [images] seaweedfs
	Mode         string // ModeAuto (default; XDRCHECK_OBJSTORE overrides), ModeDocker or ModeBinary
	NamePrefix   string // container name prefix; default "xdrcheck-serve"
	Bucket       string // default "ledgers"
	ProxyAddr    string // where the logging proxy listens; default 127.0.0.1:0
	DataDir      string // binary mode: the store's data directory; default a new temporary directory, removed by Close
	CacheDir     string // binary mode: where the extracted executable is kept; default <user cache>/xdrcheck/seaweedfs
	Log          *lake.DeliveryLog
	ReadyTimeout time.Duration // default 60 s
}

// Store is a running object store.
type Store struct {
	Mode      string // ModeDocker or ModeBinary, as used
	Container string // docker mode
	Binary    string // binary mode: the executable, and its sha256
	BinarySHA string
	Notes     []string // for example why the binary mode was used
	Bucket    string
	Endpoint  string // the logging proxy: give this to consumers
	Direct    string // the store itself

	client  *s3.Client // direct
	proxy   *http.Server
	log     *lake.DeliveryLog
	child   *proc.Child
	dataDir string
	ownData bool
}

var seq atomic.Int64

// Launch starts the store, waits until its S3 gateway answers, creates the bucket and starts the proxy.
func Launch(ctx context.Context, o Options) (*Store, error) {
	if !strings.Contains(o.Image, "@sha256:") {
		return nil, fmt.Errorf("objstore: image %q is not pinned by digest", o.Image)
	}
	if o.NamePrefix == "" {
		o.NamePrefix = "xdrcheck-serve"
	}
	if o.Bucket == "" {
		o.Bucket = "ledgers"
	}
	if o.ProxyAddr == "" {
		o.ProxyAddr = "127.0.0.1:0"
	}
	if o.ReadyTimeout == 0 {
		o.ReadyTimeout = 60 * time.Second
	}
	if o.Mode == ModeAuto {
		o.Mode = os.Getenv("XDRCHECK_OBJSTORE")
	}
	s := &Store{Bucket: o.Bucket, log: o.Log}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	var err error
	switch o.Mode {
	case ModeAuto, ModeDocker:
		err = s.startContainer(ctx, o)
		if err != nil && o.Mode == ModeAuto {
			s.Notes = append(s.Notes, "container could not be created ("+firstLine(err.Error())+"); running the image's own weed executable instead")
			s.Container = ""
			err = s.startBinary(ctx, o)
		}
	case ModeBinary:
		err = s.startBinary(ctx, o)
	default:
		err = fmt.Errorf("objstore: unknown mode %q", o.Mode)
	}
	if err != nil {
		return nil, err
	}
	s.client = newClient(s.Direct)

	deadline := time.Now().Add(o.ReadyTimeout)
	for {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := s.client.CreateBucket(cctx, &s3.CreateBucketInput{Bucket: aws.String(o.Bucket)})
		cancel()
		if err == nil || strings.Contains(err.Error(), "BucketAlreadyExists") || strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("objstore: S3 gateway not ready after %s: %v\n%s", o.ReadyTimeout, err, s.logs())
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}

	target, _ := url.Parse(s.Direct)
	rp := httputil.NewSingleHostReverseProxy(target)
	ln, err := net.Listen("tcp", o.ProxyAddr)
	if err != nil {
		return nil, err
	}
	s.proxy = &http.Server{Handler: s.logging(rp)}
	go s.proxy.Serve(ln)
	s.Endpoint = "http://" + ln.Addr().String()
	ok = true
	return s, nil
}

// Client returns an S3 client for endpoint (the proxy or the store) with the static credentials.
func Client(endpoint string) *s3.Client { return newClient(endpoint) }

func newClient(endpoint string) *s3.Client {
	return s3.New(s3.Options{
		Region:       Region,
		BaseEndpoint: aws.String(endpoint),
		UsePathStyle: true,
		// SeaweedFS returns no response checksums; validate only where the API requires it.
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
		Credentials:                credentials.NewStaticCredentialsProvider(AccessKey, SecretKey, ""),
	})
}

// Upload copies a written layout into the bucket under prefix (the store root a consumer is given as
// `<bucket>/<prefix>`), with each object's SEP-54 metadata.
func (s *Store) Upload(ctx context.Context, prefix string, l *lake.Layout) error {
	put := func(key string, data []byte, ctype string, md map[string]string) error {
		_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(s.Bucket), Key: aws.String(path.Join(prefix, key)), Body: bytes.NewReader(data),
			ContentType: aws.String(ctype), Metadata: md,
		})
		return err
	}
	cfg, err := os.ReadFile(filepath.Join(l.Dir, lake.ConfigFile))
	if err != nil {
		return err
	}
	if err := put(lake.ConfigFile, cfg, "application/json", nil); err != nil {
		return fmt.Errorf("objstore: upload %s: %w", lake.ConfigFile, err)
	}
	for _, o := range l.Objects {
		data, err := os.ReadFile(filepath.Join(l.Dir, filepath.FromSlash(o.Key)))
		if err != nil {
			return err
		}
		if err := put(o.Key, data, "application/octet-stream", o.Metadata); err != nil {
			return fmt.Errorf("objstore: upload %s: %w", o.Key, err)
		}
	}
	return nil
}

// ReadBack fetches every object of an uploaded layout directly from the store and compares its sha256 with
// what was written, so "the store did not have it" is ruled out before a consumer starts.
func (s *Store) ReadBack(ctx context.Context, prefix string, l *lake.Layout) error {
	for _, o := range l.Objects {
		out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(path.Join(prefix, o.Key))})
		if err != nil {
			return fmt.Errorf("objstore: read back %s: %w", o.Key, err)
		}
		h := sha256.New()
		_, err = io.Copy(h, out.Body)
		out.Body.Close()
		if err != nil {
			return err
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != o.SHA256 {
			return fmt.Errorf("objstore: read back %s: sha256 %s, wrote %s", o.Key, got, o.SHA256)
		}
	}
	return nil
}

// Close stops the proxy and the store: it removes the container and its volumes, or kills the process group
// and removes the data directory it created.
func (s *Store) Close() error {
	if s.proxy != nil {
		s.proxy.Close()
	}
	var err error
	if s.Container != "" {
		_, err = docker(context.Background(), "rm", "-f", "-v", s.Container)
	}
	if s.child != nil {
		s.child.Kill("store closed")
		s.child.Wait()
		s.child = nil
	}
	if s.ownData && s.dataDir != "" {
		os.RemoveAll(s.dataDir)
	}
	return err
}

func (s *Store) startContainer(ctx context.Context, o Options) error {
	s.Mode = ModeDocker
	s.Container = fmt.Sprintf("%s-%d-%d", o.NamePrefix, os.Getpid(), seq.Add(1))
	if _, err := docker(ctx, "run", "-d", "--pull", "never", "--name", s.Container, "--label", "xdrcheck.owner="+o.NamePrefix,
		"-p", "127.0.0.1::8333", o.Image, "server", "-dir=/data", "-s3"); err != nil {
		docker(context.Background(), "rm", "-f", "-v", s.Container)
		return err
	}
	port, err := docker(ctx, "port", s.Container, "8333/tcp")
	if err != nil {
		return err
	}
	s.Direct = "http://" + strings.TrimSpace(strings.Split(port, "\n")[0])
	return nil
}

func (s *Store) startBinary(ctx context.Context, o Options) error {
	s.Mode = ModeBinary
	bin, sum, err := ExtractWeed(ctx, o.Image, o.CacheDir)
	if err != nil {
		return err
	}
	s.Binary, s.BinarySHA = bin, sum
	s.dataDir = o.DataDir
	if s.dataDir == "" {
		if s.dataDir, err = os.MkdirTemp("", "xdrcheck-seaweedfs-"); err != nil {
			return err
		}
		s.ownData = true
	}
	ports, err := freePorts(8)
	if err != nil {
		return err
	}
	args := []string{"server", "-dir=" + s.dataDir, "-s3", "-iam=false", "-ip=127.0.0.1", "-ip.bind=127.0.0.1",
		"-s3.port.iceberg=0", "-s3.port.lance=0"}
	for i, f := range []string{"master.port", "master.port.grpc", "volume.port", "volume.port.grpc", "filer.port", "filer.port.grpc", "s3.port", "s3.port.grpc"} {
		args = append(args, fmt.Sprintf("-%s=%d", f, ports[i]))
	}
	child, err := proc.Start(context.Background(), proc.Spec{Path: bin, Args: args, Dir: s.dataDir, Name: "seaweedfs", TailBytes: 16 << 10})
	if err != nil {
		return err
	}
	s.child = child
	s.Direct = fmt.Sprintf("http://127.0.0.1:%d", ports[6])
	return nil
}

func (s *Store) logs() string {
	if s.Container != "" {
		out, _ := docker(context.Background(), "logs", "--tail", "20", s.Container)
		return out
	}
	if s.child != nil {
		select {
		case <-s.child.Done():
			r := s.child.Wait()
			return fmt.Sprintf("weed exited %d: %s", r.ExitCode, r.Stderr.Data)
		default:
		}
	}
	return ""
}

// ExtractWeed returns the `weed` executable of a pinned SeaweedFS image, extracting it once with `docker save`
// (which reads the local image store and creates no container) into cacheDir/<digest>/weed, and its sha256.
func ExtractWeed(ctx context.Context, image, cacheDir string) (string, string, error) {
	digest := image[strings.Index(image, "@sha256:")+len("@sha256:"):]
	if cacheDir == "" {
		base, err := userdir.UserCache()
		if err != nil {
			return "", "", err
		}
		cacheDir = filepath.Join(base, "seaweedfs")
	}
	dir := filepath.Join(cacheDir, digest)
	bin := filepath.Join(dir, "weed")
	if _, err := os.Stat(bin); err != nil {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", "", err
		}
		tarPath := filepath.Join(dir, "image.tar")
		if _, err := docker(ctx, "save", "-o", tarPath, image); err != nil {
			return "", "", err
		}
		err := extractFromImage(tarPath, "usr/bin/weed", bin+".part")
		os.Remove(tarPath)
		if err != nil {
			return "", "", fmt.Errorf("objstore: extract weed from %s: %w", image, err)
		}
		if err := os.Rename(bin+".part", bin); err != nil {
			return "", "", err
		}
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(data)
	return bin, hex.EncodeToString(sum[:]), nil
}

// extractFromImage copies one file out of a `docker save` archive, searching the layers from the top down.
func extractFromImage(tarPath, name, out string) error {
	var manifest []struct{ Layers []string }
	if err := readTarMember(tarPath, "manifest.json", func(r io.Reader) error { return json.NewDecoder(r).Decode(&manifest) }); err != nil {
		return err
	}
	if len(manifest) != 1 {
		return fmt.Errorf("archive holds %d images", len(manifest))
	}
	layers := manifest[0].Layers
	for i := len(layers) - 1; i >= 0; i-- {
		found := false
		err := readTarMember(tarPath, layers[i], func(r io.Reader) error {
			br := bufio.NewReader(r)
			var lr io.Reader = br
			if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
				zr, err := gzip.NewReader(br)
				if err != nil {
					return err
				}
				lr = zr
			}
			tr := tar.NewReader(lr)
			for {
				h, err := tr.Next()
				if err == io.EOF {
					return nil
				}
				if err != nil {
					return err
				}
				if strings.TrimPrefix(h.Name, "./") == name && h.Typeflag == tar.TypeReg {
					f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
					if err != nil {
						return err
					}
					_, err = io.Copy(f, tr)
					if cerr := f.Close(); err == nil {
						err = cerr
					}
					found = err == nil
					return err
				}
			}
		})
		if err != nil {
			return err
		}
		if found {
			return nil
		}
	}
	return fmt.Errorf("%s not found in any layer", name)
}

func readTarMember(tarPath, member string, fn func(io.Reader) error) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("%s not in archive", member)
		}
		if err != nil {
			return err
		}
		if h.Name == member {
			return fn(tr)
		}
	}
}

func freePorts(n int) ([]int, error) {
	var lns []net.Listener
	defer func() {
		for _, l := range lns {
			l.Close()
		}
	}()
	var ports []int
	for len(ports) < n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		lns = append(lns, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

var objectSeq = regexp.MustCompile(`--([0-9]+)\.xdr\.[A-Za-z0-9._-]+$`)

type recorder struct {
	http.ResponseWriter
	status int
	n      int64
}

func (r *recorder) WriteHeader(code int) { r.status = code; r.ResponseWriter.WriteHeader(code) }
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	n, err := r.ResponseWriter.Write(b)
	r.n += int64(n)
	return n, err
}

// logging records every request that passes the proxy.
func (s *Store) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &recorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		key := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/"), s.Bucket)
		key = strings.TrimPrefix(key, "/")
		d := lake.Delivery{View: "s3", Method: r.Method, Key: key, Query: r.URL.RawQuery, Bytes: rec.n, Status: strconv.Itoa(rec.status)}
		if rec.status == 0 {
			d.Status = "200"
		}
		if m := objectSeq.FindStringSubmatch(r.URL.Path); m != nil && r.Method == http.MethodGet {
			if n, err := strconv.ParseUint(m[1], 10, 32); err == nil {
				d.Ledgers = []uint32{uint32(n)}
			}
		}
		s.log.Add(d)
	})
}

func docker(ctx context.Context, args ...string) (string, error) {
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %v: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// Available reports whether docker answers and the image is present locally.
func Available(image string) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return err
	}
	if _, err := docker(context.Background(), "image", "inspect", "--format", "{{.Id}}", image); err != nil {
		return errors.New("image not present locally: " + image)
	}
	return nil
}
