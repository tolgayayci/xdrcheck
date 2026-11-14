package walletbackend

// The database: one TimescaleDB server per adapter process, from the image pinned by digest in pins.toml
// ([images] timescaledb), the image wallet-backend's own compose file and CI use.
//
// The server runs in a container with no network at all (`--network none`). wallet-backend and the adapter
// reach it through a Unix socket in a directory the adapter owns and bind-mounts into the container, so the same
// set-up works on a normal host and inside the offline wrapper (scripts/offline-run.sh), whose private network
// namespace cannot reach a port published on the host. The data directory is a tmpfs inside the container, so
// no volume is created; the container is started with --rm and removed when the adapter exits. Containers left
// by an adapter that was killed are recognised by their labels (the owner prefix and the adapter's process ID)
// and removed by the next adapter that starts with the same prefix.
//
// SQL runs through `psql` inside the container (docker exec), and every query the adapter reads returns one JSON
// value, so nothing depends on psql's text layout.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Database modes.
const (
	DBModeDocker = "docker"
)

// dbServer is a running database server.
type dbServer struct {
	Mode      string
	Image     string
	Container string
	SocketDir string // host directory holding the server's Unix socket
	Notes     []string
	templates map[string]string // commit -> template database
}

var dbSeq atomic.Int64

// dbOptions configure startDB.
type dbOptions struct {
	Image      string // image reference with digest
	NamePrefix string // container name prefix; containers are labelled with it
	RunDir     string // where the socket directory is made (keep the path short: sockets are limited to 107 bytes)
	MemoryMax  int64  // bytes; 0 for none
	PidsMax    int    // 0 for none
	Ready      time.Duration
}

const sockMount = "/xdrcheck-sock"

// startDB starts the server and waits until it accepts connections.
func startDB(ctx context.Context, o dbOptions) (*dbServer, error) {
	if !strings.Contains(o.Image, "@sha256:") {
		return nil, fmt.Errorf("database image %q is not pinned by digest", o.Image)
	}
	if o.Ready == 0 {
		o.Ready = 90 * time.Second
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker is not available: %w", err)
	}
	if _, err := docker(ctx, nil, "image", "inspect", "--format", "{{.Id}}", o.Image); err != nil {
		return nil, fmt.Errorf("database image not present locally (fetch it first): %s", o.Image)
	}
	removeStale(o.NamePrefix)

	if err := os.MkdirAll(o.RunDir, 0o755); err != nil {
		return nil, err
	}
	removeStaleSockets(o.RunDir, o.NamePrefix, o.Image)
	sock, err := makeSocketDir(o.RunDir, o.NamePrefix)
	if err != nil {
		return nil, err
	}
	// The server runs as the image's postgres user, which must be able to create its socket here.
	if err := os.Chmod(sock, 0o777); err != nil {
		os.RemoveAll(sock)
		return nil, err
	}
	s := &dbServer{Mode: DBModeDocker, Image: o.Image, SocketDir: sock, templates: map[string]string{}}
	s.Container = fmt.Sprintf("%s-db-%d-%d", o.NamePrefix, os.Getpid(), dbSeq.Add(1))
	args := []string{"run", "-d", "--rm", "--pull", "never", "--network", "none", "--name", s.Container,
		"--label", "xdrcheck.owner=" + o.NamePrefix, "--label", "xdrcheck.pid=" + strconv.Itoa(os.Getpid()),
		"--tmpfs", "/var/lib/postgresql/data:rw",
		"-v", sock + ":" + sockMount,
		"-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-e", "NO_TS_TUNE=true"}
	if o.MemoryMax > 0 {
		args = append(args, "--memory", strconv.FormatInt(o.MemoryMax, 10))
	}
	if o.PidsMax > 0 {
		args = append(args, "--pids-limit", strconv.Itoa(o.PidsMax))
	}
	args = append(args, o.Image, "postgres",
		// Telemetry off (the image registers a reporting job by default); the two settings of wallet-backend's
		// own compose file; fsync off for speed; enough connections for several wallet-backend processes.
		"-c", "timescaledb.telemetry_level=off",
		"-c", "timescaledb.enable_chunk_skipping=on",
		"-c", "timescaledb.enable_sparse_index_bloom=on",
		"-c", "fsync=off",
		"-c", "max_connections=300",
		"-c", "listen_addresses=",
		"-c", "unix_socket_directories=/var/run/postgresql,"+sockMount)
	if _, err := docker(ctx, nil, args...); err != nil {
		s.Close()
		return nil, err
	}
	if err := s.waitReady(ctx, o.Ready); err != nil {
		s.Close()
		return nil, err
	}
	s.Notes = append(s.Notes, fmt.Sprintf("database: %s mode, container %s from %s, socket in a bind-mounted directory (no network)", s.Mode, s.Container, s.Image))
	return s, nil
}

// waitReady waits for the image's first-start initialisation to finish and for the final server to answer.
func (s *dbServer) waitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	initDone := false
	for {
		if !initDone {
			logs, _ := dockerCombined(ctx, "logs", s.Container)
			initDone = strings.Contains(logs, "PostgreSQL init process complete")
		}
		if initDone {
			if _, err := s.Query(ctx, "postgres", "SELECT 1"); err == nil {
				return nil
			}
		}
		if time.Now().After(deadline) {
			logs, _ := dockerCombined(context.Background(), "logs", "--tail", "30", s.Container)
			return fmt.Errorf("database not ready after %s:\n%s", timeout, logs)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// URL is the connection URL wallet-backend is given for a database.
func (s *dbServer) URL(db string) string {
	return "postgres://postgres@/" + db + "?host=" + s.SocketDir + "&sslmode=disable"
}

// Exec runs SQL statements in a database.
func (s *dbServer) Exec(ctx context.Context, db, sql string) error {
	_, err := s.Query(ctx, db, sql)
	return err
}

// Query runs SQL in a database and returns psql's unaligned, tuples-only output, trimmed.
func (s *dbServer) Query(ctx context.Context, db, sql string) (string, error) {
	out, err := docker(ctx, strings.NewReader(sql), "exec", "-i", s.Container,
		"psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-h", sockMount, "-U", "postgres", "-d", db, "-f", "-")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// QueryJSON runs a query whose rows are wrapped into one JSON array and decodes it into v.
func (s *dbServer) QueryJSON(ctx context.Context, db, query string, v any) error {
	out, err := s.Query(ctx, db, "SELECT coalesce(json_agg(row_to_json(q)), '[]'::json) FROM ("+query+") q")
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(out))
	dec.UseNumber()
	return dec.Decode(v)
}

// Close removes the container and the socket directory. The socket and its lock file belong to the image's
// postgres user, which is not mapped inside the offline wrapper's user namespace, and the kernel refuses to
// unlink a file whose owner is unmapped there; so the container removes them itself first.
func (s *dbServer) Close() error {
	var err error
	if s.Container != "" {
		docker(context.Background(), nil, "exec", s.Container, "sh", "-c", "rm -f "+sockMount+"/.s.PGSQL.*")
		_, err = docker(context.Background(), nil, "rm", "-f", "-v", s.Container)
		if err != nil && strings.Contains(err.Error(), "No such container") {
			err = nil
		}
	}
	if s.SocketDir != "" {
		os.RemoveAll(s.SocketDir)
	}
	return err
}

// removeStale removes containers of this owner prefix whose adapter process is gone.
func removeStale(prefix string) {
	out, err := docker(context.Background(), nil, "ps", "-a", "--filter", "label=xdrcheck.owner="+prefix, "--format", `{{.Names}} {{.Label "xdrcheck.pid"}}`)
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		pid, err := strconv.Atoi(f[1])
		if err != nil || pid == os.Getpid() {
			continue
		}
		if syscall.Kill(pid, 0) == nil {
			continue // still running
		}
		docker(context.Background(), nil, "rm", "-f", "-v", f[0])
	}
}

// maxSocketPath is the longest Unix socket path the kernel accepts (sun_path, 108 bytes with its terminator).
const maxSocketPath = 107

// socketFile is the name of the server's socket in the socket directory.
const socketFile = "/.s.PGSQL.5432"

var socketSeq atomic.Int64

// makeSocketDir makes this process's socket directory, <runDir>/<prefix>-<pid>-<n>. The name begins with the
// container name prefix, which carries the run's own identity (the scripts use <prefix>-run<their PID>), so a
// run's leak check looks at its own directories only: a PID alone cannot tell this run's processes from those of
// another run in another PID namespace sharing the cache. The path must leave room for the socket file.
func makeSocketDir(runDir, prefix string) (string, error) {
	for {
		dir := filepath.Join(runDir, fmt.Sprintf("%s-%d-%d", prefix, os.Getpid(), socketSeq.Add(1)))
		if n := len(dir) + len(socketFile); n > maxSocketPath {
			return "", fmt.Errorf("socket path %s%s is %d bytes, more than the %d a Unix socket allows: use a shorter name prefix or cache directory", dir, socketFile, n, maxSocketPath)
		}
		err := os.Mkdir(dir, 0o755)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return dir, err
	}
}

// socketDirPID returns the adapter PID in the name of a socket directory of this prefix (<prefix>-<pid>-<n>).
func socketDirPID(name, prefix string) (int, bool) {
	rest, ok := strings.CutPrefix(name, prefix+"-")
	if !ok {
		return 0, false
	}
	f := strings.Split(rest, "-")
	if len(f) != 2 {
		return 0, false
	}
	pid, err := strconv.Atoi(f[0])
	if err != nil {
		return 0, false
	}
	if _, err := strconv.Atoi(f[1]); err != nil {
		return 0, false
	}
	return pid, true
}

// removeStaleSockets removes socket directories of this name prefix left by an adapter process that is gone
// (the processes of one run share its PID namespace). Directories of other prefixes are never touched. Files the
// container's user created there are removed through a throwaway container of the same image when the adapter
// cannot unlink them itself (see Close).
func removeStaleSockets(runDir, prefix, image string) {
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		pid, ok := socketDirPID(e.Name(), prefix)
		if !ok || pid == os.Getpid() || syscall.Kill(pid, 0) == nil {
			continue
		}
		dir := filepath.Join(runDir, e.Name())
		if os.RemoveAll(dir) == nil {
			continue
		}
		docker(context.Background(), nil, "run", "--rm", "--pull", "never", "--network", "none", "-v", dir+":"+sockMount,
			"--entrypoint", "sh", image, "-c", "rm -f "+sockMount+"/.s.PGSQL.*")
		os.RemoveAll(dir)
	}
}

// quoteIdent quotes a PostgreSQL identifier.
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// quoteLiteral quotes a PostgreSQL string literal.
func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// MakeTemplate turns a freshly migrated database into a template. Connections to it are disallowed first:
// TimescaleDB's background scheduler holds a session on every database, and CREATE DATABASE … TEMPLATE fails
// while any session is connected.
func (s *dbServer) MakeTemplate(ctx context.Context, db string) error {
	return s.Exec(ctx, "postgres", fmt.Sprintf(
		"ALTER DATABASE %s WITH ALLOW_CONNECTIONS false IS_TEMPLATE true;\n"+
			"SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = %s;", quoteIdent(db), quoteLiteral(db)))
}

// CreateFrom creates a database from a template, retrying briefly while a session on the template is ending.
func (s *dbServer) CreateFrom(ctx context.Context, db, template string) error {
	var err error
	for i := 0; i < 20; i++ {
		err = s.Exec(ctx, "postgres", fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s", quoteIdent(db), quoteIdent(template)))
		if err == nil || !strings.Contains(err.Error(), "being accessed by other users") {
			return err
		}
		s.Exec(ctx, "postgres", fmt.Sprintf("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = %s", quoteLiteral(template)))
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

// Drop drops a database, ending its sessions first.
func (s *dbServer) Drop(ctx context.Context, db string) error {
	return s.Exec(ctx, "postgres", fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", quoteIdent(db)))
}

// Exists reports whether a database exists.
func (s *dbServer) Exists(ctx context.Context, db string) (bool, error) {
	out, err := s.Query(ctx, "postgres", "SELECT count(*) FROM pg_database WHERE datname = "+quoteLiteral(db))
	if err != nil {
		return false, err
	}
	return out == "1", nil
}

func docker(ctx context.Context, stdin *strings.Reader, args ...string) (string, error) {
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %v: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// dockerCombined returns stdout and stderr together (container logs go to both).
func dockerCombined(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// sanitizeDBName turns a session ID into a database name.
func sanitizeDBName(prefix, s string) string {
	var b strings.Builder
	b.WriteString(prefix)
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	name := b.String()
	if len(name) > 60 {
		name = name[:60]
	}
	return name
}

var errNoDatabase = errors.New("no database server")

// shortRunDir returns a short directory for sockets under the cache directory.
func shortRunDir(cache string) string { return filepath.Join(cache, "run") }
