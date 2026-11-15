package overlay

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// tree is what the audit reads: the files of the public tree, either a directory on disk or the tree of one
// commit read straight from git (no checkout).
type tree interface {
	// files lists the public paths, slash-separated, relative to the tree's root.
	files() map[string]bool
	// read returns a file's content, or nil when it is larger than maxCompare.
	read(rel string) ([]byte, error)
	// blobID is the git blob id of a file's content.
	blobID(rel string) (string, error)
}

// dirTree is a directory on disk.
type dirTree struct {
	root   string
	public map[string]bool
}

func (d *dirTree) files() map[string]bool { return d.public }

func (d *dirTree) read(rel string) ([]byte, error) {
	return readBounded(filepath.Join(d.root, filepath.FromSlash(rel)))
}

func (d *dirTree) blobID(rel string) (string, error) {
	f, err := os.Open(filepath.Join(d.root, filepath.FromSlash(rel)))
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", st.Size())
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashObject is `git hash-object` of data: the id git gives that content as a blob.
func HashObject(data []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// EmptyBlob is the id of empty content, which every repository can hold; it is never a leak.
var EmptyBlob = HashObject(nil)

// gitEntry is one regular file of a commit's tree.
type gitEntry struct {
	oid  string
	size int64
}

// gitTree is the tree of one commit.
type gitTree struct {
	entries map[string]gitEntry
	public  map[string]bool
	cat     *catFile
}

func (g *gitTree) files() map[string]bool { return g.public }

func (g *gitTree) read(rel string) ([]byte, error) {
	e, ok := g.entries[rel]
	if !ok {
		return nil, os.ErrNotExist
	}
	if e.size > maxCompare {
		return nil, nil
	}
	return g.cat.read(e.oid)
}

func (g *gitTree) blobID(rel string) (string, error) {
	e, ok := g.entries[rel]
	if !ok {
		return "", os.ErrNotExist
	}
	return e.oid, nil
}

// readTree lists the regular files of commit rev in repo (symlinks and submodules are not files).
func readTree(repo, rev string, cat *catFile) (*gitTree, error) {
	out, err := gitOutput(repo, "ls-tree", "-r", "-l", "-z", "--full-tree", rev+"^{commit}", "--")
	if err != nil {
		return nil, err
	}
	g := &gitTree{entries: map[string]gitEntry{}, public: map[string]bool{}, cat: cat}
	for _, rec := range bytes.Split(out, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		meta, path, ok := strings.Cut(string(rec), "\t")
		if !ok {
			return nil, fmt.Errorf("git ls-tree: unreadable line %q", rec)
		}
		f := strings.Fields(meta)
		if len(f) != 4 || f[1] != "blob" || (f[0] != "100644" && f[0] != "100755") {
			continue
		}
		size, err := strconv.ParseInt(f[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("git ls-tree: size %q of %s", f[3], path)
		}
		g.entries[path] = gitEntry{oid: f[2], size: size}
		g.public[path] = true
	}
	return g, nil
}

// RevList is `git rev-list SPEC` in repo. A spec that starts with "-" is refused: it would be read as an option.
func RevList(repo, spec string) ([]string, error) {
	if spec == "" || strings.HasPrefix(spec, "-") {
		return nil, fmt.Errorf("not a revision range: %q", spec)
	}
	out, err := gitOutput(repo, "rev-list", spec, "--")
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// ResolveCommit is the full id of the commit rev names.
func ResolveCommit(repo, rev string) (string, error) {
	if rev == "" || strings.HasPrefix(rev, "-") {
		return "", fmt.Errorf("not a revision: %q", rev)
	}
	out, err := gitOutput(repo, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("%s is not a commit", rev)
	}
	return strings.TrimSpace(string(out)), nil
}

func gitOutput(repo string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// catFile reads blobs through one `git cat-file --batch` process.
type catFile struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

func newCatFile(repo string) (*catFile, error) {
	cmd := exec.Command("git", "-C", repo, "cat-file", "--batch")
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &catFile{cmd: cmd, in: in, out: bufio.NewReaderSize(out, 1<<20)}, nil
}

func (c *catFile) read(oid string) ([]byte, error) {
	if _, err := io.WriteString(c.in, oid+"\n"); err != nil {
		return nil, err
	}
	hdr, err := c.out.ReadString('\n')
	if err != nil {
		return nil, err
	}
	f := strings.Fields(hdr)
	if len(f) != 3 || f[1] != "blob" {
		return nil, fmt.Errorf("git cat-file: %s: %s", oid, strings.TrimSpace(hdr))
	}
	n, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil {
		return nil, err
	}
	data := make([]byte, n+1) // the content and its trailing newline
	if _, err := io.ReadFull(c.out, data); err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (c *catFile) close() {
	c.in.Close()
	c.cmd.Wait()
}
