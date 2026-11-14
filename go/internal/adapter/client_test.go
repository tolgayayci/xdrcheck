package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(examplesDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// example splits a worked example into its request params or its response result/error.
func example(t *testing.T, n string) (params, result, errBody json.RawMessage) {
	t.Helper()
	var m struct {
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(mustRead(t, "valid-"+n+".json"), &m); err != nil {
		t.Fatal(err)
	}
	return m.Params, m.Result, m.Error
}

func compactJSON(t *testing.T, b []byte) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// sameJSON reports whether two documents are the same JSON value.
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	x, err1 := decodeAny(a)
	y, err2 := decodeAny(b)
	if err1 != nil || err2 != nil {
		t.Fatalf("not JSON: %v %v", err1, err2)
	}
	return jsonEqual(x, y)
}

// The 13 worked examples round-trip through the client: the client turns each request example's params into
// the exact request line (the scripted fake checks it), and each response example decodes into the typed
// result and encodes back to the same JSON value. Four sessions cover the four ingest outcomes (completed,
// halted, refused, error).
func TestWorkedExamplesRoundTrip(t *testing.T) {
	seen := map[string]bool{}
	for _, ingestResp := range []string{"06", "07", "08", "13"} {
		t.Run("ingest-"+ingestResp, func(t *testing.T) {
			var steps []scriptStep
			for _, pair := range [][2]string{{"01", "02"}, {"03", "04"}, {"05", ingestResp}, {"09", "10"}, {"11", "12"}} {
				steps = append(steps, scriptStep{Expect: mustRead(t, "valid-"+pair[0]+".json"), Respond: compactJSON(t, mustRead(t, "valid-"+pair[1]+".json"))})
				seen[pair[0]], seen[pair[1]] = true, true
			}
			script := filepath.Join(t.TempDir(), "script.json")
			b, _ := json.Marshal(steps)
			os.WriteFile(script, b, 0o644)

			var stderr, transcript bytes.Buffer
			cfg := fakeConfig("script:" + script)
			cfg.Stderr, cfg.Transcript = &stderr, &transcript
			ctx := context.Background()
			c, err := Start(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Kill("test end")

			roundTrip := func(name string, got any, want json.RawMessage) {
				t.Helper()
				enc, err := json.Marshal(got)
				if err != nil {
					t.Fatal(err)
				}
				if !sameJSON(t, enc, want) {
					t.Errorf("%s does not round-trip:\n got  %s\n want %s", name, enc, compactJSON(t, want))
				}
			}

			var dp DescribeParams
			p, want, _ := example(t, "01")
			mustDecode(t, p, &dp)
			_, want, _ = example(t, "02")
			d, err := c.Describe(ctx, dp)
			if err != nil {
				t.Fatalf("describe: %v\n%s", err, stderr.String())
			}
			roundTrip("describe", d, want)

			var pp PrepareParams
			p, _, _ = example(t, "03")
			mustDecode(t, p, &pp)
			_, want, _ = example(t, "04")
			pr, err := c.Prepare(ctx, pp)
			if err != nil {
				t.Fatalf("prepare: %v\n%s", err, stderr.String())
			}
			roundTrip("prepare", pr, want)

			var ip IngestParams
			p, _, _ = example(t, "05")
			mustDecode(t, p, &ip)
			_, want, wantErr := example(t, ingestResp)
			ir, err := c.Ingest(ctx, ip)
			if wantErr != nil {
				var ae *AdapterError
				if !errors.As(err, &ae) {
					t.Fatalf("ingest: want an AdapterError, got %v", err)
				}
				roundTrip("error", ae.ErrorBody, wantErr)
			} else {
				if err != nil {
					t.Fatalf("ingest: %v\n%s", err, stderr.String())
				}
				roundTrip("ingest", ir, want)
			}

			var op ObserveParams
			p, _, _ = example(t, "09")
			mustDecode(t, p, &op)
			_, want, _ = example(t, "10")
			obs, err := c.Observe(ctx, op)
			if err != nil {
				t.Fatalf("observe: %v\n%s", err, stderr.String())
			}
			roundTrip("observe", obs, want)

			var tp TeardownParams
			p, _, _ = example(t, "11")
			mustDecode(t, p, &tp)
			_, want, _ = example(t, "12")
			tr, err := c.Teardown(ctx, tp)
			if err != nil {
				t.Fatalf("teardown: %v\n%s", err, stderr.String())
			}
			roundTrip("teardown", tr, want)

			res := c.Close()
			if res.ExitCode != 0 {
				t.Fatalf("fake exited %d (a request differed from the example?)\n%s", res.ExitCode, stderr.String())
			}
			if !strings.Contains(stderr.String(), "is a log line, not a response") {
				t.Error("stderr was not passed through as logs")
			}
			if n := strings.Count(transcript.String(), "\n"); n != 10 {
				t.Errorf("transcript has %d lines, want 10", n)
			}
		})
	}
	if len(seen) != 13 {
		t.Errorf("covered %d of the 13 worked examples", len(seen))
	}
}

func mustDecode(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := decodeStrict(b, v); err != nil {
		t.Fatal(err)
	}
}

func TestDeadlineKillsTheAdapter(t *testing.T) {
	cfg := fakeConfig("good,hang-observe")
	cfg.Stderr = &bytes.Buffer{}
	cfg.Deadlines.Observe = 300 * time.Millisecond
	ctx := context.Background()
	c, err := Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Kill("test end")
	if _, err := c.Describe(ctx, DescribeParams{HarnessVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = c.Observe(ctx, ObserveParams{Session: "s-1", Range: Range{Start: 1, End: 1}, Kinds: []string{"receipts"}})
	var te *TimeoutError
	if !errors.As(err, &te) || te.Method != MethodObserve {
		t.Fatalf("want a TimeoutError for observe, got %v", err)
	}
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the adapter is still running after its deadline")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("timeout took %s", el)
	}
	if _, err := c.Teardown(ctx, TeardownParams{Session: "s-1"}); err == nil {
		t.Error("a killed client still answers")
	}
}

func TestAdapterExitMidCall(t *testing.T) {
	cfg := fakeConfig("good,die-in-ingest")
	cfg.Stderr = &bytes.Buffer{}
	ctx := context.Background()
	c, err := Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Kill("test end")
	if _, err := c.Describe(ctx, DescribeParams{HarnessVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	_, err = c.Ingest(ctx, IngestParams{Session: "s-1", Input: Input{Kind: "rpc", URL: "http://127.0.0.1:1"}, Range: Range{Start: 2, End: 2},
		Network: Network{Name: "testnet", Passphrase: "Test SDF Network ; September 2015"}, Unit: "single", DeadlineMS: 1000})
	var xe *ExitError
	if !errors.As(err, &xe) || xe.Result.ExitCode != 7 {
		t.Fatalf("want an ExitError with code 7, got %v", err)
	}
}

func TestCallsBeforeDescribeAreRefused(t *testing.T) {
	cfg := fakeConfig("good")
	cfg.Stderr = &bytes.Buffer{}
	c, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Kill("test end")
	if _, err := c.Teardown(context.Background(), TeardownParams{Session: "s-1"}); err == nil {
		t.Error("teardown before describe was sent")
	}
}

func TestInvalidRequestIsNotSent(t *testing.T) {
	cfg := fakeConfig("good")
	cfg.Stderr = &bytes.Buffer{}
	c, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Kill("test end")
	ctx := context.Background()
	if _, err := c.Describe(ctx, DescribeParams{HarnessVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	_, err = c.Prepare(ctx, PrepareParams{Session: "Bad Session", TargetVersion: "x", Network: Network{Name: "testnet", Passphrase: "p"}, Workdir: "w"})
	if err == nil || !strings.Contains(err.Error(), "invalid prepare request") {
		t.Fatalf("want an invalid-request error, got %v", err)
	}
	if c.Err() != nil {
		t.Errorf("a harness-side request error broke the client: %v", c.Err())
	}
}

func TestUnsolicitedOutputIsAViolation(t *testing.T) {
	cfg := fakeConfig("good,unsolicited")
	cfg.Stderr = &bytes.Buffer{}
	ctx := context.Background()
	c, err := Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Kill("test end")
	if _, err := c.Describe(ctx, DescribeParams{HarnessVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // the fake writes its second describe response meanwhile
	_, err = c.Teardown(ctx, TeardownParams{Session: "s-1"})
	var pe *ProtocolError
	if !errors.As(err, &pe) || pe.Reason != ReasonUnsolicited {
		t.Fatalf("want %s, got %v", ReasonUnsolicited, err)
	}
}

// readLines frames lines longer than its read buffer from their fragments, and drops a line over the cap.
func TestReadLinesFraming(t *testing.T) {
	read := func(max int, in string) []lineMsg {
		c := &Client{cfg: Config{MaxLineBytes: max}, lines: make(chan lineMsg, 16)}
		c.readLines(strings.NewReader(in))
		var out []lineMsg
		for m := range c.lines {
			out = append(out, m)
		}
		return out
	}
	long := strings.Repeat("x", 300<<10) // several of the reader's 64 KiB fragments
	got := read(1<<20, "a\n"+long+"\n\ntail")
	want := []string{"a", long, "", "tail"}
	if len(got) != len(want) {
		t.Fatalf("%d lines, want %d", len(got), len(want))
	}
	for i, m := range got {
		if string(m.data) != want[i] {
			t.Errorf("line %d: %d bytes, want %d", i, len(m.data), len(want[i]))
		}
		if wantErr := i == 3; (m.err == io.ErrUnexpectedEOF) != wantErr || !wantErr && m.err != nil {
			t.Errorf("line %d: err %v", i, m.err)
		}
	}

	// Over the cap: one errLineTooLong, the rest of the output drained, nothing after it.
	got = read(100<<10, "a\n"+long+"\nb\n")
	if len(got) != 2 || string(got[0].data) != "a" || got[1].err != errLineTooLong || got[1].data != nil {
		t.Fatalf("over the cap: %+v", got)
	}
	// Over the cap and cut off by EOF without a newline: nothing is reported for it.
	got = read(100<<10, "a\n"+long)
	if len(got) != 1 || string(got[0].data) != "a" {
		t.Fatalf("over the cap at EOF: %d messages", len(got))
	}
	// Exactly at the cap: kept.
	got = read(len(long), long+"\n")
	if len(got) != 1 || got[0].err != nil || len(got[0].data) != len(long) {
		t.Fatalf("at the cap: %d messages", len(got))
	}
}
