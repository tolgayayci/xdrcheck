package adapter

// The test binary doubles as a scripted fake adapter: with XDRCHECK_FAKE_ADAPTER set it speaks the protocol on
// stdin/stdout and exits.
//
//   script:<file>  answers a fixed sequence: for each step it reads one request, checks it is JSON-equal to the
//                  step's "expect" (exit 3 otherwise) and writes the step's "respond" line verbatim.
//   good[,flaw…]   a reactive adapter built from the worked examples; each flaw breaks one thing on purpose.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
)

const examplesDir = "../../../corpus/schema/examples/adapter-protocol"

// jsonEqual compares two decoded JSON values by adapterkit's comparison (numbers by value).
func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	same, err := adapterkit.SameJSON(x, y)
	return err == nil && same
}

func TestMain(m *testing.M) {
	if mode := os.Getenv("XDRCHECK_FAKE_ADAPTER"); mode != "" {
		os.Exit(fake(mode))
	}
	os.Exit(m.Run())
}

type scriptStep struct {
	Expect  json.RawMessage `json:"expect"`
	Respond string          `json:"respond"`
}

func fake(mode string) int {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	send := func(line string) {
		out.WriteString(line + "\n")
		out.Flush()
	}
	fmt.Fprintln(os.Stderr, `fake adapter starting; {"xcc":"xcc.adapter/1","id":1,"method":"describe","result":{}} is a log line, not a response`)

	if file, ok := strings.CutPrefix(mode, "script:"); ok {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 4
		}
		var steps []scriptStep
		if err := json.Unmarshal(data, &steps); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 4
		}
		for i, st := range steps {
			if !in.Scan() {
				fmt.Fprintf(os.Stderr, "step %d: stdin closed\n", i)
				return 3
			}
			got, err1 := decodeAny(in.Bytes())
			want, err2 := decodeAny(st.Expect)
			if err1 != nil || err2 != nil || !jsonEqual(got, want) {
				fmt.Fprintf(os.Stderr, "step %d: request\n  %s\nwant\n  %s\n", i, in.Bytes(), st.Expect)
				return 3
			}
			send(st.Respond)
		}
		for in.Scan() {
			fmt.Fprintf(os.Stderr, "unexpected request after the script: %s\n", in.Bytes())
			return 3
		}
		return 0
	}

	flaws := strings.Split(mode, ",")[1:]
	has := func(f string) bool { return slices.Contains(flaws, f) }
	results := map[string]map[string]any{}
	for _, n := range []string{"02", "04", "06", "10", "12"} {
		ex := readExample(n)
		results[ex["method"].(string)] = ex["result"].(map[string]any)
	}
	for in.Scan() {
		req, err := decodeAny(in.Bytes())
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad request:", err)
			return 3
		}
		r := req.(map[string]any)
		method := r["method"].(string)
		id := r["id"]
		params, _ := r["params"].(map[string]any)
		result := deepCopy(results[method]).(map[string]any)
		msg := map[string]any{"xcc": Protocol, "id": id, "method": method}

		switch method {
		case MethodDescribe:
			if has("no-envelope") {
				delete(result, "envelope")
			}
			if has("wrong-tag") {
				msg["xcc"] = "xcc.adapter/2"
			}
			if has("unstable") {
				result["adapter"].(map[string]any)["version"] = fmt.Sprintf("0.1.0+pid%d", os.Getpid())
			}
			if has("malformed") {
				send(`{"xcc":"xcc.adapter/1","id":1,"method":"describe","result":{"adapter":`)
				continue
			}
			if has("old-version") {
				result["protocol_version"] = "xcc.adapter/0"
			}
		case MethodPrepare:
			if has("bad-id") {
				msg["id"] = 99
			}
			if has("unknown-field") {
				result["started_at_ledger"] = 1
			}
		case MethodIngest:
			declared := results[MethodDescribe]
			kind := params["input"].(map[string]any)["kind"]
			if !slices.Contains(declared["inputs"].([]any), kind) {
				msg["error"] = map[string]any{"code": "unsupported_input", "message": fmt.Sprintf("cannot read %v", kind)}
				break
			}
			if u, ok := params["unit"]; ok && !slices.Contains(declared["units"].([]any), u) {
				code := "unsupported_unit"
				if has("wrong-code") {
					code = "invalid_params"
				}
				msg["error"] = map[string]any{"code": code, "message": fmt.Sprintf("cannot run unit %v", u)}
				break
			}
			if has("die-in-ingest") {
				fmt.Fprintln(os.Stderr, "fake adapter dying")
				return 7
			}
		case MethodObserve:
			if has("wall-clock") {
				result["ledgers"].([]any)[0].(map[string]any)["ingested_at"] = "2026-11-12T10:30:37Z"
			}
			if has("wall-clock-value") {
				sc := result["ledgers"].([]any)[0].(map[string]any)["state_changes"].([]any)[0].(map[string]any)
				sc["native_label"] = "SIGNER/ADD"
				sc["cause"] = "fine: free text"
				result["ledgers"].([]any)[0].(map[string]any)["transactions"].([]any)[0].(map[string]any)["result_code"] = "2026-11-12T10:30:37Z"
			}
			if has("hang-observe") {
				time.Sleep(time.Hour)
			}
		}
		if _, isErr := msg["error"]; !isErr {
			msg["result"] = result
		}
		b, _ := json.Marshal(msg)
		send(string(b))
		if has("unsolicited") && method == MethodDescribe {
			send(string(b))
		}
	}
	if has("no-exit") {
		time.Sleep(time.Hour)
	}
	return 0
}

func readExample(n string) map[string]any {
	data, err := os.ReadFile(filepath.Join(examplesDir, "valid-"+n+".json"))
	if err != nil {
		panic(err)
	}
	v, err := decodeAny(data)
	if err != nil {
		panic(err)
	}
	return v.(map[string]any)
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = deepCopy(e)
		}
		return m
	case []any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = deepCopy(e)
		}
		return s
	default:
		return v
	}
}

func fakeConfig(mode string) Config {
	return Config{
		Argv:   []string{os.Args[0], "-test.run=^$"},
		Env:    append(os.Environ(), "XDRCHECK_FAKE_ADAPTER="+mode),
		Name:   "fake-adapter",
		Stderr: os.Stderr,
	}
}
