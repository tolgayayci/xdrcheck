package fixture

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// validateScript validates argv[2] against the JSON Schema 2020-12 document
// argv[1], with format checks, and prints the first errors.
const validateScript = `
import json, sys
import jsonschema
schema = json.load(open(sys.argv[1]))
doc = json.load(open(sys.argv[2]))
v = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
errs = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
for e in errs[:10]:
    print("/".join(str(p) for p in e.path), e.message[:200])
sys.exit(1 if errs else 0)
`

// ValidateReport validates a report file against corpus/schema/report.schema.json
// with the repository's Python virtualenv (.venv, see `make repo-checks`).
// The test is skipped, not passed, when the virtualenv is missing.
func ValidateReport(t *testing.T, reportPath string) {
	t.Helper()
	repo := filepath.Dir(ModuleRoot(t))
	py := filepath.Join(repo, ".venv", "bin", "python")
	if _, err := os.Stat(py); err != nil {
		t.Skipf("no %s: create it with `python3 -m venv .venv && .venv/bin/pip install -r scripts/py/requirements.txt`", py)
	}
	schema := filepath.Join(repo, "corpus", "schema", "report.schema.json")
	out, err := exec.Command(py, "-I", "-c", validateScript, schema, reportPath).CombinedOutput()
	if err != nil {
		t.Errorf("%s does not validate against report.schema.json: %v\n%s", reportPath, err, out)
	}
}
