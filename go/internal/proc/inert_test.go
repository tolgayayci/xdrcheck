package proc

import (
	"context"
	"testing"
)

// The interface fields that are not acted on yet (Spec.Sandbox; the CPU, open-file and file-size limits) change
// nothing about how a child runs: the same child exits the same way, under the same mechanism.
func TestInertFields(t *testing.T) {
	s := helperSpec("exit:5")
	s.Mechanism = None
	s.Sandbox = &Sandbox{Profile: "driver", ReadOnly: []string{"/usr"}, Writable: []string{t.TempDir()}}
	s.Limits = Limits{CPUSeconds: 1, NoFile: 3, FileSizeMax: 1}
	r, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if r.ExitCode != 5 || r.Mechanism != None || r.TimedOut {
		t.Errorf("result %+v", r)
	}
	if (Limits{CPUSeconds: 1, NoFile: 1, FileSizeMax: 1}).any() {
		t.Error("the not-yet-applied limits select a limiting mechanism")
	}
}
