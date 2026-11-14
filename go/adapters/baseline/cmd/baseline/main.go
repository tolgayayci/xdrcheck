// Command baseline is the baseline indexer's adapter (`baseline [--max-protocol N …]`), speaking the replay
// protocol xcc.adapter/1 over stdio, and the indexer itself (`baseline index …`), which the adapter starts.
package main

import (
	"os"

	"github.com/tolgayayci/xdrcheck/go/adapters/baseline"
)

func main() { os.Exit(baseline.Main(os.Args[1:])) }
