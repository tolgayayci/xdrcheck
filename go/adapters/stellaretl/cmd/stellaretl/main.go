// Command stellaretl is the replay adapter for stellar-etl, speaking the replay protocol xcc.adapter/1 over
// stdio. See the package documentation of adapters/stellaretl.
package main

import (
	"os"

	"github.com/tolgayayci/xdrcheck/go/adapters/stellaretl"
)

func main() { os.Exit(stellaretl.Main(os.Args[1:])) }
