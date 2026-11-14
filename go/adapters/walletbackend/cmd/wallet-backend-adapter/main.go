// Command wallet-backend-adapter is the reference adapter for stellar/wallet-backend
// (`wallet-backend-adapter [--pins FILE] [--cachedir DIR] [--name-prefix P]`), speaking the replay protocol
// xcc.adapter/1 over stdio, and its one networked step (`wallet-backend-adapter fetch`), which clones the
// repository, builds the pinned commits and checks the database image.
package main

import (
	"os"

	"github.com/tolgayayci/xdrcheck/go/adapters/walletbackend"
)

func main() { os.Exit(walletbackend.Main(os.Args[1:])) }
