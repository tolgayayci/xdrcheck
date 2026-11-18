// Throwaway: what wallet-backend 79ea2acd AddressBytea.Scan returns for the stored bytes,
// and whether go-stellar-sdk v0.7.3 strkey.DecodeAny accepts it.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/stellar/go-stellar-sdk/strkey"
)

func main() {
	b, _ := hex.DecodeString(os.Args[1])
	enc, err := strkey.Encode(strkey.VersionByte(b[0]), b[1:33]) // == types.go Scan at 79ea2acd
	fmt.Println("Scan ->", enc, err)
	_, _, err = strkey.DecodeAny(enc)
	fmt.Println("DecodeAny ->", err)
}
