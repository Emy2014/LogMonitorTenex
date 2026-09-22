// Command hashpass prints an argon2id hash of its argument.
//
// Exists so the edge-gate credential is hashed with exactly the parameters the
// gateway verifies against, rather than a second implementation that could
// drift.
package main

import (
	"fmt"
	"os"

	"github.com/logmonitor/gateway/internal/auth"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hashpass <password>")
		os.Exit(2)
	}
	hash, err := auth.HashPassword(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hash)
}
