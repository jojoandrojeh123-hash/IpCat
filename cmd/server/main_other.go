//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("mcwatch-server is supported on Linux only.")
	os.Exit(1)
}
