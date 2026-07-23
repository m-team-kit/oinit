//go:build windows
// +build windows

package main

import (
	"os"
	"strings"
)

// readTokenFile reads an access token from path. The Unix shared-/tmp threat
// model (world-writable predictable paths, symlink swaps) does not apply on
// Windows, where NTFS ACLs govern access, so this is a straightforward read.
//
// Returns the trimmed token and true, or "" and false if the file is missing
// or empty.
func readTokenFile(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", false
	}
	return token, true
}
