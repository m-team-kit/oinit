//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/lbrocke/oinit/pkg/log"
)

// maxTokenFileSize bounds how much is read from a token file.
const maxTokenFileSize = 1 << 20 // 1 MiB

// readTokenFile reads an access token from path with checks appropriate for a
// shared, multi-user host. The token file paths (e.g. /tmp/bt_u$UID) are
// world-predictable, so without validation a local attacker could plant a file
// to inject their own token, or a symlink to trick us into reading an unrelated
// secret and transmitting it to the CA. To prevent that, the file is:
//   - opened O_NOFOLLOW, so a symlink planted at the path is not followed;
//   - required to be a regular file owned by the current user;
//   - rejected if group- or world-writable, so only we could have written it.
//
// Returns the trimmed token and true, or "" and false if the file is missing,
// fails a check, or is empty.
func readTokenFile(path string) (string, bool) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", false
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", false
	}
	if !info.Mode().IsRegular() {
		log.LogDebugTTY("Ignoring token file (not a regular file): " + path)
		return "", false
	}
	if info.Mode().Perm()&0o022 != 0 {
		log.LogDebugTTY("Ignoring token file writable by group/other: " + path)
		return "", false
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Getuid()) {
		log.LogDebugTTY(fmt.Sprintf("Ignoring token file not owned by current user (owner uid %d): %s", stat.Uid, path))
		return "", false
	}

	data, err := io.ReadAll(io.LimitReader(f, maxTokenFileSize))
	if err != nil {
		return "", false
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", false
	}
	return token, true
}
