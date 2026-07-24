package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/lbrocke/oinit/pkg/log"
)

const (
	FORCE_COMMAND = "oinit-switch"

	ERR_PROHIBITED = "This user does not provide interactive access."
	ERR_INTERNAL   = "An error occurred."

	// SAFE_PATH replaces any inherited/forwarded PATH before handing off to
	// oinit-switch, so no executable is resolved via an attacker-controlled
	// search path.
	SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// This program will be invoked by OpenSSH as
//
//	oinit-shell -c 'oinit-switch <target>'
//
// Ensure that only FORCE_COMMAND can be run and no interactive login shell is
// provided.
func main() {
	if len(os.Args) != 3 || os.Args[1] != "-c" {
		log.LogFatal(ERR_PROHIBITED)
	}

	command := os.Args[2]
	argv := strings.Fields(command)

	// Require an exact match on the executable name (argv[0]). A prefix check
	// on the whole command string would also accept look-alikes such as
	// "oinit-switch-evil".
	if len(argv) < 2 || argv[0] != FORCE_COMMAND {
		log.LogFatal(ERR_PROHIBITED)
	}

	// Resolve oinit-switch to an absolute path next to this binary (they are
	// installed together), rather than through $PATH, so a caller-controlled
	// PATH cannot substitute an attacker binary run as the oinit user.
	self, err := os.Executable()
	if err != nil {
		log.LogFatal(ERR_INTERNAL)
	}
	path := filepath.Join(filepath.Dir(self), FORCE_COMMAND)
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		log.LogFatal(ERR_INTERNAL)
	}

	// Do not let a forwarded/inherited PATH influence what oinit-switch (or the
	// shell it starts) resolves.
	os.Setenv("PATH", SAFE_PATH)

	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		log.LogFatal(ERR_INTERNAL)
	}
}
