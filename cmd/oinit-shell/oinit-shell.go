package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/lbrocke/oinit/pkg/log"
)

const (
	FORCE_COMMAND = "oinit-switch"

	ERR_PROHIBITED = "This user does not provide interactive access."
	ERR_INTERNAL   = "An error occurred."
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

	// syscall.Exec() requires full path
	path, err := exec.LookPath(argv[0])
	if err != nil {
		log.LogFatal(ERR_INTERNAL)
	}

	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		log.LogFatal(ERR_INTERNAL)
	}
}
