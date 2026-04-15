package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/lbrocke/oinit/pkg/log"
	"github.com/mattn/go-isatty"
)

const (
	SU_COMMAND  = "su"
	OINIT_USER  = "oinit"
	SYS_UID_MAX = 99

	ERR_NOT_ALLOWED = "This is not allowed."
	ERR_INTERNAL    = "Internal error. oinit might not be set up correctly."
)

// getUser returns the uid for the given username. If the user doesn't exist,
// an error is returned.
func getUid(name string) (int, error) {
	user, err := user.Lookup(name)
	if err != nil {
		return -1, err
	}

	uid, err := strconv.Atoi(user.Uid)
	if err != nil {
		return -1, err
	}

	return uid, nil
}

// prepareForwardedOidcSocket searches for a forwarded oidc-agent unix socket
// (matching "oidc-forward" in /proc/net/unix), makes it accessible to other
// users, and sets OIDC_SOCK_AUTODETECTED in the environment.
func prepareForwardedOidcSocket() {
	socketPath := findForwardedOidcSocket()
	if socketPath == "" {
		return
	}

	// Make the socket accessible to the target user. We can't chown
	// (requires root), but we own the socket so we can chmod it.
	if err := os.Chmod(socketPath, 0666); err != nil {
		log.LogInfo(fmt.Sprintf("Could not chmod forwarded socket %s: %v", socketPath, err))
		return
	}

	os.Setenv("OIDC_SOCK_AUTODETECTED", socketPath)
	log.LogInfo(fmt.Sprintf("Detected forwarded oidc-agent socket: %s", socketPath))
}

// findForwardedOidcSocket searches /proc/net/unix for a unix socket whose path
// contains "oidc-forward". If multiple are found (concurrent sessions), it
// disambiguates by matching socket inodes against the session's sshd process.
func findForwardedOidcSocket() string {
	type unixSocket struct {
		inode string
		path  string
	}

	f, err := os.Open("/proc/net/unix")
	if err != nil {
		log.LogDebug(fmt.Sprintf("Cannot open /proc/net/unix: %v", err))
		return ""
	}
	defer f.Close()

	var candidates []unixSocket
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		path := fields[7]
		if strings.Contains(path, "oidc-forward") {
			candidates = append(candidates, unixSocket{
				inode: fields[6],
				path:  path,
			})
		}
	}

	if len(candidates) == 0 {
		return ""
	}
	if len(candidates) == 1 {
		return candidates[0].path
	}

	// Multiple candidates — find our session's sshd and match by inode
	sshdPid := findSessionSshdPid()
	if sshdPid == 0 {
		log.LogDebug("Could not find session sshd PID, using first oidc-forward socket")
		return candidates[0].path
	}

	sshdInodes := getProcessSocketInodes(sshdPid)
	for _, c := range candidates {
		if sshdInodes[c.inode] {
			return c.path
		}
	}

	log.LogDebug("No inode match for session sshd, using first oidc-forward socket")
	return candidates[0].path
}

// findSessionSshdPid walks up the process tree from the current process
// to find the sshd process that owns this session.
func findSessionSshdPid() int {
	pid := os.Getppid()
	for i := 0; i < 10; i++ {
		if pid <= 1 {
			return 0
		}
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			return 0
		}
		if strings.TrimSpace(string(comm)) == "sshd" {
			return pid
		}
		// Parse ppid from /proc/<pid>/stat
		// Format: pid (comm) state ppid ...
		// comm can contain parens, so find last ')' first
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return 0
		}
		statStr := string(stat)
		idx := strings.LastIndex(statStr, ")")
		if idx < 0 || idx+2 >= len(statStr) {
			return 0
		}
		fields := strings.Fields(statStr[idx+2:])
		if len(fields) < 2 {
			return 0
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0
		}
		pid = ppid
	}
	return 0
}

// getProcessSocketInodes returns the set of inode numbers for all sockets
// held open by the given process.
func getProcessSocketInodes(pid int) map[string]bool {
	inodes := make(map[string]bool)
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return inodes
	}
	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(link, "socket:[") {
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			inodes[inode] = true
		}
	}
	return inodes
}

func main() {
	if len(os.Args) < 2 {
		log.LogFatal(ERR_NOT_ALLOWED)
	}

	// Arguments are the allowed users (certificate principals).
	allowedUsers := os.Args[1:]

	curUser, err := user.Current()
	if err != nil {
		log.LogFatal(ERR_INTERNAL)
	}
	curUid, err := strconv.Atoi(curUser.Uid)
	if err != nil {
		log.LogFatal(ERR_INTERNAL)
	}

	// Detect forwarded oidc-agent socket and prepare it for the target user
	prepareForwardedOidcSocket()

	// If the current user is one of the allowed users, exec their shell
	// directly. This happens when the certificate contains the current
	// username as principal, allowing the user to connect as himself/herself
	// directly without going through a service account.
	for _, u := range allowedUsers {
		uid, err := getUid(u)
		if err != nil {
			continue
		}
		if uid == curUid {
			execShell()
		}
	}

	// Now make sure the program is executed by the oinit service user.
	// This is not strictly necessary, because the 'su' command would
	// just prompt for a password in case the user executing this program
	// isn't oinit.
	oinitUid, err := getUid(OINIT_USER)
	if err != nil {
		log.LogFatal(ERR_INTERNAL)
	}

	if curUid != oinitUid {
		log.LogFatal(ERR_NOT_ALLOWED)
	}

	// Find the first allowed user that is a different, non-system
	// user and switch to them via su.
	var target string
	for _, u := range allowedUsers {
		uid, err := getUid(u)
		if err != nil {
			continue
		}
		if uid == curUid {
			continue
		}
		if uid < SYS_UID_MAX {
			log.LogInfo(fmt.Sprintf("skipping system user %s (uid %d)", u, uid))
			continue
		}
		target = u
		break
	}

	if target == "" {
		log.LogFatal(ERR_NOT_ALLOWED)
	}

	// syscall.Exec() requires full path
	argv0, err := exec.LookPath(SU_COMMAND)
	if err != nil {
		log.LogFatal(ERR_INTERNAL)
	}

	// Build su options — whitelist OIDC_SOCK_AUTODETECTED through su if set
	var suOpts []string
	if _, ok := os.LookupEnv("OIDC_SOCK_AUTODETECTED"); ok {
		suOpts = append(suOpts, "-w", "OIDC_SOCK_AUTODETECTED")
	}

	var argv []string
	if sshCmd, ok := os.LookupEnv("SSH_ORIGINAL_COMMAND"); ok {
		// In case a command was given to ssh, execute this command instead of
		// starting an interactive shell session.

		// By default, ssh does not request a tty when a command is given.
		// Using the '-P' option for 'su' (which is recommended to prevent
		// TIOCSTI ioctl terminal injection) however would create a pseudo tty
		// anyways. This results in problems for other programs using ssh (like
		// git and rsync), as they expect no tty to be created. Therefore,
		// do not use the '-P' option here.
		// To prevent users abusing this security hole, for example by forcing
		// tty allocation anyway ("ssh -tt example.org /bin/bash"), make sure
		// this program does not run ssh command when a tty is present.

		if isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd()) {
			log.LogFatal(ERR_NOT_ALLOWED)
		}

		argv = append([]string{SU_COMMAND}, suOpts...)
		argv = append(argv, "-", target, "-c", sshCmd)
	} else {
		argv = append([]string{SU_COMMAND}, suOpts...)
		argv = append(argv, "-", target, "-P")
	}

	// Use syscall.Exec (which calls execve) instead of exec.Command (which does fork + evecve)
	// to prevent unnecessary resource hogging and hide this script in htop
	if err := syscall.Exec(argv0, argv, os.Environ()); err != nil {
		os.Exit(1)
	}
}

// execShell execs the current user's login shell (or SSH_ORIGINAL_COMMAND).
// This function never returns.
func execShell() {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	shellPath, err := exec.LookPath(shell)
	if err != nil {
		log.LogFatal(ERR_INTERNAL)
	}

	if sshCmd, ok := os.LookupEnv("SSH_ORIGINAL_COMMAND"); ok {
		if err := syscall.Exec(shellPath, []string{shell, "-c", sshCmd}, os.Environ()); err != nil {
			os.Exit(1)
		}
	} else {
		// Use "-<shell>" as argv[0] to start a login shell, matching
		// the convention used by login(1) and su(1).
		if err := syscall.Exec(shellPath, []string{"-" + shell}, os.Environ()); err != nil {
			os.Exit(1)
		}
	}
}
