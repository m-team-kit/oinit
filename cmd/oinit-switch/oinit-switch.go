package main

import (
	"bufio"
	"fmt"
	golog "log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/lbrocke/oinit/pkg/log"
	"github.com/mattn/go-isatty"
)

const (
	SU_COMMAND  = "su"
	OINIT_USER  = "oinit"
	LOG_FILE    = "/var/log/oinit/oinit.log"
	SYS_UID_MAX = 99

	ERR_NOT_ALLOWED = "This is not allowed."
	ERR_INTERNAL    = "Internal error. oinit might not be set up correctly."
)

var fileLogger *golog.Logger
var socketCleanupPath string // set once socket is found; cleaned up on fatal exit

// oidcSocketRe constrains forwarded oidc-agent socket paths to the exact form
// created by the client (ssh -R /tmp/oidc-forward-<random>:...). The path is
// client-controlled and is later passed to os.Chown and concatenated into an
// "su -c" command, so anything outside this allowlist (shell metacharacters,
// paths outside /tmp, etc.) is rejected.
var oidcSocketRe = regexp.MustCompile(`^/tmp/oidc-forward-[0-9]+$`)

// initFileLog opens the oinit log file for append logging. Non-fatal if it
// fails. The file lives in a root/oinit-owned directory and is opened with
// O_NOFOLLOW and mode 0600 to prevent a local user from pre-planting a symlink
// (CWE-59) or reading session metadata via a shared-/tmp file (CWE-377).
func initFileLog() {
	f, err := os.OpenFile(LOG_FILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return
	}
	fileLogger = golog.New(f, "oinit-switch: ", golog.LstdFlags)
}

// logf logs a message to both the TTY (via pkg/log) and the log file.
func logf(msg string) {
	log.LogInfo(msg)
	if fileLogger != nil {
		fileLogger.Println(msg)
	}
}

// fatalf logs a message to both the TTY and log file, removes any
// forwarded socket, then exits.
func fatalf(msg string) {
	if socketCleanupPath != "" {
		os.Remove(socketCleanupPath)
		if fileLogger != nil {
			fileLogger.Printf("[pid %d] Removed socket %s on fatal exit", os.Getpid(), socketCleanupPath)
		}
	}
	if fileLogger != nil {
		fileLogger.Println("FATAL: " + msg)
	}
	log.LogFatal(msg)
}

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

// findForwardedOidcSocket searches /proc/net/unix for a unix socket whose path
// contains "oidc-forward". If multiple are found (concurrent sessions), it
// disambiguates by matching socket inodes against the session's sshd process.
type unixSocket struct {
	inode string
	path  string
}

func findForwardedOidcSocket() string {
	f, err := os.Open("/proc/net/unix")
	if err != nil {
		logf(fmt.Sprintf("Cannot open /proc/net/unix: %v", err))
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
		if oidcSocketRe.MatchString(path) {
			candidates = append(candidates, unixSocket{
				inode: fields[6],
				path:  path,
			})
		}
	}

	if len(candidates) == 0 {
		return ""
	}

	// Bind the socket to THIS session by verifying its inode is held open by
	// this session's own sshd process. Every forwarded oidc socket is owned by
	// the oinit service user, so ownership alone cannot tell two concurrent
	// sessions apart: selecting by recency — or blindly trusting a lone
	// candidate — would let one session pick, and later chown away, another
	// user's forwarded socket, hijacking that user's oidc-agent. If this
	// session's sshd or a socket it holds cannot be positively identified,
	// disable forwarding (fail closed) rather than risk selecting the wrong
	// socket.
	sshdPid := findSessionSshdPid()
	if sshdPid == 0 {
		logf("Could not identify this session's sshd process; disabling oidc-agent forwarding")
		return ""
	}

	sshdInodes := getProcessSocketInodes(sshdPid)
	if path := selectSessionSocket(candidates, sshdInodes, ownedByCurrentUser); path != "" {
		return path
	}

	logf("No forwarded oidc-agent socket belongs to this session; disabling forwarding")
	return ""
}

// selectSessionSocket returns the candidate socket that both belongs to this
// session's sshd (its inode is among sshdInodes) and is owned by the current
// user (owned(path) is true), or "" if none qualifies. Both conditions are
// required: inode membership binds the socket to this session, and the
// ownership check guards against a path swapped for one not owned by us.
func selectSessionSocket(candidates []unixSocket, sshdInodes map[string]bool, owned func(string) bool) string {
	for _, c := range candidates {
		if sshdInodes[c.inode] && owned(c.path) {
			return c.path
		}
	}
	return ""
}

// ownedByCurrentUser reports whether the file at path exists and is owned by
// the current (oinit) user. Symlinks are not followed.
func ownedByCurrentUser(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Getuid())
}

// findSessionSshdPid walks up the process tree from the current process to
// find the per-connection sshd process that owns this session (named "sshd" or,
// on OpenSSH >= 9.8, "sshd-session"). Returns 0 if it cannot be found.
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
		// OpenSSH >= 9.8 renames the per-connection worker to "sshd-session"
		// (older versions call it "sshd"). Match either, otherwise the socket
		// disambiguation above is silently skipped on modern OpenSSH and every
		// selection would fall through to the fail-closed path.
		if name := strings.TrimSpace(string(comm)); name == "sshd" || name == "sshd-session" {
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
	initFileLog()
	// logf(fmt.Sprintf("[pid %d] invoked with args: %v", os.Getpid(), os.Args[1:]))

	if len(os.Args) < 2 {
		fatalf(ERR_NOT_ALLOWED)
	}

	// Arguments are the allowed users (certificate principals).
	allowedUsers := os.Args[1:]

	curUser, err := user.Current()
	if err != nil {
		fatalf(ERR_INTERNAL)
	}
	curUid, err := strconv.Atoi(curUser.Uid)
	if err != nil {
		fatalf(ERR_INTERNAL)
	}

	// Detect forwarded oidc-agent socket (applied later once target is known)
	socketPath := findForwardedOidcSocket()
	socketCleanupPath = socketPath

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
			// Socket is already owned by us — just set the env var
			if socketPath != "" {
				os.Setenv("OIDC_SOCK", socketPath)
				logf(fmt.Sprintf("Detected forwarded oidc-agent socket: %s", socketPath))
			}
			execShell()
		}
	}

	// Now make sure the program is executed by the oinit service user.
	// This is not strictly necessary, because the 'su' command would
	// just prompt for a password in case the user executing this program
	// isn't oinit.
	oinitUid, err := getUid(OINIT_USER)
	if err != nil {
		fatalf(ERR_INTERNAL)
	}

	if curUid != oinitUid {
		fatalf(ERR_NOT_ALLOWED)
	}

	// Find the first allowed user that is a different, non-system user and
	// switch to them via su. root (uid 0) is the one system account permitted
	// as a target: it is only ever present as a certificate principal when the
	// CA was explicitly configured with allow-root, and the su itself still
	// requires PAM to permit the oinit -> root switch. All other system users
	// (uid 1..SYS_UID_MAX-1) remain blocked as defence-in-depth.
	var target string
	for _, u := range allowedUsers {
		uid, err := getUid(u)
		if err != nil {
			continue
		}
		if uid == curUid {
			continue
		}
		if uid != 0 && uid < SYS_UID_MAX {
			logf(fmt.Sprintf("skipping system user %s (uid %d)", u, uid))
			continue
		}
		target = u
		break
	}

	if target == "" {
		fatalf(ERR_NOT_ALLOWED)
	}

	// Chown the forwarded socket to the target user (requires CAP_CHOWN).
	var suOpts []string
	if socketPath != "" {
		targetUser, err := user.Lookup(target)
		if err == nil {
			targetUid, _ := strconv.Atoi(targetUser.Uid)
			targetGid, _ := strconv.Atoi(targetUser.Gid)
			if err := os.Chown(socketPath, targetUid, targetGid); err != nil {
				logf(fmt.Sprintf("Could not setup oidc-agent forwarding. Chown socket %s to %s: %v failed", socketPath, target, err))
			} else {
				logf(fmt.Sprintf("oidc-agent forwarding enabled via %s", socketPath))
				os.Setenv("OIDC_SOCK", socketPath)
				suOpts = append(suOpts, "-w", "OIDC_SOCK")
			}
		}
	}

	// syscall.Exec() requires full path
	argv0, err := exec.LookPath(SU_COMMAND)
	if err != nil {
		fatalf(ERR_INTERNAL)
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
			fatalf(ERR_NOT_ALLOWED)
		}

		if socketPath != "" {
			sshCmd = sshCmd + "; rm -f " + socketPath
		}
		argv = append([]string{SU_COMMAND}, suOpts...)
		argv = append(argv, "-", target, "-c", sshCmd)
	} else if socketPath != "" {
		// Start a login shell and clean up the socket on exit
		argv = append([]string{SU_COMMAND}, suOpts...)
		argv = append(argv, "-", target, "-P", "-c", "$SHELL -l; rm -f "+socketPath)
	} else {
		argv = append([]string{SU_COMMAND}, suOpts...)
		argv = append(argv, "-", target, "-P")
	}

	// Use syscall.Exec (which calls execve) instead of exec.Command (which does fork + evecve)
	// to prevent unnecessary resource hogging and hide this script in htop
	if err := syscall.Exec(argv0, argv, os.Environ()); err != nil {
		if socketPath != "" {
			os.Remove(socketPath)
			logf(fmt.Sprintf("[pid %d] Removed socket %s after exec failure for user %s", os.Getpid(), socketPath, target))
		}
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
		fatalf(ERR_INTERNAL)
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
