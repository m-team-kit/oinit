package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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
	"golang.org/x/sys/unix"
)

const (
	SU_COMMAND    = "su"
	OINIT_USER    = "oinit"
	LOG_FILE      = "/var/log/oinit/oinit.log"
	SWITCH_CONFIG = "/etc/oinit/oinit-switch.conf"
	SYS_UID_MAX   = 99

	// SAFE_PATH replaces any inherited/forwarded PATH so neither this process
	// nor the shell/su it starts resolves an executable through an
	// attacker-controlled search path.
	SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	ERR_NOT_ALLOWED = "This is not allowed."
	ERR_INTERNAL    = "Internal error. oinit might not be set up correctly."
)

// suCandidates are the absolute paths searched, in order, for the su binary.
// A fixed list is used instead of exec.LookPath so a caller-controlled $PATH
// cannot redirect su to an attacker binary (this process runs as the oinit
// service user and may hold CAP_CHOWN).
var suCandidates = []string{"/usr/bin/su", "/bin/su"}

// usernameRe mirrors the CA's username validation. oinit-switch re-validates the
// certificate principals it is handed as an independent, defence-in-depth check,
// since the CA that signed them runs on a different host.
var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

// isValidUsername reports whether name is a safe local username to use as a su
// target (no whitespace or shell metacharacters, bounded length).
func isValidUsername(name string) bool {
	return len(name) > 0 && len(name) <= 32 && usernameRe.MatchString(name)
}

// switchConfig holds the target-selection policy read from SWITCH_CONFIG.
//   - allowUsers: the only system users (uid < SYS_UID_MAX, including root)
//     permitted as su targets.
//   - blockUsers: usernames never permitted as su targets (any uid), taking
//     precedence over allowUsers.
type switchConfig struct {
	allowUsers map[string]bool
	blockUsers map[string]bool
}

// readSwitchConfig reads SWITCH_CONFIG. A missing or unreadable config yields
// empty sets, so by default no system user may be selected and nothing is
// blocked.
func readSwitchConfig() switchConfig {
	f, err := os.Open(SWITCH_CONFIG)
	if err != nil {
		return switchConfig{allowUsers: map[string]bool{}, blockUsers: map[string]bool{}}
	}
	defer f.Close()

	return parseSwitchConfig(f)
}

// parseSwitchConfig parses "allow-users = a, b c" and "block-users = d e" lines
// (comments starting with '#' and blank lines ignored) from r.
func parseSwitchConfig(r io.Reader) switchConfig {
	cfg := switchConfig{allowUsers: map[string]bool{}, blockUsers: map[string]bool{}}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, found := strings.Cut(line, "=")
		if !found {
			continue
		}

		var target map[string]bool
		switch strings.TrimSpace(key) {
		case "allow-users":
			target = cfg.allowUsers
		case "block-users":
			target = cfg.blockUsers
		default:
			continue
		}

		for _, name := range strings.FieldsFunc(val, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		}) {
			target[name] = true
		}
	}
	return cfg
}

// findSu returns the absolute path to the su binary from the fixed candidate
// list, never consulting $PATH.
func findSu() (string, error) {
	for _, p := range suCandidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("su not found in " + strings.Join(suCandidates, ", "))
}

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

// isAllowedTarget reports whether the certificate principal u may be used as a
// su target for the current (oinit) user. It re-validates the principal name,
// resolves the account, and applies classifyTarget. reason is a log message when
// the principal is rejected for a noteworthy cause (invalid name, blocked system
// user); it is empty when the principal is simply skipped (unknown account, or
// it is the current user).
func isAllowedTarget(u string, curUid int, cfg switchConfig) (bool, string) {
	if !isValidUsername(u) {
		return false, "not a valid username"
	}
	uid, err := getUid(u)
	if err != nil {
		return false, ""
	}
	return classifyTarget(u, uid, curUid, cfg)
}

// classifyTarget is the pure target-selection policy, applied deny-first: a
// principal is refused if it is in block-users; otherwise skipped if it is the
// current user; otherwise refused if it is a system user (uid < SYS_UID_MAX) not
// listed in allow-users. root (uid 0) is a system user and so must also be
// listed in allow-users to be permitted.
func classifyTarget(username string, uid, curUid int, cfg switchConfig) (bool, string) {
	if cfg.blockUsers[username] {
		return false, "listed in block-users"
	}
	if uid == curUid {
		return false, ""
	}
	if uid < SYS_UID_MAX && !cfg.allowUsers[username] {
		return false, fmt.Sprintf("system user (uid %d) not in allow-users", uid)
	}
	return true, ""
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

	// Collect the socket inodes held open by this session's own sshd
	// process(es) so a candidate can be positively bound to this session.
	sshdInodes := sessionSshdSocketInodes()

	path, reason := chooseForwardedSocket(candidates, sshdInodes, ownedByCurrentUser)

	if fileLogger != nil {
		fileLogger.Printf("[pid %d] oidc socket selection: %d candidate(s), %d session sshd inode(s) -> %q (%s)",
			os.Getpid(), len(candidates), len(sshdInodes), path, reason)
	}

	if path == "" {
		logf("Could not bind a forwarded oidc-agent socket to this session; disabling forwarding")
	}

	return path
}

// chooseForwardedSocket applies the socket-selection policy and returns the
// chosen socket path (or "" to disable forwarding) plus a short reason for the
// log. The policy, in order:
//
//  1. inode-bound: a candidate whose inode is held by this session's sshd and
//     which we own. This positively binds the socket to this session and is the
//     only case that is safe under concurrent sessions.
//  2. sole-owned: no inode match, but exactly one candidate is owned by us.
//     With a single forwarded socket there is no other session to confuse it
//     with, so selecting it cannot hijack another user's agent. This keeps
//     forwarding working when the sshd holding the listener is not readable
//     from here (e.g. it runs as root under privilege separation).
//  3. otherwise refuse: multiple owned candidates with no inode match is
//     genuinely ambiguous - selecting by guesswork could chown away another
//     session's socket - so forwarding is disabled.
func chooseForwardedSocket(candidates []unixSocket, sshdInodes map[string]bool, owned func(string) bool) (string, string) {
	if p := selectSessionSocket(candidates, sshdInodes, owned); p != "" {
		return p, "inode-bound"
	}

	var ownedPaths []string
	for _, c := range candidates {
		if owned(c.path) {
			ownedPaths = append(ownedPaths, c.path)
		}
	}
	if len(ownedPaths) == 1 {
		return ownedPaths[0], "sole-owned"
	}

	return "", "ambiguous"
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

// sessionSshdSocketInodes walks up the process-ancestor chain and returns the
// set of socket inodes held open by every readable sshd/sshd-session ancestor
// (named "sshd", or "sshd-session" on OpenSSH >= 9.8). Inodes are unioned across
// all such ancestors because the process that actually holds the forwarded
// listener varies with the OpenSSH privilege-separation model. Only ancestors
// of the current process are inspected, so a concurrent session's sshd - which
// lives in a sibling process tree, not an ancestor - never contributes its
// inodes here, and its forwarded socket therefore cannot be matched.
func sessionSshdSocketInodes() map[string]bool {
	inodes := make(map[string]bool)

	pid := os.Getppid()
	for i := 0; i < 20 && pid > 1; i++ {
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			break
		}
		if name := strings.TrimSpace(string(comm)); name == "sshd" || name == "sshd-session" {
			for inode := range getProcessSocketInodes(pid) {
				inodes[inode] = true
			}
		}

		ppid, err := parentPid(pid)
		if err != nil {
			break
		}
		pid = ppid
	}

	return inodes
}

// parentPid returns the parent PID of pid by parsing /proc/<pid>/stat.
func parentPid(pid int) (int, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// Format: pid (comm) state ppid ...
	// comm may itself contain spaces or parens, so scan past the last ')'.
	statStr := string(stat)
	idx := strings.LastIndex(statStr, ")")
	if idx < 0 || idx+2 >= len(statStr) {
		return 0, errors.New("cannot locate comm in /proc stat")
	}
	fields := strings.Fields(statStr[idx+2:])
	if len(fields) < 2 {
		return 0, errors.New("cannot parse ppid from /proc stat")
	}
	return strconv.Atoi(fields[1])
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

	// Never trust an inherited/forwarded PATH: this process resolves su from a
	// fixed candidate list, but the login shell it starts (and any child) must
	// not resolve binaries through an attacker-controlled search path either.
	os.Setenv("PATH", SAFE_PATH)

	if len(os.Args) < 2 {
		logf("no certificate principals passed as arguments")
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
		if !isValidUsername(u) {
			continue
		}
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
		logf(fmt.Sprintf("invoked as uid %d, expected the %q service user (uid %d)", curUid, OINIT_USER, oinitUid))
		fatalf(ERR_NOT_ALLOWED)
	}

	// Find the first allowed user that is a different, permitted account and
	// switch to them via su. Users in SWITCH_CONFIG's block-users are always
	// refused; system users (uid < SYS_UID_MAX, including root) are refused
	// unless listed in allow-users; and the su itself still requires PAM to
	// permit the oinit -> target switch.
	switchCfg := readSwitchConfig()
	var target string
	for _, u := range allowedUsers {
		ok, reason := isAllowedTarget(u, curUid, switchCfg)
		if ok {
			target = u
			break
		}
		if reason != "" {
			logf(fmt.Sprintf("skipping principal %q: %s", u, reason))
		}
	}

	if target == "" {
		logf(fmt.Sprintf("no allowed switch target among principals: %v", allowedUsers))
		fatalf(ERR_NOT_ALLOWED)
	}

	// Chown the forwarded socket to the target user (requires CAP_CHOWN).
	var suOpts []string
	if socketPath != "" {
		targetUser, err := user.Lookup(target)
		if err == nil {
			targetUid, _ := strconv.Atoi(targetUser.Uid)
			targetGid, _ := strconv.Atoi(targetUser.Gid)
			// Use fchownat with AT_SYMLINK_NOFOLLOW rather than os.Chown, which
			// follows symlinks. The socket path lives in a world-writable /tmp
			// and this process holds CAP_CHOWN, so following a symlink swapped
			// in at the path could chown an arbitrary target file. This changes
			// only the socket itself, never a link target.
			if err := unix.Fchownat(unix.AT_FDCWD, socketPath, targetUid, targetGid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				logf(fmt.Sprintf("Could not setup oidc-agent forwarding. Chown socket %s to %s: %v failed", socketPath, target, err))
			} else {
				logf(fmt.Sprintf("oidc-agent forwarding enabled via %s", socketPath))
				os.Setenv("OIDC_SOCK", socketPath)
				suOpts = append(suOpts, "-w", "OIDC_SOCK")
			}
		}
	}

	// Resolve su from a fixed absolute-path list, never via $PATH.
	argv0, err := findSu()
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
			logf(fmt.Sprintf("refusing SSH_ORIGINAL_COMMAND %q: a tty was requested alongside a forced command", sshCmd))
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
