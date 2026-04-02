package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lbrocke/oinit/internal/dnsutil"
	"github.com/lbrocke/oinit/internal/liboinitca"
	"github.com/lbrocke/oinit/internal/oidc"
	"github.com/lbrocke/oinit/internal/oinit"
	"github.com/lbrocke/oinit/internal/sshutil"
	"github.com/lbrocke/oinit/internal/util"
	"github.com/lbrocke/oinit/pkg/log"

	"github.com/mattn/go-tty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/exp/slices"
)

const (
	COMMAND_ADD    = "add"
	COMMAND_DEL    = "del"
	COMMAND_DELETE = "delete"
	COMMAND_LIST   = "list"
	COMMAND_MATCH  = "match"

	USAGE = "oinit-v1.2.0\nUsage:\n" +
		"\toinit add    <ssh-host>[:port]\tAdd a host managed by oinit (CA found automatically (DNS or by assumptions).\n" +
		"\toinit add    <ssh-host>[:port]  [http[s]://<ca-host>[:<port>]]\n" +
		"                                \tAdd a host managed by oinit, with a specific CA.\n" +
		"\toinit del    <ssh-host>[:port]\tRemove oinit management for a host.\n" +
		"\toinit list\t\t\tList all hosts managed by oinit.\n" +
		"\n" +
		"\tThe following environment variables are considered as follows:\n" +
		"\tSkip prompting:\n" +
		"\t  - OIDC_AGENT_ACCOUNT:			Name of an oidc-agent account to use\n" +
		"\t  - OIDC_ISS, or OIDC_ISSUER:		Name of an oidc-issuer to use\n" +
		"\tFind an access token\n" +
		"\t  ACCESS_TOKEN, BEARER_TOKEN, OIDC, OS_ACCESS_TOKEN, OIDC_ACCESS_TOKEN\n"
)

// handleCommandAdd handles the 'add' command to add a host managed by oinit.
// It takes the host and optional CA as arguments.
func handleCommandAdd(args []string) {
	if len(args) < 1 {
		fmt.Print(USAGE)
		return
	}

	hostport := args[0]

	// Split into host and port, as in some cases special handling is required
	// (such as in the known hosts file).
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		// Assume that hostport string given to net.SplitHostPort() doesn't contain a port
		// https://groups.google.com/g/golang-nuts/c/KA41Tj9Aabg/m/1NUcxQcoUjwJ
		host = strings.TrimSpace(hostport)
		port = "22"

		hostport = net.JoinHostPort(host, port)
	}

	// Check if host was already added before. This also includes the system-wide
	// configuration, therefore hosts that were added by the system admin
	// won't be added to the user config again.
	if found, err := oinit.IsManagedHost(hostport); err != nil {
		log.LogError("Could not read hosts file: " + err.Error())
		return
	} else if found {
		log.LogInfo("This host was already added.")
		return
	}

	// Determine CA automatically if not given on command line.
	var ca string
	if len(args) >= 2 {
		ca = args[1]
	} else {
		detected, err := dnsutil.LookupCA(host)
		if err != nil {
			log.LogWarn("The CA for this host could not be determined automatically.")
			log.LogWarn("You can manually specify the CA by running:")
			log.LogWarn("")
			log.LogWarn("\toinit add " + args[0] + " [ca]")
			return
		}

		ca = detected
	}

	// ensure we have a $HOME/.ssh folder (see issue #3 on oinit codebase)
	homedirname, err := os.UserHomeDir()
	if err != nil {
		log.LogFatal(err.Error())
	}
	newpath := filepath.Join(homedirname, ".ssh")
	if err := os.MkdirAll(newpath, os.ModePerm); err != nil {
		log.LogFatal("Could not find $HOME/.ssh" + err.Error())
	}

	// Try to contact CA, which returns the host CA public key to be added
	// to the user's known_hosts file.
	if res, err := liboinitca.NewClient(ca).GetHost(host); err != nil {
		log.LogError("Could not contact CA: " + err.Error())
		return
	} else {
		if err := sshutil.AddSSHKnownHost(host, port, res.PublicKey); err != nil {
			log.LogWarn("Could not add public key to your known_hosts file.")

			if newLine, err := sshutil.GenerateKnownHosts(host, port, res.PublicKey); err == nil {
				log.LogWarn("Please add the following line by yourself:")
				log.LogWarn("\t" + newLine)
			}
		}
	}

	// Add to users' hosts file.
	if err := oinit.AddHostUser(hostport, ca); err != nil {
		log.LogError("Could not add host: " + err.Error())
		return
	} else {
		log.LogSuccess(hostport + " was added.")
	}

	// Check if 'Match exec ...' block is present, and if not try to add it.
	if added, err := sshutil.AddSSHMatchBlock(); err != nil {
		log.LogWarn("Could not read or modify your OpenSSH config file.")
		log.LogWarn("Please verify it contains the following lines:")
		log.LogWarn("")

		for _, line := range strings.Split(sshutil.GenerateMatchBlock(), "\n") {
			log.LogWarn("\t" + line)
		}
	} else if added {
		log.LogInfo("As this is your first time running oinit, your OpenSSH config file has")
		log.LogInfo("been modified to invoke oinit when connecting to hosts managed by it.")
	}
}

// handleCommandDelete handles the 'delete' command to delete a host.
// It takes the host as an argument.
func handleCommandDelete(args []string) {
	if len(args) < 1 {
		fmt.Print(USAGE)
		return
	}

	hostport := args[0]

	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = strings.TrimSpace(hostport)
	}

	found, err := oinit.DeleteHostUser(hostport)
	if err != nil {
		log.LogFatal("Could not delete host: " + err.Error())
	}
	if !found {
		log.LogFatal(hostport + " is either not managed by oinit, or configured system-wide.")
	}

	if sshutil.AgentIsRunning() {
		sshAgent, _ := sshutil.GetAgent()

		sshutil.AgentRemoveCertificates(sshAgent, host)
	}

	log.LogSuccess(hostport + " was deleted.")
}

// handleCommandList handles the 'list' command to list all hosts managed by oinit.
func handleCommandList() {
	all, err := oinit.GetManagedHosts()
	if err != nil {
		log.LogError("Could not load hosts: " + err.Error())
		return
	}

	hosts := make([]string, 0, len(all))
	for hostport := range all {
		hosts = append(hosts, hostport)
	}
	sort.Strings(hosts)

	log.LogInfo("The following hosts are managed by oinit:")

	for _, host := range hosts {
		fmt.Println("\t" + host)
	}
}

// getTokenFromOidcAgent prompts the user to select a supported OIDC issuer
// and then requests an access token via oidc-agent. It takes the CA client
// and host as arguments and returns the access token.
func getTokenFromOidcAgent(caClient liboinitca.Client, host string) string {

	hostRes, err := caClient.GetHost(host)
	if err != nil {
		log.LogFatalTTY("Contacting the CA failed: " + err.Error())
	}

	// Put provider URLs into slice to be able to sort them
	providers := make([]string, len(hostRes.Providers))
	for i, info := range hostRes.Providers {
		providers[i] = info.URL
	}
	sort.Strings(providers)

	provider, err := promptProviders(providers)
	if err != nil {
		log.LogFatalTTY(err.Error())
	}

	// Get scopes for selected provider
	var scopes []string
	for _, info := range hostRes.Providers {
		if info.URL != provider {
			continue
		}

		scopes = info.Scopes
	}

	token, err := oidc.GetToken(provider, scopes)
	if err != nil {
		log.LogFatalTTY("Could not get token from oidc-agent: " + err.Error())
	}
	if token == "" {
		log.LogFatalTTY("Received an empty token from oidc-agent.")
	}

	return token
}

// promptProviders prompts the user to select an OIDC provider from the list
// of available providers. It takes a list of provider URLs as arguments and
// returns the selected provider URL.
func promptProviders(providers []string) (string, error) {
	if len(providers) == 0 {
		//lint:ignore ST1005 Error is display to user directly
		return "", errors.New("The server indicated that no OIDC provider is supported")
	}

	accs := oidc.GetConfiguredAccounts()

	// Check if user pre-selected an account
	if account := os.Getenv("OIDC_AGENT_ACCOUNT"); account != "" {
		for issuer, accounts := range accs {
			if slices.Contains(accounts, account) {
				return issuer, nil
			}
		}
	}

	// Check if user pre-selected an issuer
	if issuer := util.Getenvs("OIDC_ISS", "OIDC_ISSUER"); issuer != "" {
		if _, ok := accs[issuer]; ok {
			return issuer, nil
		}
	}

	for i, issuer := range providers {
		str := issuer

		if accounts, ok := accs[issuer]; ok && len(accounts) > 0 {
			str += " (Accounts: " + strings.Join(accs[issuer], ", ") + ")"
		}

		log.LogTTY(fmt.Sprintf("[%d] %s", i+1, str))
	}

	tty, err := tty.Open()
	if err != nil {
		return "", errors.New("There was an error opening your TTY: " + err.Error())
	}

	log.PromptTTY(fmt.Sprintf("Please select a provider to use [1-%d]: ", len(providers)))

	sel, err := tty.ReadString()
	tty.Close()

	if err != nil {
		return "", errors.New("There was an error reading from your TTY: " + err.Error())
	}

	selected, err := strconv.Atoi(sel)
	if err != nil || selected < 1 || selected > len(providers) {
		//lint:ignore ST1005 Error is display to user directly
		return "", errors.New("Your selection is invalid.")
	}

	return providers[selected-1], nil
}

// promptForManualToken prompts the user to manually enter an access token
// when oidc-agent is not available. Shows the list of supported providers.
func promptForManualToken(caClient liboinitca.Client, host string) string {
	hostRes, err := caClient.GetHost(host)
	if err != nil {
		log.LogFatalTTY("Contacting the CA failed: " + err.Error())
	}

	// Display supported providers
	log.LogTTY("Supported OIDC providers for this host:")
	for i, info := range hostRes.Providers {
		log.LogTTY(fmt.Sprintf("  %d. %s", i+1, info.URL))
	}
	log.LogTTY("")

	// Prompt for access token
	tty, err := tty.Open()
	if err != nil {
		log.LogFatalTTY("There was an error opening your TTY: " + err.Error())
	}
	defer tty.Close()

	log.PromptTTY("Please enter an access token for any of the above providers: ")
	token, err := tty.ReadString()
	if err != nil {
		log.LogFatalTTY("There was an error reading from your TTY: " + err.Error())
	}

	token = strings.TrimSpace(token)
	if token == "" {
		log.LogFatalTTY("No access token provided.")
	}

	return token
}

// generateEd25519Keys generates a new ED25519 key pair and returns the
// marshalled public key (ssh-ed25519 AAA...) as well as private key.
func generateEd25519Keys() (string, ed25519.PrivateKey, error) {
	pubkey, privkey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", nil, err
	}

	pubkeyInst, err := ssh.NewPublicKey(pubkey)
	if err != nil {
		return "", nil, err
	}

	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pubkeyInst)), "\n"), privkey, nil
}

// handleCommandMatch handles the 'match' command to match a host managed by oinit.
// It takes the host and port as arguments.
func handleCommandMatch(args []string) {
	if len(args) != 2 {
		os.Exit(1)
	}

	host := strings.ToLower(args[0])
	port := args[1]
	hostport := strings.ToLower(net.JoinHostPort(host, port))

	if is, err := oinit.IsManagedHost(hostport); err != nil || !is {
		// Return non-zero exit code to indicate that host/port do not match
		os.Exit(1)
	}

	ca, err := oinit.GetCA(hostport)
	if err != nil {
		log.LogFatalTTY("The CA managing '" + host + "' could not be determined.\n" +
			"Did you run 'oinit add " + hostport + "' yet?")
	}

	caClient := liboinitca.NewClient(ca)

	var sshAgent agent.ExtendedAgent
	var useAgent bool

	// Check if ssh-agent is running
	if sshutil.AgentIsRunning() {
		sshAgent, _ = sshutil.GetAgent()

		// Check if the agent is gpg-agent, which doesn't support certificates
		if sshutil.IsGPGAgent() {
			// log.LogWarnTTY("gpg-agent does not support ssh-certificates")
			useAgent = false
		} else {
			useAgent = true

			if exists, err := sshutil.AgentHasCertificate(sshAgent, host); err == nil && exists {
				log.LogDebugTTY("Using stored certificate from ssh-agent")
				// log.LogSuccess("non-tty Using stored certificate from ssh-agent")
				// Agent already holds certificate, therefore do not request a new one
				return
			}
		}
	} else {
		useAgent = false
	}
	if !useAgent {
		// log.LogWarnTTY("ssh-agent is not running. Certificate will be saved to file.")

		// Check if we already have a valid certificate file
		if hasValidCertificateFile(host, hostport) {
			log.LogDebugTTY("Using existing certificate file")
			return
		}
	}
	// Get the Access Token

	// ... from environment variable
	log.LogDebugTTY("Searching token in environment")
	token := util.Getenvs("ACCESS_TOKEN", "BEARER_TOKEN", "OIDC", "OS_ACCESS_TOKEN",
		"OIDC_ACCESS_TOKEN", "WATTS_TOKEN", "WATTSON_TOKEN")

	// ... from BEARER_TOKEN_FILE
	if token == "" {
		log.LogDebugTTY("Searching token in BEARER_TOKEN_FILE")
		token_file := util.Getenvs("BEARER_TOKEN_FILE")
		if token_file != "" {
			if tokenData, err := os.ReadFile(token_file); err == nil {
				token = strings.TrimSpace(string(tokenData))
				log.LogDebugTTY("Using token from file: " + token_file)
			}
		}
	}
	// ... from $XDG_RUNTIME_DIR/bt_u$ID
	if token == "" {
		log.LogDebugTTY("Searching token in XDG_RUNTIME_DIR/bt_$ID")
		xdgRuntimeDir := os.Getenv("XDG_RUNTIME_DIR")
		if xdgRuntimeDir != "" {
			userID := os.Getuid()
			tokenFile := filepath.Join(xdgRuntimeDir, fmt.Sprintf("bt_u%d", userID))
			if tokenData, err := os.ReadFile(tokenFile); err == nil {
				token = strings.TrimSpace(string(tokenData))
				log.LogDebugTTY("Using token from file: " + tokenFile)
			}
		}
	}
	if token == "" {
		// ... from /tmp/bt_u$ID
		log.LogDebugTTY("Searching token in /tmp/bt_u$ID")
		userID := os.Getuid()
		tokenFile := fmt.Sprintf("/tmp/bt_u%d", userID)
		if tokenData, err := os.ReadFile(tokenFile); err == nil {
			token = strings.TrimSpace(string(tokenData))
			log.LogDebugTTY("Using token from file: " + tokenFile)
		}
	}
	// ... from oidc-agent
	if token == "" {
		log.LogDebugTTY("Searching token in oidc-agent $OP")
		if oidc.AgentIsRunning() {
			// Use oidc-agent to get token.
			token = getTokenFromOidcAgent(caClient, host)
		}
	}
	// ... manual token entry
	if token == "" {
		log.LogDebugTTY("Searching token in manual prompt")
		log.LogDebugTTY("oidc-agent is not running.")
		token = promptForManualToken(caClient, host)
	}

	log.LogDebugTTY("Generating private ssh-cert-key")
	pubkey, privkey, err := generateEd25519Keys()
	if err != nil {
		log.LogFatalTTY("There was an error generating a temporary key pair.")
	}

	res, err := caClient.PostHostCertificate(host, pubkey, token)
	if err != nil {
		log.LogFatalTTY("CA responded: " + err.Error())
	}

	certPk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(res.Certificate))
	if err != nil {
		log.LogFatalTTY("Cannot parse certificate.")
	}

	cert := certPk.(*ssh.Certificate)
	validUntil := time.Unix(int64(cert.ValidBefore-1), 0)
	log.LogDebugTTY(fmt.Sprintf("Received a certificate which is valid until %s", validUntil))

	if useAgent {
		if sshAgent.Add(agent.AddedKey{
			PrivateKey:   privkey,
			Certificate:  cert,
			LifetimeSecs: uint32(time.Until(validUntil).Seconds()),
		}) != nil {
			log.LogFatalTTY("Cannot add private key and certificate to ssh-agent.")
		} else {
			// log.LogSuccessTTY(fmt.Sprintf("Received a certificate which is valid until %s", validUntil))
			log.LogDebugTTY("Certificate stored in ssh-agent")
		}
	} else {
		// Save certificate and private key to files
		if err := saveCertificateToFiles(host, hostport, cert, privkey); err != nil {
			log.LogFatalTTY("Failed to save certificate to file: " + err.Error())
		} else {
			// log.LogSuccessTTY(fmt.Sprintf("Certificate saved to file, valid until %s", validUntil))
		}
	}
}

// hasValidCertificateFile checks if a valid certificate file exists for the given host.
// Returns true if the certificate file exists and is still valid (not expired).
func hasValidCertificateFile(host, hostport string) bool {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false
	}

	// Generate certificate filename based on host and port
	_, port, err := net.SplitHostPort(hostport)
	if err != nil {
		port = "22" // Default SSH port
	}

	certFile := filepath.Join(homeDir, ".ssh", fmt.Sprintf("oinit_%s_%s-cert.pub", host, port))
	keyFile := filepath.Join(homeDir, ".ssh", fmt.Sprintf("oinit_%s_%s", host, port))

	// Check if certificate file exists
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.LogDebugTTY("Certificate file does not exist")
		return false
	}
	// Check if key file exists
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.LogDebugTTY("Certificate key file does not exist")
		return false
	}

	// Read and parse the certificate file
	certData, err := os.ReadFile(certFile)
	if err != nil {
		log.LogDebugTTY("Can not read certificate file")
		return false
	}

	certPk, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		log.LogDebugTTY("Found certificate but can not parse it")
		return false
	}

	cert, ok := certPk.(*ssh.Certificate)
	if !ok {
		log.LogDebugTTY("Found cert, but it's not ok")
		return false
	}

	// Check if certificate is still valid (not expired)
	now := time.Now().Unix()
	if uint64(now) >= cert.ValidBefore {
		log.LogDebugTTY("Certificate Expired")
		return false // Certificate has expired
	}

	return true
}

// saveCertificateToFiles saves the SSH certificate and private key to files
// in the user's .ssh directory when ssh-agent is not available.
func saveCertificateToFiles(host string, hostport string, cert *ssh.Certificate, privkey ed25519.PrivateKey) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return err
	}

	// Generate filenames based on host and port (matching SSH config %h_%p format)
	_, port, err := net.SplitHostPort(hostport)
	if err != nil {
		port = "22" // Default SSH port
	}
	keyFile := filepath.Join(sshDir, fmt.Sprintf("oinit_%s_%s", host, port))
	certFile := filepath.Join(sshDir, fmt.Sprintf("oinit_%s_%s-cert.pub", host, port))

	// Save private key in OpenSSH format
	privKeyBlock, err := ssh.MarshalPrivateKey(privkey, "")
	if err != nil {
		return err
	}

	privKeyBytes := pem.EncodeToMemory(privKeyBlock)
	if err := os.WriteFile(keyFile, privKeyBytes, 0600); err != nil {
		return err
	}

	// Save certificate
	certBytes := ssh.MarshalAuthorizedKey(cert)
	if err := os.WriteFile(certFile, certBytes, 0644); err != nil {
		return err
	}

	log.LogDebugTTY(fmt.Sprintf("Certificate saved to file: %s", certFile))

	return nil
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		fmt.Print(USAGE)
		return
	}

	switch args[0] {
	case COMMAND_ADD:
		handleCommandAdd(args[1:])
	case COMMAND_DEL:
		handleCommandDelete(args[1:])
	case COMMAND_DELETE:
		handleCommandDelete(args[1:])
	case COMMAND_LIST:
		handleCommandList()
	case COMMAND_MATCH:
		handleCommandMatch(args[1:])
	default:
		fmt.Print(USAGE)
	}
}
