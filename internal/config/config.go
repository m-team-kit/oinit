package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/lbrocke/oinit/internal/util"

	"golang.org/x/crypto/ssh"
	"gopkg.in/ini.v1"
)

const (
	ERR_HOST_NOT_FOUND = "host not found in config"

	// DefaultCacheDuration is the fallback TTL (seconds) for the cached
	// motley_cue provider list (including OIDC scopes) when a host group does
	// not set cache-duration. Kept short so scope changes on motley_cue are
	// picked up quickly.
	DefaultCacheDuration = 10
)

type DefaultOptions struct {
	PathHostCAPrivateKey string `ini:"host-ca-privkey"`
	PathHostCAPublicKey  string `ini:"host-ca-pubkey"`
	PathUserCAPrivateKey string `ini:"user-ca-privkey"`
	PathUserCAPublicKey  string `ini:"user-ca-pubkey"`
	CertValidity         string `ini:"cert-validity"` // allows non-int values, parsed manually
	CertValidityFallback int    `ini:"cert-validity-fallback"`
	CacheDuration        int    `ini:"cache-duration"`
	ListenAddress        string `ini:"listen-address"`
	CertPrincipals       string `ini:"cert-principals"`
	ProvisionUser        string `ini:"provision-user"`
	DefaultUser          string `ini:"default-user"`
	ForceCommand         string `ini:"force-command"`
	AllowRoot            string `ini:"allow-root"`
	AllowUsers           string `ini:"allow-users"`
	BlockUsers           string `ini:"block-users"`
	RequireTokenAud      string `ini:"require-token-aud"`
}

type Keys struct {
	HostCAPrivateKey interface{}
	HostCAPublicKey  ssh.PublicKey
	UserCAPrivateKey interface{}
	UserCAPublicKey  ssh.PublicKey
}

type HostGroup struct {
	DefaultOptions
	Keys
	CertDuration     int
	Name             string
	Hosts            map[string]string
	ProvisionUserVal bool
	AllowRootVal     bool
	AllowUsersVal    []string
	BlockUsersVal    []string
}

type Config struct {
	HostGroups    []HostGroup
	ListenAddress string
}

// HostInfo is returned from the GetInfo function
type HostInfo struct {
	Name                 string
	URL                  string
	CertDuration         int
	CertValidityFallback int
	CacheDuration        int
	CertPrincipals       string
	ProvisionUser        bool
	DefaultUser          string
	ForceCommand         string
	AllowRoot            bool
	AllowUsers           []string
	BlockUsers           []string
	RequireTokenAud      string
	Keys
}

func Load(path string) (Config, error) {
	var conf Config
	var defOptions DefaultOptions

	cfg, err := ini.Load(path)
	if err != nil {
		return conf, err
	}

	if err := cfg.MapTo(&defOptions); err != nil {
		return conf, err
	}

	// ini doesn't support mapping to map[string]string, do it manually
	for _, hostgroup := range cfg.Sections() {
		if hostgroup.Name() == ini.DefaultSection {
			continue
		}

		// prefill with global values
		opts := &DefaultOptions{
			PathHostCAPrivateKey: defOptions.PathHostCAPrivateKey,
			PathHostCAPublicKey:  defOptions.PathHostCAPublicKey,
			PathUserCAPrivateKey: defOptions.PathUserCAPrivateKey,
			PathUserCAPublicKey:  defOptions.PathUserCAPublicKey,
			CertValidity:         defOptions.CertValidity,
			CertValidityFallback: defOptions.CertValidityFallback,
			CacheDuration:        defOptions.CacheDuration,
			ListenAddress:        defOptions.ListenAddress,
			CertPrincipals:       defOptions.CertPrincipals,
			ProvisionUser:        defOptions.ProvisionUser,
			DefaultUser:          defOptions.DefaultUser,
			ForceCommand:         defOptions.ForceCommand,
			AllowRoot:            defOptions.AllowRoot,
			AllowUsers:           defOptions.AllowUsers,
			BlockUsers:           defOptions.BlockUsers,
			RequireTokenAud:      defOptions.RequireTokenAud,
		}

		if err := hostgroup.MapTo(opts); err != nil {
			return conf, err
		}

		hg := &HostGroup{
			DefaultOptions: *opts,
			Name:           hostgroup.Name(),
			Hosts:          hostgroup.KeysHash(),
		}

		hosts := make(map[string]string)
		for key, val := range hostgroup.KeysHash() {
			if key == "host-ca-privkey" || key == "host-ca-pubkey" ||
				key == "user-ca-privkey" || key == "user-ca-pubkey" ||
				key == "cert-validity" || key == "cert-validity-fallback" ||
				key == "cache-duration" ||
				key == "listen-address" ||
				key == "cert-principals" || key == "provision-user" ||
				key == "default-user" || key == "force-command" ||
				key == "allow-root" || key == "allow-users" ||
				key == "block-users" || key == "require-token-aud" {
				continue
			}

			hosts[key] = val
		}

		hg.Hosts = hosts

		if hg.Name != ini.DefaultSection &&
			(hg.PathHostCAPrivateKey == "" ||
				hg.PathHostCAPublicKey == "" ||
				hg.PathUserCAPrivateKey == "" ||
				hg.PathUserCAPublicKey == "" ||
				hg.CertValidity == "") {
			return conf, errors.New("missing option in hostgroup " + hg.Name)
		}

		// cache-duration is optional; fall back to a short default so scope
		// changes on motley_cue propagate quickly.
		if hg.CacheDuration == 0 {
			hg.CacheDuration = DefaultCacheDuration
		}

		// Apply defaults for new options
		if hg.CertPrincipals == "" {
			hg.CertPrincipals = "oinit $provisioned-user"
		}
		if hg.ForceCommand == "" {
			hg.ForceCommand = "oinit-switch $cert-principals"
		}
		if hg.ProvisionUser == "" {
			hg.ProvisionUserVal = true
		} else {
			val, err := strconv.ParseBool(hg.ProvisionUser)
			if err != nil {
				return conf, fmt.Errorf("invalid provision-user value in hostgroup %s: %s", hg.Name, hg.ProvisionUser)
			}
			hg.ProvisionUserVal = val
		}

		// allow-root gates whether a certificate whose resolved username is
		// "root" may be issued for this host group. Default: false (deny).
		if hg.AllowRoot == "" {
			hg.AllowRootVal = false
		} else {
			val, err := strconv.ParseBool(hg.AllowRoot)
			if err != nil {
				return conf, fmt.Errorf("invalid allow-root value in hostgroup %s: %s", hg.Name, hg.AllowRoot)
			}
			hg.AllowRootVal = val
		}

		// allow-users is an optional allowlist of usernames permitted to receive
		// certificates for this host group. When empty there is no per-user
		// restriction; when set, the resolved username must appear in the list.
		// (root is additionally gated by allow-root, and the oinit service
		// account is always refused.)
		hg.AllowUsersVal = splitList(hg.AllowUsers)

		// block-users is an optional denylist of usernames that are always
		// refused for this host group, taking precedence over allow-users and
		// allow-root.
		hg.BlockUsersVal = splitList(hg.BlockUsers)

		// Validate: if provisioning is disabled, a default-user must be set
		if !hg.ProvisionUserVal && hg.DefaultUser == "" {
			return conf, fmt.Errorf("default-user is required when provision-user is false in hostgroup %s", hg.Name)
		}

		conf.HostGroups = append(conf.HostGroups, *hg)
	}

	// Set global listen address from default options
	conf.ListenAddress = defOptions.ListenAddress

	if err := loadKeys(&conf); err != nil {
		return conf, fmt.Errorf("could not load keys: %w", err)
	}

	if err := parseCertValidity(&conf); err != nil {
		return conf, fmt.Errorf("could not parse certificate validity: %w", err)
	}

	return conf, nil
}

// labelledPath names a config option (its ini key, for error messages) and the
// path it currently holds.
type labelledPath struct {
	option string
	path   string
}

func loadKeys(conf *Config) error {
	var uniqPubKeys = make(map[string]ssh.PublicKey)
	var uniqPrivKeys = make(map[string]interface{})

	for i, group := range conf.HostGroups {
		pubKeys := []labelledPath{
			{"host-ca-pubkey", group.PathHostCAPublicKey},
			{"user-ca-pubkey", group.PathUserCAPublicKey},
		}
		for _, lp := range pubKeys {
			if _, ok := uniqPubKeys[lp.path]; ok {
				continue
			}

			pk, err := parsePublicKeyFile(lp.path)
			if err != nil {
				return fmt.Errorf("hostgroup %q: %s (%s): %w", group.Name, lp.option, lp.path, err)
			}

			uniqPubKeys[lp.path] = pk
		}

		privKeys := []labelledPath{
			{"host-ca-privkey", group.PathHostCAPrivateKey},
			{"user-ca-privkey", group.PathUserCAPrivateKey},
		}
		for _, lp := range privKeys {
			if _, ok := uniqPrivKeys[lp.path]; ok {
				continue
			}

			pk, err := parsePrivateKeyFile(lp.path)
			if err != nil {
				return fmt.Errorf("hostgroup %q: %s (%s): %w", group.Name, lp.option, lp.path, err)
			}
			uniqPrivKeys[lp.path] = pk
		}

		conf.HostGroups[i].Keys.HostCAPublicKey = uniqPubKeys[group.PathHostCAPublicKey]
		conf.HostGroups[i].Keys.UserCAPublicKey = uniqPubKeys[group.PathUserCAPublicKey]
		conf.HostGroups[i].Keys.HostCAPrivateKey = uniqPrivKeys[group.PathHostCAPrivateKey]
		conf.HostGroups[i].Keys.UserCAPrivateKey = uniqPrivKeys[group.PathUserCAPrivateKey]
	}

	return nil
}

func parseCertValidity(conf *Config) error {
	for i, group := range conf.HostGroups {
		validity := group.CertValidity

		if validity == "token" {
			conf.HostGroups[i].CertDuration = 0
			continue
		}

		dur, err := strconv.Atoi(validity)
		if err != nil {
			return fmt.Errorf("hostgroup %q: cert-validity %q: %w", group.Name, validity, err)
		}

		conf.HostGroups[i].CertDuration = dur
	}

	return nil
}

func parsePublicKeyFile(path string) (ssh.PublicKey, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pk, _, _, _, err := ssh.ParseAuthorizedKey(content)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

func parsePrivateKeyFile(path string) (interface{}, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pk, err := ssh.ParseRawPrivateKey(content)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// splitList splits a comma- or whitespace-separated INI value into a slice of
// non-empty tokens.
func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	return fields
}

func (c Config) GetInfo(host string) (HostInfo, error) {
	host = strings.ToLower(host)

	for _, hostGroup := range c.HostGroups {
		for hostName, caURL := range hostGroup.Hosts {
			hostName = strings.ToLower(hostName)

			if util.MatchesHost(host, "", hostName, "") {
				return HostInfo{
					Name:                 hostName,
					URL:                  caURL,
					CertDuration:         hostGroup.CertDuration,
					CertValidityFallback: hostGroup.CertValidityFallback,
					CacheDuration:        hostGroup.CacheDuration,
					CertPrincipals:       hostGroup.CertPrincipals,
					ProvisionUser:        hostGroup.ProvisionUserVal,
					DefaultUser:          hostGroup.DefaultUser,
					ForceCommand:         hostGroup.ForceCommand,
					AllowRoot:            hostGroup.AllowRootVal,
					AllowUsers:           hostGroup.AllowUsersVal,
					BlockUsers:           hostGroup.BlockUsersVal,
					RequireTokenAud:      hostGroup.RequireTokenAud,
					Keys:                 hostGroup.Keys,
				}, nil
			}
		}
	}

	return HostInfo{}, errors.New(ERR_HOST_NOT_FOUND)
}
