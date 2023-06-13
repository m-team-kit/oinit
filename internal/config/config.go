package config

import (
	"errors"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/ini.v1"
)

const (
	ERR_HOST_NOT_FOUND = "host not found in config"
)

type DefaultOptions struct {
	PathHostCAPrivateKey string `ini:"host-ca-privkey"`
	PathHostCAPublicKey  string `ini:"host-ca-pubkey"`
	PathUserCAPrivateKey string `ini:"user-ca-privkey"`
	PathUserCAPublicKey  string `ini:"user-ca-pubkey"`
	CertValidity         string `ini:"cert-validity"`
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
	CertDuration uint64
	Name         string
	Hosts        map[string]string
}

type Config struct {
	HostGroups []HostGroup
}

type HostInfo struct {
	Name         string
	URL          string
	CertDuration uint64
	Keys
}

func LoadConfig(path string) (Config, error) {
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
				key == "cert-validity" {
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

		conf.HostGroups = append(conf.HostGroups, *hg)
	}

	if loadKeys(&conf) != nil {
		return conf, errors.New("could not open and parse keys")
	}

	if parseCertValidities(&conf) != nil {
		return conf, errors.New("could not parse certificate validities")
	}

	return conf, nil
}

func loadKeys(conf *Config) error {
	var uniqPubKeys = make(map[string]ssh.PublicKey)
	var uniqPrivKeys = make(map[string]interface{})

	for i, group := range conf.HostGroups {
		for _, path := range []string{group.PathHostCAPublicKey, group.PathUserCAPublicKey} {
			if _, ok := uniqPubKeys[path]; ok {
				continue
			}

			pk, err := parsePublicKeyFile(path)
			if err != nil {
				return err
			}

			uniqPubKeys[path] = pk
		}

		for _, path := range []string{group.PathHostCAPrivateKey, group.PathUserCAPrivateKey} {
			if _, ok := uniqPrivKeys[path]; ok {
				continue
			}

			pk, err := parsePrivateKeyFile(path)
			if err != nil {
				return err
			}

			uniqPrivKeys[path] = pk
		}

		conf.HostGroups[i].Keys.HostCAPublicKey = uniqPubKeys[group.PathHostCAPublicKey]
		conf.HostGroups[i].Keys.UserCAPublicKey = uniqPubKeys[group.PathUserCAPublicKey]
		conf.HostGroups[i].Keys.HostCAPrivateKey = uniqPrivKeys[group.PathHostCAPrivateKey]
		conf.HostGroups[i].Keys.UserCAPrivateKey = uniqPrivKeys[group.PathUserCAPrivateKey]
	}

	return nil
}

func parseCertValidities(conf *Config) error {
	for i, group := range conf.HostGroups {
		validity := group.CertValidity

		if validity == "token" {
			conf.HostGroups[i].CertDuration = 0
			continue
		}

		dur, err := time.ParseDuration(validity)
		if err != nil {
			return err
		}

		conf.HostGroups[i].CertDuration = uint64(dur.Seconds())
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

// matchesHost determines whether the given host matches host2.
// host2 may be a wildcard domain in the form of
//
//	*.example.com
//
// which matches any subdomain of example.com, but not example.com itself.
func matchesHost(host, host2 string) bool {
	if strings.HasPrefix(host2, "*.") {
		root, _ := strings.CutPrefix(host2, "*.")

		return strings.HasSuffix(host, root) && host != root
	} else {
		return host == host2
	}
}

func (c Config) GetInfo(host string) (HostInfo, error) {
	for _, hostGroup := range c.HostGroups {
		for hostName, caURL := range hostGroup.Hosts {
			if matchesHost(host, hostName) {
				return HostInfo{
					Name:         hostName,
					URL:          caURL,
					CertDuration: hostGroup.CertDuration,
					Keys:         hostGroup.Keys,
				}, nil
			}
		}
	}

	return HostInfo{}, errors.New(ERR_HOST_NOT_FOUND)
}