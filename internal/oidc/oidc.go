package oidc

import (
	"errors"
	"fmt"
	"sort"

	"github.com/indigo-dc/liboidcagent-go"
	"golang.org/x/exp/maps"
)

const (
	APP_HINT = "oinit"
)

// AgentHelper is satisfied by liboidcagent's OIDCAgentError (both by value and
// by pointer, since ErrorWithHelp has a value receiver). It exposes the
// actionable help text the agent returns alongside a failure, which the library
// documents SHOULD be shown to the user.
type AgentHelper interface {
	ErrorWithHelp() string
}

// AgentErrorMessage returns the most descriptive message available for an error
// returned by GetToken: the agent's error together with its help text when the
// error originates from oidc-agent, otherwise the plain error string.
func AgentErrorMessage(err error) string {
	var h AgentHelper
	if errors.As(err, &h) {
		return h.ErrorWithHelp()
	}
	return err.Error()
}

type socket struct {
	AddressEnvVar string
	Type          string
}

// GetConfiguredAccounts returns a map of configured accounts. The map key is
// the issuer URL, while the corresponding value is a list of oidc-agent
// account short names.
func GetConfiguredAccounts() map[string][]string {
	// liboidcagent provides GetConfiguredAccounts() which however only returns
	// the short names of accounts, no issuer URLs.
	// Make use of GetAccountInfos() to build a map of issuers with existing
	// accounts.

	accounts := make(map[string][]string)

	infos, err := liboidcagent.GetAccountInfos()
	if err != nil {
		// This may also happen if oidc-agent 5 is not installed, as previous
		// versions do not support this call.
		return accounts
	}

	for issuer, info := range infos {
		accs := maps.Keys(info.Accounts)
		sort.Strings(accs)

		accounts[issuer] = accs
	}

	return accounts
}

func GetToken(issuer string, scopes []string) (string, error) {
	req := liboidcagent.TokenRequest{
		IssuerURL:       issuer,
		Scopes:          scopes,
		ApplicationHint: APP_HINT,
	}

	res, err := liboidcagent.GetTokenResponse(req)
	if err != nil {
		// Preserve the error as-is (it is an OIDCAgentError carrying a Help()
		// message); callers can render it via AgentErrorMessage.
		return "", err
	}

	// A successful exchange with an empty access token is still a failure for
	// our purposes: sending it to the CA would only yield a confusing
	// "token rejected" downstream. Surface it here instead.
	if res.Token == "" {
		return "", fmt.Errorf("oidc-agent returned an empty access token for issuer %q", issuer)
	}

	return res.Token, nil
}
