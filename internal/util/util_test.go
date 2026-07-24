package util

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchesHost(t *testing.T) {
	type args struct {
		host  string
		port  string
		host2 string
		port2 string
	}
	tests := []struct {
		name    string
		args    args
		matches bool
	}{
		{
			args: args{
				host:  "localhost",
				port:  "22",
				host2: "localhost",
				port2: "22",
			},
			matches: true,
		},
		{
			args: args{
				host:  "example.com",
				port:  "22",
				host2: "example.com",
				port2: "22",
			},
			matches: true,
		},
		{
			args: args{
				host:  "example.com",
				port:  "22",
				host2: "example.org",
				port2: "22",
			},
			matches: false,
		},
		{
			args: args{
				host:  "example.com",
				port:  "22",
				host2: "example.com",
				port2: "2222",
			},
			matches: false,
		},
		{
			args: args{
				host:  "login.example.com",
				port:  "22",
				host2: "*.example.com",
				port2: "22",
			},
			matches: true,
		},
		{
			args: args{
				host:  "example.com",
				port:  "22",
				host2: "*.example.com",
				port2: "22",
			},
			matches: false,
		},
		{
			// Look-alike domain must not match the wildcard.
			args: args{
				host:  "evilexample.com",
				port:  "22",
				host2: "*.example.com",
				port2: "22",
			},
			matches: false,
		},
		{
			// Deeper subdomains still match.
			args: args{
				host:  "a.b.example.com",
				port:  "22",
				host2: "*.example.com",
				port2: "22",
			},
			matches: true,
		},
	}

	for _, tt := range tests {
		assert.Equal(
			t,
			tt.matches,
			MatchesHost(tt.args.host, tt.args.port, tt.args.host2, tt.args.port2),
		)
	}
}

func TestGetenvs(t *testing.T) {
	keys := []string{"TEST_1", "TEST_2"}

	assert.Equal(t, Getenvs(keys...), "")

	os.Setenv(keys[1], keys[1])
	assert.Equal(t, Getenvs(keys...), keys[1])

	os.Setenv(keys[0], keys[0])
	assert.Equal(t, Getenvs(keys...), keys[0])
}

func TestNormalizeIssuer(t *testing.T) {
	assert.Equal(t, "https://op.example.com", NormalizeIssuer("https://op.example.com"))
	assert.Equal(t, "https://op.example.com", NormalizeIssuer("https://op.example.com/"))
	assert.Equal(t, "https://op.example.com", NormalizeIssuer("https://op.example.com//"))
	assert.Equal(t, "https://op.example.com/auth/realms/x", NormalizeIssuer("https://op.example.com/auth/realms/x/"))
	assert.Equal(t, "", NormalizeIssuer(""))

	// Issuers differing only by a trailing slash must normalise equal.
	assert.Equal(t,
		NormalizeIssuer("https://aai.egi.eu/auth/realms/egi"),
		NormalizeIssuer("https://aai.egi.eu/auth/realms/egi/"))
}
