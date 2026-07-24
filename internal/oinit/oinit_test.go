package oinit

import (
	"strings"
	"testing"
)

func TestParseHosts(t *testing.T) {
	t.Run("skips comments and blank lines", func(t *testing.T) {
		in := "oinit-demo.vm.fedcloud.eu:22 https://oinit-demo.vm.fedcloud.eu\n" +
			"hpc.example.org:1022 http://hpc.example.org\n" +
			"# localhost:22 http://localhost:9999\n" +
			"\n" +
			"   \n" +
			"   # indented comment\n" +
			"ssh-oidc-web.data.kit.edu:22 https://ssh-oidc-web.data.kit.edu:443\n"

		hosts := make(map[string]string)
		if err := parseHosts(strings.NewReader(in), hosts); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := map[string]string{
			"oinit-demo.vm.fedcloud.eu:22": "https://oinit-demo.vm.fedcloud.eu",
			"hpc.example.org:1022":         "http://hpc.example.org",
			"ssh-oidc-web.data.kit.edu:22": "https://ssh-oidc-web.data.kit.edu:443",
		}
		if len(hosts) != len(want) {
			t.Fatalf("got %d hosts, want %d: %v", len(hosts), len(want), hosts)
		}
		for k, v := range want {
			if hosts[k] != v {
				t.Errorf("hosts[%q] = %q, want %q", k, hosts[k], v)
			}
		}
		if _, ok := hosts["#"]; ok {
			t.Error("comment line was parsed as a host entry")
		}
		if _, ok := hosts["localhost:22"]; ok {
			t.Error("commented-out host localhost:22 was included")
		}
	})

	t.Run("first definition wins", func(t *testing.T) {
		hosts := make(map[string]string)
		in := "host:22 https://first\nhost:22 https://second\n"
		if err := parseHosts(strings.NewReader(in), hosts); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hosts["host:22"] != "https://first" {
			t.Errorf("got %q, want first definition", hosts["host:22"])
		}
	})

	t.Run("genuinely malformed line errors", func(t *testing.T) {
		hosts := make(map[string]string)
		// A data line with an extra field (space inside the CA position).
		if err := parseHosts(strings.NewReader("host:22 https://ca extra\n"), hosts); err == nil {
			t.Fatal("expected malformed error, got nil")
		}
	})

	t.Run("missing CA errors", func(t *testing.T) {
		hosts := make(map[string]string)
		if err := parseHosts(strings.NewReader("host:22\n"), hosts); err == nil {
			t.Fatal("expected malformed error for line without CA, got nil")
		}
	})
}
