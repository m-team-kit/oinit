//go:build !windows
// +build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadTokenFile(t *testing.T) {
	dir := t.TempDir()

	writeFile := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("valid owned 0600 file", func(t *testing.T) {
		p := writeFile("good", "  my-token\n", 0o600)
		tok, ok := readTokenFile(p)
		if !ok || tok != "my-token" {
			t.Fatalf("got (%q, %v), want (\"my-token\", true)", tok, ok)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if tok, ok := readTokenFile(filepath.Join(dir, "nope")); ok {
			t.Fatalf("got (%q, true), want (\"\", false)", tok)
		}
	})

	t.Run("empty file rejected", func(t *testing.T) {
		p := writeFile("empty", "   \n", 0o600)
		if tok, ok := readTokenFile(p); ok {
			t.Fatalf("got (%q, true), want (\"\", false)", tok)
		}
	})

	t.Run("group/other-writable rejected", func(t *testing.T) {
		p := writeFile("loose", "my-token", 0o666)
		if tok, ok := readTokenFile(p); ok {
			t.Fatalf("got (%q, true) for world-writable file, want (\"\", false)", tok)
		}
	})

	t.Run("directory rejected", func(t *testing.T) {
		p := filepath.Join(dir, "adir")
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if tok, ok := readTokenFile(p); ok {
			t.Fatalf("got (%q, true) for directory, want (\"\", false)", tok)
		}
	})

	t.Run("symlink not followed", func(t *testing.T) {
		target := writeFile("target", "secret", 0o600)
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if tok, ok := readTokenFile(link); ok {
			t.Fatalf("got (%q, true) via symlink, want (\"\", false)", tok)
		}
	})
}
