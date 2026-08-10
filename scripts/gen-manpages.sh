#!/bin/sh
# Generate roff man pages from the Markdown sources in man/*.md using go-md2man,
# plus gzipped copies for the Linux packages.
#
# Invoked by `make man` and by the goreleaser `before` hook, so it must not
# depend on `make`. Only `go` (to run go-md2man), sed and gzip are required.
set -eu

# Run from the repository root regardless of where we are called from.
cd "$(dirname "$0")/.."

# Pinned so packaged man pages are reproducible.
GO_MD2MAN="github.com/cpuguy83/go-md2man/v2@v2.0.4"

VERSION="$(cat VERSION 2>/dev/null || echo dev)"

# Use SOURCE_DATE_EPOCH when set (reproducible builds), otherwise today.
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
	DATE="$(date -u -d "@${SOURCE_DATE_EPOCH}" +'%B %Y' 2>/dev/null \
		|| date -u -r "${SOURCE_DATE_EPOCH}" +'%B %Y')"
else
	DATE="$(date -u +'%B %Y')"
fi

for src in man/*.md; do
	[ -e "$src" ] || continue
	out="${src%.md}"                 # man/oinit.1.md -> man/oinit.1
	tmp="$(mktemp)"
	sed -e "s|@VERSION@|${VERSION}|g" -e "s|@DATE@|${DATE}|g" "$src" > "$tmp"
	go run "$GO_MD2MAN" -in "$tmp" -out "$out"
	rm -f "$tmp"
	# Keep the uncompressed roff (used by the Homebrew cask) and also emit a
	# gzipped copy (used by the deb/rpm/apk/archlinux packages). -n keeps the
	# gzip output reproducible (no name/timestamp header).
	gzip -9 -n -c "$out" > "$out.gz"
	echo "generated $out and $out.gz"
done
