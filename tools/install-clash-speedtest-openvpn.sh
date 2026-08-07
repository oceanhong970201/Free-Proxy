#!/usr/bin/env bash
set -euo pipefail

readonly SPEEDTEST_REPOSITORY="https://github.com/faceair/clash-speedtest.git"
readonly SPEEDTEST_VERSION="v1.8.8"
readonly SPEEDTEST_COMMIT="7972f7bd94c2a755d4db6d1092b5fc3aa3e70652"
readonly MIHOMO_VERSION="v1.19.29"
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly BIN_DIR="$(go env GOPATH)/bin"
readonly BINARY="$BIN_DIR/clash-speedtest"
readonly PATCH="$ROOT/tools/clash-speedtest-mihomo-1.19.29.patch"

has_expected_core() {
  test -x "$BINARY" &&
    go version -m "$BINARY" | grep -Fq $'dep\tgithub.com/metacubex/mihomo\t'"$MIHOMO_VERSION" &&
    go version -m "$BINARY" | grep -Fq $'build\t-tags=with_gvisor'
}

mkdir -p "$BIN_DIR"
if ! has_expected_core; then
  build_dir="$(mktemp -d)"
  trap 'rm -rf "$build_dir"' EXIT
  git init -q "$build_dir"
  git -C "$build_dir" fetch -q --depth 1 "$SPEEDTEST_REPOSITORY" "$SPEEDTEST_COMMIT"
  git -C "$build_dir" checkout -q --detach FETCH_HEAD
  test "$(git -C "$build_dir" rev-parse HEAD)" = "$SPEEDTEST_COMMIT"
  git -C "$build_dir" apply --unidiff-zero --check "$PATCH"
  git -C "$build_dir" apply --unidiff-zero "$PATCH"
  (
    cd "$build_dir"
    go mod edit "-require=github.com/metacubex/mihomo@$MIHOMO_VERSION"
    go mod tidy
    go build -tags with_gvisor -trimpath -o "$BINARY" .
  )
fi

has_expected_core
"$BINARY" -v
go version -m "$BINARY" | grep -F $'dep\tgithub.com/metacubex/mihomo\t'
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "$BIN_DIR" >> "$GITHUB_PATH"
fi
echo "installed clash-speedtest $SPEEDTEST_VERSION with Mihomo $MIHOMO_VERSION and gVisor"
