#!/usr/bin/env bash
#
# Unit tests for install.sh — the AGENT installer this repo owns. ServerKit
# vendors this file into its scripts/ and serves it at
# GET /api/v1/servers/install.sh; edit it HERE and re-vendor there.
#
# install.sh is source-able: when sourced it defines every function and then
# returns *before* main() (the BASH_SOURCE guard). Combined with a curl stub
# on PATH that serves GitHub-API fixtures, that lets us exercise version
# discovery (paging!), checksum verification and argument parsing with no
# network and no root.
#
# Run:  bash scripts/test/test_agent_install.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="$SCRIPT_DIR/../../install.sh"

PASS=0
FAIL=0
SKIP=0
ok()   { PASS=$((PASS + 1)); printf '  \033[32m✔\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  \033[31m✘\033[0m %s\n' "$1"; }
skip() { SKIP=$((SKIP + 1)); printf '  \033[33m∼\033[0m %s (skipped)\n' "$1"; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --------------------------------------------------------------------------
# curl stub: serves GitHub-API release pages / release assets from fixture
# files in $FIXTURES, records every requested URL in $CURL_LOG, and mimics
# `curl -f` on a missing fixture (exit 22).
# --------------------------------------------------------------------------
STUB_BIN="$WORK/bin"
FIXTURES="$WORK/fixtures"
CURL_LOG="$WORK/curl.log"
mkdir -p "$STUB_BIN" "$FIXTURES"
: > "$CURL_LOG"

cat > "$STUB_BIN/curl" <<'EOF'
#!/bin/bash
url=""; out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -*) shift ;;
        *)  url="$1"; shift ;;
    esac
done
printf '%s\n' "$url" >> "$CURL_LOG"
case "$url" in
    *"/releases?"*)   body="$FIXTURES/releases_page_${url##*page=}.json" ;;
    *"/checksums.txt") body="$FIXTURES/checksums.txt" ;;
    *)                body="$FIXTURES/asset" ;;
esac
[ -f "$body" ] || exit 22
if [ -n "$out" ]; then cp "$body" "$out"; else cat "$body"; fi
EOF
chmod +x "$STUB_BIN/curl"
export PATH="$STUB_BIN:$PATH"
export FIXTURES CURL_LOG

# --------------------------------------------------------------------------
# Source install.sh (functions only — the BASH_SOURCE guard skips main).
# --------------------------------------------------------------------------
# shellcheck disable=SC1090
source "$INSTALL_SH"
set +e +u   # hand control back to the harness; tests re-arm set -e per subshell

printf '\nagent install.sh unit tests\n\n'

# --------------------------------------------------------------------------
# T0 — release-coordinate contract. This is the test whose absence let the
# installer rot: the agent moved to its own repo (plain vX.Y.Z tags) and this
# script kept asking jhd3197/ServerKit for `agent-v*` tags that exist nowhere,
# so every enrollment 404'd at the download step. The old T1/T2 below actively
# encoded the dead scheme with agent-v* fixtures and stayed green throughout.
# --------------------------------------------------------------------------
repo_default="$(grep -m1 '^GITHUB_REPO=' "$INSTALL_SH" | cut -d'"' -f2)"
if [ "$repo_default" = "jhd3197/serverkit-agent" ]; then
    ok "GITHUB_REPO points at the repo that publishes agent binaries"
else
    bad "GITHUB_REPO=[$repo_default]; agent releases live in jhd3197/serverkit-agent"
fi
if grep -qE 'releases/download/v\$\{VERSION\}/\$\{ASSET_NAME\}' "$INSTALL_SH"; then
    ok "download URL uses the published /v\${VERSION}/ tag scheme"
else
    bad "download URL does not use /v\${VERSION}/: $(grep -n 'releases/download' "$INSTALL_SH" | tr '\n' ' ')"
fi
if grep -q 'agent-v' "$INSTALL_SH"; then
    # A prose mention in a comment is fine; a URL or a tag filter is not.
    if grep 'agent-v' "$INSTALL_SH" | grep -qvE '^\s*#'; then
        bad "live agent-v reference remains: $(grep -n 'agent-v' "$INSTALL_SH" | grep -vE ':\s*#' | tr '\n' ' ')"
    else
        ok "no live agent-v* references remain (comments only)"
    fi
else
    ok "no agent-v* references remain"
fi

# --------------------------------------------------------------------------
# T1 — version discovery picks the newest vX.Y.Z, and must SKIP the malformed
# release tagged literally "v" that sits in the agent repo's release list.
# Without the digit guard that tag yields an empty VERSION and the installer
# builds .../releases/download/v/serverkit-agent--linux-amd64.tar.gz.
# --------------------------------------------------------------------------
printf '[{"tag_name": "v"},{"tag_name": "v1.2.0"},{"tag_name": "v1.1.0"}]' \
    > "$FIXTURES/releases_page_1.json"

: > "$CURL_LOG"
if ! got="$(
    # && chain: set -e is suppressed inside an if-condition substitution, so
    # only an explicit chain makes get_latest_version's status gate the result.
    set -Eeuo pipefail
    VERSION="latest"; SERVERKIT_AGENT_VERSION=""; GITHUB_REPO="jhd3197/serverkit-agent"
    get_latest_version >/dev/null \
        && printf '%s' "$VERSION"
)"; then
    bad "version discovery aborted under set -Eeuo pipefail"
elif [ "$got" = "1.2.0" ]; then
    ok "discovery picks the newest vX.Y.Z and skips the malformed \"v\" tag"
else
    bad "discovery: VERSION=[$got], want 1.2.0"
fi
if grep -q 'per_page=100' "$CURL_LOG"; then
    ok "release requests ask GitHub for per_page=100"
else
    bad "per_page=100 missing from release requests"
fi
if ! grep -q 'page=2' "$CURL_LOG"; then
    ok "discovery stops once a tag is found (no page=2 request)"
else
    bad "unexpected page sequence: $(tr '\n' ' ' < "$CURL_LOG")"
fi

# --------------------------------------------------------------------------
# T1b — paging still works when page 1 holds nothing usable.
# --------------------------------------------------------------------------
mkdir -p "$WORK/fx1b"
printf '[{"tag_name": "v"},{"tag_name": "nightly"}]' > "$WORK/fx1b/releases_page_1.json"
printf '[{"tag_name": "v0.9.1"}]' > "$WORK/fx1b/releases_page_2.json"
: > "$CURL_LOG"
if ! got="$(
    set -Eeuo pipefail
    FIXTURES="$WORK/fx1b"
    VERSION="latest"; SERVERKIT_AGENT_VERSION=""; GITHUB_REPO="jhd3197/serverkit-agent"
    get_latest_version >/dev/null \
        && printf '%s' "$VERSION"
)"; then
    bad "paged discovery aborted under set -Eeuo pipefail"
elif [ "$got" = "0.9.1" ]; then
    ok "discovery pages forward past a page with no usable tags"
else
    bad "paged discovery: VERSION=[$got], want 0.9.1"
fi

# --------------------------------------------------------------------------
# T2 — discovery must fail LOUDLY (exit 1), not silently, when no vX.Y.Z tag
# exists on any page; and an empty page ends the paging early.
# --------------------------------------------------------------------------
mkdir -p "$WORK/fx2"
printf '[{"tag_name": "v"},{"tag_name": "nightly"}]' > "$WORK/fx2/releases_page_1.json"
printf '[]' > "$WORK/fx2/releases_page_2.json"
: > "$CURL_LOG"
if (
    set -Eeuo pipefail
    FIXTURES="$WORK/fx2"
    VERSION="latest"; SERVERKIT_AGENT_VERSION=""; GITHUB_REPO="jhd3197/serverkit-agent"
    get_latest_version
) >/dev/null 2>&1; then
    bad "discovery must exit non-zero when no vX.Y.Z tag exists"
else
    ok "discovery fails loudly (exit 1) when no vX.Y.Z tag exists on any page"
fi
if grep -q 'page=2' "$CURL_LOG" && ! grep -q 'page=3' "$CURL_LOG"; then
    ok "an empty release page stops the paging (no page=3 request)"
else
    bad "empty-page stop broken: $(tr '\n' ' ' < "$CURL_LOG")"
fi

# --------------------------------------------------------------------------
# T2b — verify_checksum must fetch checksums.txt from the /v${VERSION}/ tag.
# Exercised for real through the curl stub, so a URL regression shows up here
# and not only in the static grep above.
# --------------------------------------------------------------------------
: > "$CURL_LOG"
(
    set +e
    t="$WORK/ck-url"; mkdir -p "$t"
    VERSION="1.2.0"; GITHUB_REPO="jhd3197/serverkit-agent"
    verify_checksum "$t" "serverkit-agent-1.2.0-linux-amd64.tar.gz"
) >/dev/null 2>&1
if grep -q 'serverkit-agent/releases/download/v1.2.0/checksums.txt' "$CURL_LOG"; then
    ok "checksums.txt is fetched from <agent repo>/releases/download/v1.2.0/"
else
    bad "wrong checksums URL: $(tr '\n' ' ' < "$CURL_LOG")"
fi

# --------------------------------------------------------------------------
# T3 — the panel-injected version short-circuits GitHub discovery entirely,
# and an explicit --version is left untouched.
# --------------------------------------------------------------------------
: > "$CURL_LOG"
if ! got="$(
    set -Eeuo pipefail
    VERSION="latest"; SERVERKIT_AGENT_VERSION="9.9.9"; GITHUB_REPO="jhd3197/serverkit-agent"
    get_latest_version >/dev/null \
        && printf '%s' "$VERSION"
)"; then
    bad "panel-injected version path aborted under set -Eeuo pipefail"
elif [ "$got" = "9.9.9" ] && [ ! -s "$CURL_LOG" ]; then
    ok "panel-injected SERVERKIT_AGENT_VERSION is used without any GitHub call"
else
    bad "panel-injected version: VERSION=[$got], curl calls: $(tr '\n' ' ' < "$CURL_LOG")"
fi

: > "$CURL_LOG"
if ! got="$(
    set -Eeuo pipefail
    VERSION="1.2.3"; SERVERKIT_AGENT_VERSION=""; GITHUB_REPO="jhd3197/serverkit-agent"
    get_latest_version >/dev/null \
        && printf '%s' "$VERSION"
)"; then
    bad "explicit --version path aborted under set -Eeuo pipefail"
elif [ "$got" = "1.2.3" ] && [ ! -s "$CURL_LOG" ]; then
    ok "an explicit --version skips discovery"
else
    bad "explicit version: VERSION=[$got]"
fi

# --------------------------------------------------------------------------
# T4 — checksum verification: pass on match, HALT on mismatch, warn-and-
# continue when checksums.txt is not published (older releases).
# --------------------------------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
    asset="serverkit-agent-0.3.2-linux-amd64.tar.gz"

    t="$WORK/ck-good"; mkdir -p "$t"
    printf 'agent-bytes' > "$t/$asset"
    sha="$(sha256sum "$t/$asset" | cut -d' ' -f1)"
    printf '%s  %s\n' "$sha" "$asset" > "$FIXTURES/checksums.txt"
    if (
        set -Eeuo pipefail
        VERSION="0.3.2"; GITHUB_REPO="jhd3197/serverkit-agent"
        verify_checksum "$t" "$asset"
    ) >/dev/null 2>&1; then
        ok "verify_checksum passes on a matching sha256"
    else
        bad "verify_checksum rejected a good archive"
    fi

    t="$WORK/ck-bad"; mkdir -p "$t"
    printf 'agent-bytes' > "$t/$asset"
    printf '%s  %s\n' \
        "0000000000000000000000000000000000000000000000000000000000000000" \
        "$asset" > "$FIXTURES/checksums.txt"
    if (
        set -Eeuo pipefail
        VERSION="0.3.2"; GITHUB_REPO="jhd3197/serverkit-agent"
        verify_checksum "$t" "$asset"
    ) >/dev/null 2>&1; then
        bad "verify_checksum must HALT on a checksum mismatch"
    else
        ok "verify_checksum halts (exit 1) on a checksum mismatch"
    fi

    t="$WORK/ck-missing"; mkdir -p "$t"
    printf 'agent-bytes' > "$t/$asset"
    rm -f "$FIXTURES/checksums.txt"
    if (
        set -Eeuo pipefail
        VERSION="0.3.2"; GITHUB_REPO="jhd3197/serverkit-agent"
        verify_checksum "$t" "$asset"
    ) >/dev/null 2>&1; then
        ok "missing checksums.txt is best-effort (warn + continue)"
    else
        bad "missing checksums.txt must not abort the install"
    fi

    t="$WORK/ck-noentry"; mkdir -p "$t"
    printf 'agent-bytes' > "$t/$asset"
    printf '%s  some-other-file.tar.gz\n' "$sha" > "$FIXTURES/checksums.txt"
    if (
        set -Eeuo pipefail
        VERSION="0.3.2"; GITHUB_REPO="jhd3197/serverkit-agent"
        verify_checksum "$t" "$asset"
    ) >/dev/null 2>&1; then
        ok "checksums.txt without our asset entry is best-effort (warn + continue)"
    else
        bad "a checksums.txt missing our entry must not abort the install"
    fi
    rm -f "$FIXTURES/checksums.txt"
else
    skip "checksum verification — sha256sum unavailable on this host"
fi

# --------------------------------------------------------------------------
# T5 — argument parsing: an option with a missing value must die loudly
# (previously `shift 2` failed silently under set -e), and required-arg
# validation still works.
# --------------------------------------------------------------------------
out="$(bash "$INSTALL_SH" --token 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "requires a value"; then
    ok "--token with no value fails loudly with 'requires a value'"
else
    bad "--token with no value: rc=$rc out=[$out]"
fi

out="$(bash "$INSTALL_SH" --token abc 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "Server URL is required"; then
    ok "missing --server is still reported after the arg-guard change"
else
    bad "missing --server: rc=$rc out=[$out]"
fi

out="$(bash "$INSTALL_SH" --help 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "Usage"; then
    ok "--help still exits 0 with usage"
else
    bad "--help: rc=$rc"
fi

# --------------------------------------------------------------------------
# T6 — the source guard must not break piped execution (curl | bash), where
# BASH_SOURCE[0] is unset. No args → main runs → 'token is required'.
# --------------------------------------------------------------------------
out="$(bash < "$INSTALL_SH" 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "Registration token is required"; then
    ok "piped execution (stdin, as curl|bash) still reaches main()"
else
    bad "piped execution broken by the source guard: rc=$rc out=[$out]"
fi

# --------------------------------------------------------------------------
# T7 — create_user falls back to busybox adduser -S -D -H when useradd is
# absent (Alpine). Restricted PATH: only these stubs are visible.
# --------------------------------------------------------------------------
UBIN="$WORK/ubin"; mkdir -p "$UBIN"
printf '#!/bin/bash\nexit 1\n' > "$UBIN/id"          # user does not exist yet
printf '#!/bin/bash\nexit 2\n' > "$UBIN/getent"      # no docker group
cat > "$UBIN/adduser" <<EOF
#!/bin/bash
printf '%s\n' "\$*" > "$WORK/adduser.args"
EOF
chmod +x "$UBIN"/*
rm -f "$WORK/adduser.args"
if (
    set -Eeuo pipefail
    PATH="$UBIN"
    create_user
) >/dev/null 2>&1 && grep -q -- '-S -D -H' "$WORK/adduser.args" 2>/dev/null; then
    ok "create_user falls back to adduser -S -D -H when useradd is missing"
else
    bad "busybox adduser fallback broken: args=[$(cat "$WORK/adduser.args" 2>/dev/null)]"
fi

UBIN2="$WORK/ubin2"; mkdir -p "$UBIN2"
printf '#!/bin/bash\nexit 1\n' > "$UBIN2/id"
printf '#!/bin/bash\nexit 2\n' > "$UBIN2/getent"
cat > "$UBIN2/useradd" <<EOF
#!/bin/bash
printf '%s\n' "\$*" > "$WORK/useradd.args"
EOF
chmod +x "$UBIN2"/*
rm -f "$WORK/useradd.args"
if (
    set -Eeuo pipefail
    PATH="$UBIN2"
    create_user
) >/dev/null 2>&1 && grep -q -- '-r' "$WORK/useradd.args" 2>/dev/null; then
    ok "create_user still prefers useradd -r when it exists"
else
    bad "useradd path broken: args=[$(cat "$WORK/useradd.args" 2>/dev/null)]"
fi

# --------------------------------------------------------------------------
# T8 — portability regression guard: no GNU-only grep -P may creep back in
# (BusyBox/BSD grep lack it; it's what made discovery Alpine-hostile).
# --------------------------------------------------------------------------
if grep -Eq 'grep +-[a-zA-Z]*P' "$INSTALL_SH"; then
    bad "install.sh reintroduced GNU-only 'grep -P'"
else
    ok "no GNU-only 'grep -P' in install.sh"
fi

# --------------------------------------------------------------------------
printf '\n%d passed, %d failed, %d skipped\n\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]
