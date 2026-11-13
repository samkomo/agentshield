#!/usr/bin/env bash
# AgentShield installer.
#
# Puts a checkout of AgentShield in your home directory and an `agentshield`
# command on your PATH. It never uses sudo, never edits your shell files, and
# writes nothing outside the two folders named below. Running it again updates
# the checkout in place.
#
#   curl -fsSL https://raw.githubusercontent.com/samkomo/agentshield/main/install.sh | bash
#   curl -fsSL .../install.sh | bash -s -- --ref v0.1.0
#   curl -fsSL .../install.sh | bash -s -- --uninstall
#
# Options (each also has an environment variable):
#   --ref REF        branch, tag or commit to install      AGENTSHIELD_REF          (main)
#   --dir DIR        where the checkout goes               AGENTSHIELD_INSTALL_DIR  (~/.local/share/agentshield)
#   --bin-dir DIR    where the command goes                AGENTSHIELD_BIN_DIR      (~/.local/bin)
#   --repo URL       Git URL to install from               AGENTSHIELD_REPO_URL
#   --uninstall      remove the command and the checkout; your data in ~/.agentshield is kept
set -euo pipefail

REPO_URL="${AGENTSHIELD_REPO_URL:-https://github.com/samkomo/agentshield.git}"
REF="${AGENTSHIELD_REF:-main}"
INSTALL_DIR="${AGENTSHIELD_INSTALL_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/agentshield}"
BIN_DIR="${AGENTSHIELD_BIN_DIR:-$HOME/.local/bin}"
UNINSTALL=0
MARKER="AgentShield launcher"
MIN_NODE=24

say() { printf '%s\n' "$*"; }
die() { printf 'agentshield install: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="${2:?--ref needs a value}"; shift 2 ;;
    --dir) INSTALL_DIR="${2:?--dir needs a value}"; shift 2 ;;
    --bin-dir) BIN_DIR="${2:?--bin-dir needs a value}"; shift 2 ;;
    --repo) REPO_URL="${2:?--repo needs a value}"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,19p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || true; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

LAUNCHER="$BIN_DIR/agentshield"

ours() { [ -f "$LAUNCHER" ] && grep -q "$MARKER" "$LAUNCHER"; }

if [ "$UNINSTALL" = 1 ]; then
  if [ -e "$LAUNCHER" ]; then
    ours || die "$LAUNCHER was not written by this installer; leaving it alone."
    rm -f "$LAUNCHER"; say "Removed $LAUNCHER"
  fi
  if [ -d "$INSTALL_DIR" ]; then
    [ -f "$INSTALL_DIR/bin/agentshield.mjs" ] || die "$INSTALL_DIR does not look like an AgentShield checkout; leaving it alone."
    rm -rf "$INSTALL_DIR"; say "Removed $INSTALL_DIR"
  fi
  say "Your gateway data (keys, database, audit log) was not touched: ${AGENTSHIELD_HOME:-$HOME/.agentshield}"
  exit 0
fi

# --- what is on this machine -------------------------------------------------
case "$(uname -s)" in
  Darwin|Linux) ;;
  *) die "unsupported system: $(uname -s). AgentShield runs on macOS and Linux." ;;
esac
command -v git >/dev/null 2>&1 || die "git is required and was not found on PATH."
NODE_BIN="$(command -v node || true)"
[ -n "$NODE_BIN" ] || die "Node.js $MIN_NODE or later is required and 'node' was not found on PATH. Install it from https://nodejs.org and run this again."
NODE_MAJOR="$("$NODE_BIN" -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge "$MIN_NODE" ] || die "Node.js $MIN_NODE or later is required; $NODE_BIN is $("$NODE_BIN" --version). Install a newer one and run this again."
if [ -e "$LAUNCHER" ] && ! ours; then
  die "$LAUNCHER already exists and was not written by this installer. Move it, or pass --bin-dir."
fi

checkout() { # $1 = repository directory
  git -C "$1" checkout --quiet --detach "origin/$REF" 2>/dev/null \
    || git -C "$1" checkout --quiet --detach "$REF" 2>/dev/null \
    || die "could not find '$REF' in $REPO_URL"
}

# --- the checkout ------------------------------------------------------------
if [ -d "$INSTALL_DIR/.git" ]; then
  [ -z "$(git -C "$INSTALL_DIR" status --porcelain)" ] || die "$INSTALL_DIR has local changes. Commit or discard them, then run this again."
  say "Updating $INSTALL_DIR"
  git -C "$INSTALL_DIR" remote set-url origin "$REPO_URL"
  git -C "$INSTALL_DIR" fetch --quiet --tags origin
  checkout "$INSTALL_DIR"
elif [ -e "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]; then
  die "$INSTALL_DIR exists and is not an AgentShield checkout. Move it, or pass --dir."
else
  say "Installing into $INSTALL_DIR"
  mkdir -p "$(dirname "$INSTALL_DIR")"
  STAGING="$INSTALL_DIR.staging.$$"
  trap 'rm -rf "$STAGING"' EXIT
  git clone --quiet "$REPO_URL" "$STAGING"
  checkout "$STAGING"
  [ -f "$STAGING/bin/agentshield.mjs" ] || die "$REPO_URL at $REF is not an AgentShield repository."
  rmdir "$INSTALL_DIR" 2>/dev/null || true
  mv "$STAGING" "$INSTALL_DIR"
  trap - EXIT
fi

# --- the command -------------------------------------------------------------
mkdir -p "$BIN_DIR"
TMP_LAUNCHER="$LAUNCHER.tmp.$$"
cat > "$TMP_LAUNCHER" <<EOF
#!/bin/sh
# $MARKER, written by install.sh. Re-run the installer to update it.
# Uses the Node.js found at install time, or whichever 'node' is on PATH if that one has gone.
if [ -x "$NODE_BIN" ]; then NODE="$NODE_BIN"; else NODE=node; fi
exec "\$NODE" "$INSTALL_DIR/bin/agentshield.mjs" "\$@"
EOF
chmod 755 "$TMP_LAUNCHER"
mv "$TMP_LAUNCHER" "$LAUNCHER"

# --- check it runs -----------------------------------------------------------
VERSION="$("$LAUNCHER" --version)" || die "the installed command did not run. Nothing else was changed."
say "Installed $VERSION"
say "  command:  $LAUNCHER"
say "  checkout: $INSTALL_DIR"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    say ""
    say "$BIN_DIR is not on your PATH. Add it by putting this line in your shell's startup file:"
    say "  export PATH=\"$BIN_DIR:\$PATH\""
    ;;
esac

say ""
say "Next:"
say "  agentshield service install    start the gateway and keep it running"
say "  agentshield connect hermes     protect a Hermes agent"
say "  agentshield doctor             check everything end to end"
