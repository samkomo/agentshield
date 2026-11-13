#!/bin/bash
# A stand-in for the `hermes` command: just enough of its documented surface for the installer tests.
# State lives in $STUB_HERMES_HOME; every invocation is appended to $STUB_HERMES_HOME/calls.log.
H="${STUB_HERMES_HOME:?}"
mkdir -p "$H"
echo "$*" >> "$H/calls.log"
P="$H/plugins/agentshield"
case "$1 $2" in
  "--version "*) echo "Hermes Agent v${STUB_HERMES_VERSION:-0.22.7} (test) · stable"; echo "Install directory: /nowhere" ;;
  "config path") echo "$H/config.yaml" ;;
  "config env-path") echo "$H/.env" ;;
  "plugins list")
    if [ -f "$P/plugin.yaml" ]; then
      printf '[\n  {"name": "agentshield", "status": "%s", "version": "0.1.0", "description": "x", "source": "%s", "removed": null}\n]\n' \
        "$(cat "$H/.status" 2>/dev/null || echo 'not enabled')" "$(cat "$H/.source" 2>/dev/null || echo user)"
    else echo "[]"; fi ;;
  "plugins install")
    ref=""; enable=0; prev=""
    for a in "$@"; do [ "$prev" = "--ref" ] && ref="$a"; [ "$a" = "--enable" ] && enable=1; prev="$a"; done
    mkdir -p "$P"; echo "name: agentshield" > "$P/plugin.yaml"; echo "git pinned@${ref:0:8}" > "$H/.source"
    [ "$enable" = 1 ] && [ ! -f "$H/.status" ] && echo enabled > "$H/.status"
    echo "Plugin installed" ;;
  "plugins enable") echo enabled > "$H/.status"; echo "Plugin agentshield enabled." ;;
  "plugins remove") rm -rf "$P" "$H/.status" "$H/.source"; echo "Plugin agentshield removed" ;;
  *) echo "hermes stub: unsupported: $*" >&2; exit 2 ;;
esac
