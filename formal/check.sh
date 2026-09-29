#!/usr/bin/env bash
# Runs every TLC configuration of the AKAC formal model and checks its expected outcome:
#   MC*.cfg          faithful model: TLC MUST finish without any violation or error.
#   broken/<M>.cfg   one mutated rule: TLC MUST report the named invariant/property violated.
#   witness/<W>.cfg  non-vacuity: TLC MUST report the named "Never..." predicate violated.
# Usage: formal/check.sh [config ...]   (default: all). Needs java and TLA2TOOLS (path to tla2tools.jar).
set -u
here="$(cd "$(dirname "$0")" && pwd)"
jar="${TLA2TOOLS:?set TLA2TOOLS to the path of tla2tools.jar}"
workers="${TLC_WORKERS:-auto}"
out="${TLC_OUT:-$(mktemp -d)}"
mkdir -p "$out"
cd "$here"
if [ "$#" -gt 0 ]; then configs=("$@"); else configs=(MC*.cfg broken/*.cfg witness/*.cfg); fi
failed=0
for cfg in "${configs[@]}"; do
  name="${cfg%.cfg}"; log="$out/${name//\//_}.log"
  # The single invariant/property a broken or witness config lists is the one that must fail.
  expected="$(awk '/^(INVARIANT|PROPERTY)/{getline; gsub(/ /, ""); print; exit}' "$cfg")"
  start=$(date +%s)
  java -XX:+UseParallelGC -Xss16m -cp "$jar" tlc2.TLC -deadlock -workers "$workers" \
    -metadir "$out/states/${name//\//_}" -config "$cfg" AKAC.tla >"$log" 2>&1
  code=$?
  secs=$(( $(date +%s) - start ))
  stats="$(grep -E '^[0-9.,]+ states generated' "$log" | tail -1)"
  case "$cfg" in
    MC*.cfg)
      if [ "$code" -eq 0 ] && grep -q 'No error has been found' "$log"; then
        echo "PASS  $cfg  holds (${secs}s; $stats)"
      else
        echo "FAIL  $cfg  expected no violation, TLC exit $code (${secs}s)"; grep -E 'Error|violated' "$log" | head -5; failed=1
      fi ;;
    *)
      if grep -Eq "(Invariant|Action property|Temporal properties) .*${expected}.* (is )?violated|${expected} is violated" "$log"; then
        echo "PASS  $cfg  $expected violated as expected (${secs}s; $stats)"
      else
        echo "FAIL  $cfg  expected $expected to be violated, TLC exit $code (${secs}s)"; grep -E 'Error|violated' "$log" | head -5; failed=1
      fi ;;
  esac
done
echo "logs: $out"
exit "$failed"
