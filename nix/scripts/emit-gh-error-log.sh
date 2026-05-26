#!/usr/bin/env bash
set -euo pipefail

title="${1:?title required}"
log="${2:?log path required}"
bytes="${3:-3500}"

if [[ -f "$log" ]]; then
  message="$(tail -c "$bytes" "$log")"
  if [[ -z "$message" ]]; then
    message="<empty log: $log>"
  fi
else
  message="<missing log: $log>"
fi

message="${message//'%'/'%25'}"
message="${message//$'\r'/'%0D'}"
message="${message//$'\n'/'%0A'}"

echo "::error title=${title}::${message}"
