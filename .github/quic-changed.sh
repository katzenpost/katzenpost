#!/bin/sh
set -eu
base=$1
head=$2
labels=${3:-}
case " $labels " in *" quic "*) echo true; exit 0 ;; esac
for f in $(git diff --name-only "$base...$head"); do
  case "$f" in
    quic/*) echo true; exit 0 ;;
  esac
done
if git diff "$base...$head" -- go.mod go.sum | grep -qE '^[+-].*quic-go'; then echo true; exit 0; fi
if git diff "$base...$head" -- . ":(exclude).github" | grep -E '^[+-]' | grep -vE '^(\+\+\+|---) ' | grep -qiE 'quic|DialURL'; then echo true; exit 0; fi
echo false
