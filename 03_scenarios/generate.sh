#!/usr/bin/env bash
# Generate synthetic logs with EvidenceForge, then build the three telemetry views (complete / gap / gap + note).
#
#   bash 03_scenarios/generate.sh v1            # the 8 v1 test incidents  (S01 S02 S04 S06 S07 S08 S10 S12)
#   bash 03_scenarios/generate.sh s2            # the 8 v3 held-out test incidents (S21-S28)
#   bash 03_scenarios/generate.sh tpool         # v2 practice pool (T001-T060)
#   bash 03_scenarios/generate.sh tpool3        # v3 practice pool extension (T061-T300)
#   bash 03_scenarios/generate.sh S01 T005 ...  # or any explicit IDs
#
# Run from the repo root with the project venv active (see README). Needs tools/EvidenceForge (uv sync done).
# Output: 03_scenarios/generated/<ID>/C1 (raw logs, git-ignored) and 04_conditions/*/<ID> (views).
# EFORGE_SPOOL_DIR must be a private folder. On Windows, do NOT put it under AppData (EvidenceForge rejects it).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPOOL="${EFORGE_SPOOL_DIR:-$HOME/eforge-spool}"
mkdir -p "$SPOOL"

ids=()
for a in "$@"; do
  case "$a" in
    v1)     ids+=(S01 S02 S04 S06 S07 S08 S10 S12) ;;
    s2)     ids+=(S21 S22 S23 S24 S25 S26 S27 S28) ;;
    tpool)  for i in $(seq 1 60);   do ids+=("$(printf 'T%03d' "$i")"); done ;;
    tpool3) for i in $(seq 61 300); do ids+=("$(printf 'T%03d' "$i")"); done ;;
    *)      ids+=("$a") ;;
  esac
done
[ ${#ids[@]} -gt 0 ] || { echo "usage: bash 03_scenarios/generate.sh v1|s2|tpool|tpool3|<ID>..."; exit 1; }

built=()
for id in "${ids[@]}"; do
  cfg="$ROOT/03_scenarios/configs/$id.yaml"
  [ -f "$cfg" ] || cfg="$ROOT/03_scenarios/tpool/configs/$id.yaml"
  [ -f "$cfg" ] || { echo "$id: no config (skipped)"; continue; }
  out="$ROOT/03_scenarios/generated/$id/C1"
  if [ -f "$out/GROUND_TRUTH.json" ]; then echo "$id: already generated"; built+=("$id"); continue; fi
  echo "$id: generating..."
  if (cd "$ROOT/tools/EvidenceForge" && EFORGE_SPOOL_DIR="$SPOOL" PYTHONUTF8=1 uv run eforge generate "$cfg" -o "$out" --overwrite) \
       > "$ROOT/03_scenarios/generated/$id.log" 2>&1; then
    built+=("$id")
  else
    echo "$id: EvidenceForge failed (see 03_scenarios/generated/$id.log). A few T-scenarios needed a reseed; their metas say so."
  fi
done

[ ${#built[@]} -gt 0 ] && (cd "$ROOT" && PYTHONUTF8=1 python harness/build_views.py "${built[@]}")
echo "done: ${#built[@]} scenarios with views"
