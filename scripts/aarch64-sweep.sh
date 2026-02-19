#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="${ROOT_DIR}/src/tests"

HCC_BIN="${HCC_BIN:-hcc}"
STOP_ON_FAIL="${STOP_ON_FAIL:-0}"
HCC_TIMEOUT_SEC="${HCC_TIMEOUT_SEC:-45}"
HCC_ENABLE_SQLITE_TEST="${HCC_ENABLE_SQLITE_TEST:-0}"
HCC_AARCH64_ASSEMBLE="${HCC_AARCH64_ASSEMBLE:-0}"
AARCH64_CC="${AARCH64_CC:-aarch64-linux-gnu-gcc}"
HCC_FAIL_ON_BACKEND_WARN="${HCC_FAIL_ON_BACKEND_WARN:-1}"

# Guardrails to reduce host OOM risk during large test sweeps.
export HCC_MAX_JOBS="${HCC_MAX_JOBS:-1}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$HCC_MAX_JOBS}"
if [[ -z "${MAKEFLAGS:-}" ]]; then
  export MAKEFLAGS="-j${HCC_MAX_JOBS}"
fi
export MALLOC_ARENA_MAX="${MALLOC_ARENA_MAX:-2}"
HCC_MEM_LIMIT_KB="${HCC_MEM_LIMIT_KB:-2200000}"
if [[ "$HCC_MEM_LIMIT_KB" =~ ^[0-9]+$ ]] && [[ "$HCC_MEM_LIMIT_KB" -gt 0 ]]; then
  ulimit -Sv "$HCC_MEM_LIMIT_KB" || true
fi

if [[ "$HCC_BIN" != */* ]]; then
  if ! command -v "$HCC_BIN" >/dev/null 2>&1; then
    echo "hcc binary not found in PATH: $HCC_BIN" >&2
    exit 127
  fi
elif [[ "$HCC_BIN" != /* ]]; then
  HCC_BIN="${ROOT_DIR}/${HCC_BIN#./}"
fi

pass=0
fail=0
first_failed=""
warn_pat='AArch64: unhandled|IR lowering: goto fallback to function exit'

if ! command -v timeout >/dev/null 2>&1; then
  echo "timeout command not found; install coreutils timeout" >&2
  exit 127
fi

if [[ "$HCC_AARCH64_ASSEMBLE" == "1" ]] && ! command -v "$AARCH64_CC" >/dev/null 2>&1; then
  echo "AArch64 assembler toolchain not found in PATH: $AARCH64_CC" >&2
  exit 127
fi

cd "$TEST_DIR"
while IFS= read -r -d '' file; do
  name="$(basename "$file")"
  if [[ "$name" == "32_sql.HC" && "$HCC_ENABLE_SQLITE_TEST" != "1" ]]; then
    echo "SKIP $name (set HCC_ENABLE_SQLITE_TEST=1 to include)"
    continue
  fi
  out="/tmp/hcc-a64-${name}.out"
  err="/tmp/hcc-a64-${name}.err"

  hcc_args=(-target aarch64 -S "$name" -o /tmp/hcc-a64.s)
  if [[ "$name" == "32_sql.HC" && "$HCC_ENABLE_SQLITE_TEST" == "1" ]]; then
    hcc_args=(-target aarch64 -D__HCC_LINK_SQLITE3__ -S "$name" -o /tmp/hcc-a64.s)
  fi

  if timeout --signal=KILL "${HCC_TIMEOUT_SEC}s" \
    "$HCC_BIN" "${hcc_args[@]}" >"$out" 2>"$err"; then
    if [[ "$HCC_FAIL_ON_BACKEND_WARN" == "1" ]] && grep -En "$warn_pat" "$err" >/dev/null 2>&1; then
      echo "FAIL $name"
      sed -n '1,40p' "$err"
      fail=$((fail + 1))
      if [[ -z "$first_failed" ]]; then
        first_failed="$name"
      fi
      if [[ "$STOP_ON_FAIL" == "1" ]]; then
        break
      fi
      continue
    fi
    if [[ "$HCC_AARCH64_ASSEMBLE" == "1" ]]; then
      if "$AARCH64_CC" -c /tmp/hcc-a64.s -o /tmp/hcc-a64.o >>"$out" 2>>"$err"; then
        echo "PASS $name"
        pass=$((pass + 1))
      else
        echo "FAIL $name"
        sed -n '1,40p' "$err"
        fail=$((fail + 1))
        if [[ -z "$first_failed" ]]; then
          first_failed="$name"
        fi
        if [[ "$STOP_ON_FAIL" == "1" ]]; then
          break
        fi
      fi
    else
      echo "PASS $name"
      pass=$((pass + 1))
    fi
  else
    ec=$?
    echo "FAIL $name"
    if [[ $ec -eq 124 ]]; then
      echo "Timed out after ${HCC_TIMEOUT_SEC}s"
    fi
    sed -n '1,40p' "$err"
    fail=$((fail + 1))
    if [[ -z "$first_failed" ]]; then
      first_failed="$name"
    fi
    if [[ "$STOP_ON_FAIL" == "1" ]]; then
      break
    fi
  fi
done < <(find . -maxdepth 1 -type f -name '*.HC' -print0 | sort -z)

echo
echo "Summary: pass=$pass fail=$fail"
if [[ $fail -ne 0 ]]; then
  echo "First failing test: $first_failed"
  exit 1
fi
