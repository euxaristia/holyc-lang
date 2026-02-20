#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="${ROOT_DIR}/src/tests"

HCC_BIN="${HCC_BIN:-hcc}"
HCC_ENABLE_SQLITE_TEST="${HCC_ENABLE_SQLITE_TEST:-0}"
HCC_TIMEOUT_SEC="${HCC_TIMEOUT_SEC:-45}"

if [[ "$HCC_BIN" != */* ]]; then
  if ! command -v "$HCC_BIN" >/dev/null 2>&1; then
    echo "hcc binary not found in PATH: $HCC_BIN" >&2
    exit 127
  fi
elif [[ "$HCC_BIN" != /* ]]; then
  HCC_BIN="${ROOT_DIR}/${HCC_BIN#./}"
fi

if ! command -v timeout >/dev/null 2>&1; then
  echo "timeout command not found; install coreutils timeout" >&2
  exit 127
fi

tmp_emitted="$(mktemp)"
tmp_bad="$(mktemp)"
tmp_out="$(mktemp)"
tmp_err="$(mktemp)"
cleanup() {
  rm -f "$tmp_emitted" "$tmp_bad" "$tmp_out" "$tmp_err"
}
trap cleanup EXIT

# Opcodes intentionally supported by src/codegen-aarch64.c.
supported_ops=(
  nop alloca load store gep
  iadd isub imul idiv udiv irem urem ineg
  fadd fsub fmul fdiv fneg
  and or xor shl shr sar not
  trunc zext sext fptrunc fpext fptoui fptosi uitofp sitofp ptrtoint inttoptr bitcast
  ret br jmp loop switch call phi
)

is_supported() {
  local op="$1"
  if [[ "$op" == cmp_* ]]; then
    return 0
  fi
  for it in "${supported_ops[@]}"; do
    if [[ "$it" == "$op" ]]; then
      return 0
    fi
  done
  return 1
}

cd "$TEST_DIR"
while IFS= read -r -d '' file; do
  name="$(basename "$file")"
  if [[ "$name" == "32_sql.HC" && "$HCC_ENABLE_SQLITE_TEST" != "1" ]]; then
    continue
  fi

  hcc_args=(--dump-ir "$name")
  if [[ "$name" == "32_sql.HC" && "$HCC_ENABLE_SQLITE_TEST" == "1" ]]; then
    hcc_args=(-D__HCC_LINK_SQLITE3__ --dump-ir "$name")
  fi

  if timeout --signal=KILL "${HCC_TIMEOUT_SEC}s" \
    "$HCC_BIN" "${hcc_args[@]}" >"$tmp_out" 2>"$tmp_err"; then
    :
  else
    ec=$?
    echo "FAIL $name (dump-ir failed, ec=$ec)" >&2
    if [[ $ec -eq 124 || $ec -eq 137 ]]; then
      echo "Timed out after ${HCC_TIMEOUT_SEC}s" >&2
    fi
    sed -n '1,40p' "$tmp_err" >&2
    if [[ "$name" == "32_sql.HC" && "$HCC_ENABLE_SQLITE_TEST" == "1" ]] &&
       grep -Eiq "sqlite|cannot find -lsqlite3|fatal error: sqlite3\\.h" "$tmp_err"; then
      echo "Hint: SQLite test failed under current toolchain." >&2
      echo "Hint: install sqlite3 dev libs or run with HCC_ENABLE_SQLITE_TEST=0." >&2
    fi
    exit 1
  fi

  awk '/^[[:space:]]{4}[a-z_]+[[:space:]]/{print $1}' "$tmp_out" >>"$tmp_emitted"
done < <(find . -maxdepth 1 -type f -name '*.HC' -print0 | sort -z)

sort -u "$tmp_emitted" | while IFS= read -r op; do
  [[ -z "$op" || "$op" == "arg" ]] && continue
  if ! is_supported "$op"; then
    echo "$op" >>"$tmp_bad"
  fi
done

if [[ -s "$tmp_bad" ]]; then
  echo "AArch64 opcode audit failed. Unsupported emitted IR ops:" >&2
  sort -u "$tmp_bad" >&2
  exit 1
fi

echo "AArch64 opcode audit PASS"
