
#!/usr/bin/env bash
#
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
TOOLS_MOD="${REPO_ROOT}/internal/tools/go.mod"

MODE=""
OUT_DIR=""
BASE_DIR=""
BASE_BRANCH="origin/main"
ALLOW_BREAKING="${ALLOW_BREAKING_CHANGES:-false}"

TEMP_DIR="$(mktemp -d)"
WORKTREE_DIR=""

cleanup() {
  if [[ -n "$WORKTREE_DIR" ]]; then
    git worktree remove --force "$WORKTREE_DIR" \
      >/dev/null 2>&1 || true
  fi

  rm -rf -- "$TEMP_DIR"
}

trap cleanup EXIT

usage() {
  cat <<'EOF'
Usage:
  api-compatibility.sh --generate <dir>
  api-compatibility.sh --check <baseline-dir>
  api-compatibility.sh --local [branch]

Modes:
  --generate <dir>  Generate API snapshots.
  --check <dir>     Check the current API against snapshots.
  --local [branch]  Generate a temporary baseline from a branch
                    and compare it with the current checkout.

Environment:
  ALLOW_BREAKING_CHANGES=true
    Allow detected breaking changes without failing the check.
    All detected changes are still reported.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

# Parse arguments.
while (($# > 0)); do
  case "$1" in
    --generate)
      [[ -n "$MODE" ]] && die "Specify exactly one mode."
      (($# >= 2)) || die "--generate requires a directory."
      MODE="generate"
      OUT_DIR="$2"
      shift 2
      ;;
    --check)
      [[ -n "$MODE" ]] && die "Specify exactly one mode."
      (($# >= 2)) || die "--check requires a baseline directory."
      MODE="check"
      BASE_DIR="$2"
      shift 2
      ;;
    --local)
      [[ -n "$MODE" ]] && die "Specify exactly one mode."
      MODE="local"
      shift

      if (($# > 0)) && [[ "$1" != --* ]]; then
        BASE_BRANCH="$1"
        shift
      fi
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "Unknown argument: $1"
      ;;
  esac
done

[[ -n "$MODE" ]] || {
  usage >&2
  exit 2
}

[[ "$ALLOW_BREAKING" == "true" ||
   "$ALLOW_BREAKING" == "false" ]] ||
  die "ALLOW_BREAKING_CHANGES must be true or false."

# Discover packages from the current checkout.
# Exclude internal implementation packages, tools, and test support.
get_public_packages() {
  local packages

  packages="$(GOOS=linux go list ./...)" || return $?

  printf '%s\n' "$packages" |
    awk '
      !/\/internal(\/|$)/ &&
      !/\/tools(\/|$)/ &&
      !/\/testsupport(\/|$)/
    '
}

generate_snapshots() {
  local output_dir="$1"
  local packages
  local pkg
  local state_file
  local failed=0

  packages="$(get_public_packages)" ||
    die "Failed to discover packages in $(pwd)."

  [[ -n "$packages" ]] ||
    die "No public packages were discovered in $(pwd)."

  mkdir -p "$output_dir"

  printf 'Generating API snapshots in %s\n' "$output_dir"

  while IFS= read -r pkg; do
    [[ -n "$pkg" ]] || continue

    state_file="${output_dir}/${pkg}/apidiff.state"
    mkdir -p "$(dirname "$state_file")"

    printf 'Generating baseline: %s\n' "$pkg"

    if ! GOOS=linux CGO_ENABLED=0 \
      go tool -modfile="$TOOLS_MOD" apidiff \
      -w "$state_file" "$pkg"; then
      printf 'ERROR: Failed to generate baseline for %s\n' \
        "$pkg" >&2
      failed=1
    fi
  done <<< "$packages"

  ((failed == 0)) ||
    die "Baseline generation failed for one or more packages."

  printf 'API snapshot generation completed successfully.\n'
}

check_compatibility() {
  local baseline_dir="$1"
  local packages
  local pkg
  local state_file
  local output
  local status
  local has_breaking=0
  local has_errors=0
  local new_packages=0

  [[ -d "$baseline_dir" ]] ||
    die "Baseline directory does not exist: $baseline_dir"

  packages="$(get_public_packages)" ||
    die "Failed to discover packages in $(pwd)."

  [[ -n "$packages" ]] ||
    die "No public packages were discovered in $(pwd)."

  printf 'Comparing current API against baseline: %s\n' \
    "$baseline_dir"

  while IFS= read -r pkg; do
    [[ -n "$pkg" ]] || continue

    state_file="${baseline_dir}/${pkg}/apidiff.state"

    if [[ ! -f "$state_file" ]]; then
      printf 'NOTICE: No baseline snapshot for %s\n' "$pkg"
      new_packages=1
      continue
    fi

    printf 'Checking package: %s\n' "$pkg"

    # Capture output and exit status separately.
    # A tool failure must never be interpreted as a valid comparison.
    if output="$(
      GOOS=linux CGO_ENABLED=0 \
        go tool -modfile="$TOOLS_MOD" apidiff \
        -incompatible "$state_file" "$pkg" \
        2>"${TEMP_DIR}/apidiff.stderr"
    )"; then
      status=0
    else
      status=$?
    fi

    if [[ -s "${TEMP_DIR}/apidiff.stderr" ]]; then
      printf 'Diagnostics for %s:\n' "$pkg" >&2
      cat "${TEMP_DIR}/apidiff.stderr" >&2
    fi

    if ((status != 0)); then
      printf 'ERROR: API analysis failed for %s (exit %s).\n' \
        "$pkg" "$status" >&2
      has_errors=1
      continue
    fi

    if [[ -n "$output" ]]; then
      printf '\nINCOMPATIBLE API CHANGES: %s\n' "$pkg"
      printf '%s\n' "$output"
      has_breaking=1
    fi
  done <<< "$packages"

  if ((new_packages != 0)); then
    printf '\nNOTICE: Packages without baseline snapshots were found.\n'
    printf 'Verify that these are new packages or intentional exclusions.\n'
  fi

  # Analysis errors take precedence over compatibility results.
  if ((has_errors != 0)); then
    die "API compatibility could not be verified."
  fi

  if ((has_breaking != 0)); then
    if [[ "$ALLOW_BREAKING" == "true" ]]; then
      printf '\nWARNING: Breaking API changes detected and explicitly allowed.\n'
      return 0
    fi

    die "Incompatible public API changes detected."
  fi

  printf 'API compatibility check passed.\n'
}

case "$MODE" in
  generate)
    [[ -n "$OUT_DIR" ]] ||
      die "Output directory is required."

    generate_snapshots "$OUT_DIR"
    ;;
  check)
    check_compatibility "$BASE_DIR"
    ;;
  local)
    git rev-parse --verify "${BASE_BRANCH}^{commit}" \
      >/dev/null 2>&1 ||
      die "Base revision not found: $BASE_BRANCH"

    WORKTREE_DIR="${TEMP_DIR}/worktree"

    printf 'Creating baseline worktree from %s\n' "$BASE_BRANCH"
    git worktree add --detach "$WORKTREE_DIR" "$BASE_BRANCH"

    BASE_DIR="${TEMP_DIR}/baseline"

    (
      cd "$WORKTREE_DIR"
      generate_snapshots "$BASE_DIR"
    )

    check_compatibility "$BASE_DIR"
    ;;
esac
