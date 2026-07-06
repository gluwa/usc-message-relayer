#!/usr/bin/env bash
#
# check-dependabot-coverage.sh
#
# Sanity check that every dependency manifest in the repo is covered by an
# entry in .github/dependabot.yml. Dependabot cannot recurse into nested
# directories on its own, so it is easy to add a new crate / workflow / image
# and forget to register it. This script scans the working tree, computes the
# (ecosystem, directory) pairs that *should* be tracked, and warns about any
# that are missing from the config.
#
# Discovered manifests / lockfiles per ecosystem:
#   cargo          -> Cargo.toml, Cargo.lock
#   npm            -> package.json, package-lock.json, yarn.lock
#   docker         -> Dockerfile*
#   docker-compose -> docker-compose*.y{a,}ml, compose*.y{a,}ml
#   github-actions -> .github/workflows/*
#
# Exit codes:
#   0 - every discovered manifest is covered
#   1 - one or more manifests are not listed in dependabot.yml
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="${REPO_ROOT}/.github/dependabot.yml"

if [[ ! -f "${CONFIG}" ]]; then
  echo "::error::.github/dependabot.yml not found at ${CONFIG}"
  exit 1
fi

cd "${REPO_ROOT}"

missing=0
# Track already-reported (ecosystem, directory) pairs so multiple files in the
# same dir (e.g. Cargo.toml + Cargo.lock) only produce one line.
declare -A seen_pairs=()

# Normalise a filesystem path into the "/dir" form dependabot uses.
# The repo root becomes "/".
to_dep_dir() {
  local d="$1"
  d="${d#.}"        # strip leading "."
  [[ -z "${d}" ]] && d="/"
  echo "${d}"
}

# Return 0 if the given ecosystem covers the given directory in dependabot.yml.
# We extract, per ecosystem block, the `directory:` / `directories:` entries and
# check for an exact match. This is a lightweight YAML scan (no yq dependency).
is_covered() {
  local ecosystem="$1"
  local dir="$2"
  awk -v eco="${ecosystem}" -v want="${dir}" '
    /package-ecosystem:/ {
      # Extract the quoted ecosystem name.
      line=$0
      gsub(/.*package-ecosystem:[[:space:]]*"?/, "", line)
      gsub(/".*/, "", line)
      gsub(/[[:space:]].*/, "", line)
      cur=line
      indir=0
      next
    }
    /directories:/ { if (cur==eco) indir=1; next }
    /directory:/ {
      if (cur==eco) {
        val=$0
        gsub(/.*directory:[[:space:]]*"?/, "", val)
        gsub(/".*/, "", val)
        gsub(/[[:space:]]*$/, "", val)
        if (val==want) { found=1 }
      }
      indir=0
      next
    }
    # List item under a directories: block, e.g.   - "/foo"
    /^[[:space:]]*-[[:space:]]*"/ {
      if (cur==eco && indir==1) {
        val=$0
        gsub(/^[[:space:]]*-[[:space:]]*"/, "", val)
        gsub(/".*/, "", val)
        if (val==want) { found=1 }
      }
      next
    }
    # Any non-list, non-blank line ends a directories: block.
    /^[^[:space:]-]/ { indir=0 }
    END { exit(found?0:1) }
  ' "${CONFIG}"
}

check() {
  local ecosystem="$1"
  local dir="$2"
  local manifest="$3"
  local key="${ecosystem}::${dir}"
  [[ -n "${seen_pairs[${key}]:-}" ]] && return 0
  seen_pairs[${key}]=1
  if is_covered "${ecosystem}" "${dir}"; then
    echo "  ok   ${ecosystem}  ${dir}  (${manifest})"
  else
    echo "::warning file=.github/dependabot.yml::Missing dependabot coverage: ecosystem='${ecosystem}' directory='${dir}' (found ${manifest})"
    missing=1
  fi
}

echo "Scanning repository for dependency manifests..."

# --- cargo: every Cargo.toml / Cargo.lock is a directory dependabot must track ---
while IFS= read -r f; do
  dir="$(to_dep_dir "$(dirname "${f}")")"
  check "cargo" "${dir}" "${f}"
done < <(find . \( -name Cargo.toml -o -name Cargo.lock \) -not -path './.git/*' -not -path '*/target/*' | sort -u)

# --- npm: every package.json / package-lock.json / yarn.lock (excluding node_modules) ---
while IFS= read -r f; do
  dir="$(to_dep_dir "$(dirname "${f}")")"
  check "npm" "${dir}" "${f}"
done < <(find . \( -name package.json -o -name package-lock.json -o -name yarn.lock \) -not -path './.git/*' -not -path '*/node_modules/*' | sort -u)

# --- docker: every Dockerfile* ---
while IFS= read -r f; do
  dir="$(to_dep_dir "$(dirname "${f}")")"
  check "docker" "${dir}" "${f}"
done < <(find . -iname 'Dockerfile*' -not -path './.git/*' | sort)

# --- docker-compose: compose files ---
while IFS= read -r f; do
  dir="$(to_dep_dir "$(dirname "${f}")")"
  check "docker-compose" "${dir}" "${f}"
done < <(find . \( -iname 'docker-compose*.y*ml' -o -iname 'compose.y*ml' -o -iname 'compose.*.y*ml' \) -not -path './.git/*' | sort)

# --- github-actions: always expected at "/" when workflows exist ---
if [[ -d .github/workflows ]] && compgen -G ".github/workflows/*.y*ml" > /dev/null; then
  check "github-actions" "/" ".github/workflows"
fi

echo ""
if [[ "${missing}" -ne 0 ]]; then
  echo "::error::One or more dependency manifests are not covered by .github/dependabot.yml."
  echo "Add the missing (ecosystem, directory) entries to .github/dependabot.yml."
  exit 1
fi

echo "All discovered dependency manifests are covered by dependabot.yml."
