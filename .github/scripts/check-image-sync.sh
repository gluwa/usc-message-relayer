#!/usr/bin/env bash
#
# check-image-sync.sh
#
# Keep the container runtime OS and the CI runner OS in lockstep. The relayer's
# release binary runs on the Dockerfile runtime base, and CI builds/tests it on
# the GitHub-hosted runner. If those two OSes drift (e.g. a newer glibc on one
# side), a binary can pass CI yet fail at runtime. This script enforces a single
# canonical Ubuntu version across:
#
#   1. the Dockerfile runtime stage       -> FROM ubuntu:<VERSION>
#   2. every `runs-on:` in .github/workflows/*.y{a,}ml -> ubuntu-<VERSION>
#
# The canonical version lives in ONE place below; update it here and both the
# Dockerfile and the workflows must follow.
#
# Exit codes:
#   0 - Dockerfile runtime base and all runs-on values match the canonical version
#   1 - one or more are out of sync (or the Dockerfile runtime base is missing)
#
set -euo pipefail

# --- Canonical CI/runtime Ubuntu version -------------------------------------
# Keep this in sync with the Dockerfile runtime FROM and all workflow runs-on.
UBUNTU_VERSION="24.04"

DOCKER_IMAGE="ubuntu:${UBUNTU_VERSION}"
RUNNER_LABEL="ubuntu-${UBUNTU_VERSION}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

DOCKERFILE="${REPO_ROOT}/Dockerfile"
WORKFLOW_DIR="${REPO_ROOT}/.github/workflows"

fail=0

echo "Canonical Ubuntu version: ${UBUNTU_VERSION}"
echo "  expected Docker runtime base : ${DOCKER_IMAGE}"
echo "  expected CI runner label     : ${RUNNER_LABEL}"
echo ""

# --- 1. Dockerfile runtime base ---------------------------------------------
# The runtime base is the LAST `FROM` in the (multi-stage) Dockerfile. The
# earlier builder stage(s) intentionally use a rust: image and are not checked
# here.
if [[ ! -f "${DOCKERFILE}" ]]; then
  echo "::error::Dockerfile not found at ${DOCKERFILE}"
  exit 1
fi

runtime_from="$(grep -iE '^[[:space:]]*FROM[[:space:]]' "${DOCKERFILE}" | tail -n1)"
# Strip a trailing "AS <stage>" alias, if any, and the leading FROM keyword.
runtime_image="$(echo "${runtime_from}" \
  | sed -E 's/^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]+//; s/[[:space:]]+[Aa][Ss][[:space:]]+.*$//; s/[[:space:]]*$//')"

echo "Dockerfile runtime stage: FROM ${runtime_image}"
if [[ "${runtime_image}" == "${DOCKER_IMAGE}" ]]; then
  echo "  ok   Dockerfile runtime base matches ${DOCKER_IMAGE}"
else
  echo "::error file=Dockerfile::Runtime base '${runtime_image}' does not match canonical '${DOCKER_IMAGE}'"
  fail=1
fi
echo ""

# --- 2. Every runs-on in every workflow -------------------------------------
echo "Checking runs-on values in ${WORKFLOW_DIR}:"
if [[ -d "${WORKFLOW_DIR}" ]]; then
  while IFS= read -r wf; do
    # Extract the value after `runs-on:` on each line; ignore matrix refs.
    while IFS= read -r line; do
      val="$(echo "${line}" | sed -E 's/.*runs-on:[[:space:]]*//; s/[[:space:]]*$//')"
      # Skip templated / matrix expressions like ${{ matrix.os }} — nothing to
      # compare statically, but flag them so they don't silently bypass the check.
      if [[ "${val}" == *'${{'* ]]; then
        echo "::error file=${wf#${REPO_ROOT}/}::runs-on uses a dynamic expression ('${val}'); pin it to ${RUNNER_LABEL} for sync enforcement"
        fail=1
        continue
      fi
      # Strip surrounding quotes if present.
      val="${val%\"}"; val="${val#\"}"
      val="${val%\'}"; val="${val#\'}"
      if [[ "${val}" == "${RUNNER_LABEL}" ]]; then
        echo "  ok   ${wf#${REPO_ROOT}/}: runs-on: ${val}"
      else
        echo "::error file=${wf#${REPO_ROOT}/}::runs-on '${val}' does not match canonical '${RUNNER_LABEL}'"
        fail=1
      fi
    done < <(grep -nE '^[[:space:]]*runs-on:' "${wf}" || true)
  done < <(find "${WORKFLOW_DIR}" -maxdepth 1 \( -name '*.yml' -o -name '*.yaml' \) | sort)
else
  echo "::warning::No .github/workflows directory found"
fi

echo ""
if [[ "${fail}" -ne 0 ]]; then
  echo "::error::Docker runtime base and CI runner OS are out of sync."
  echo "All of these must use Ubuntu ${UBUNTU_VERSION}:"
  echo "  - Dockerfile runtime stage: FROM ${DOCKER_IMAGE}"
  echo "  - every workflow runs-on:   ${RUNNER_LABEL}"
  echo "Update them (or the UBUNTU_VERSION in this script) so they all match."
  exit 1
fi

echo "Docker runtime base and all CI runs-on values are in sync on Ubuntu ${UBUNTU_VERSION}."
