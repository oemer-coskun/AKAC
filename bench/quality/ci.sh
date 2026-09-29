#!/usr/bin/env bash
# Retrieval-quality evaluation with a real open embedding model (docs/PERFORMANCE.md,
# "Retrieval quality"). Requires Node 24 and the root dependencies (npm ci at the root).
#
#   bash bench/quality/ci.sh [OUTPUT_JSON]
#
# Environment:
#   AKAC_QUALITY_CACHE      model cache (default bench/quality/.cache); CI caches it keyed by
#                           hashFiles('bench/quality/model.lock'). Files are always re-verified.
#   AKAC_QUALITY_DOCUMENTS  acme document count (default 3000; +10 % in a second tenant)
#   AKAC_TEST_DATABASE_URL  when set, the pgvector (HNSW) backend is evaluated too, in a
#                           throwaway schema that is dropped afterwards
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="${1:-$root/bench/results/quality.json}"
export AKAC_QUALITY_CACHE="${AKAC_QUALITY_CACHE:-$here/.cache}"

# The heavy dependency lives in its own lockfile, never in the root dependency tree.
# --ignore-scripts: onnxruntime-node bundles its CPU binaries (its install script only
# fetches optional CUDA/TensorRT providers), and sharp (a transformers.js dependency for
# image pipelines, unused here) ships prebuilt binaries as optional packages.
npm ci --prefix "$here" --ignore-scripts --no-audit --no-fund

backends=memory
if [ -n "${AKAC_TEST_DATABASE_URL:-}" ]; then backends=memory,pgvector; fi

# --fetch downloads the files named in model.lock at the pinned commit (only those not already
# cached) and verifies every sha256 before anything runs; remote model loading is disabled.
node "$root/bench/quality/eval.ts" --fetch \
  --documents "${AKAC_QUALITY_DOCUMENTS:-3000}" --embedders hash,minilm --backends "$backends" --out "$out"
