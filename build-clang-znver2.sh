#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$repo_dir"
exec env SOJ_MARCH=znver2 SOJ_MTUNE=znver2 ./build-clang-fast.sh "$@"
