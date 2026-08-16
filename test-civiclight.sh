#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_dir=$(mktemp -d /tmp/soj-civiclight-test.XXXXXX)
trap 'rm -rf -- "$test_dir"' EXIT HUP INT TERM

cd "$repo_dir"
"${CC:-clang}" -O2 -march=znver2 -msha \
    -ffunction-sections -fdata-sections -I. \
    tests/civiclight-vector.c \
    algo/civiclight/civiclight.c \
    algo/civiclight/yespower/yespower-opt.c \
    algo/civiclight/yespower/yespower-avx512.c \
    algo/civiclight/yespower/yespower_sha256.c \
    algo/sha/sha256-hash.c \
    simd-utils/simd-constants.c \
    -Wl,--gc-sections -o "$test_dir/civiclight-vector"

"$test_dir/civiclight-vector"
