#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bench_dir=$(mktemp -d /tmp/soj-civiclight-salsa-bench.XXXXXX)
trap 'rm -rf -- "$bench_dir"' EXIT HUP INT TERM

cd "$repo_dir"

build_and_run()
{
    name=$1
    shift
    "${CC:-clang}" -O3 -g -march=znver2 -msha "$@" \
        -DCIVIC_YESPOWER_SALSA_BENCH -I. \
        tests/civiclight-salsa-bench.c \
        algo/civiclight/yespower/yespower-opt.c \
        algo/civiclight/yespower/yespower_sha256.c \
        -o "$bench_dir/$name"
    echo "$name"
    "$bench_dir/$name" "${CIVIC_SALSA_BENCH_CHUNKS:-12}" "${CIVIC_SALSA_BENCH_ITERATIONS:-1000}"
}

build_and_run avx2 -mavx2

if grep -qw avx512vl /proc/cpuinfo; then
    build_and_run avx512vl -mavx2 -mavx512f -mavx512vl
fi
