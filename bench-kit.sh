#!/bin/bash
# bench-kit.sh - A/B bench for the CivicLight 2-way smix kernels.
# Builds the register-promoted kernel twice -- sequential step order vs ILV
# load hoisting (-DCIVIC_PWX_ILV_REG) -- and runs them back-to-back.
# Use on a quiet box (bare-metal Linux preferred).
#
# Usage:  ./bench-kit.sh [SOJ_MARCH]     (default: native)
# If a compiler is missing on the target, pre-build locally and push:
#   ./bench-kit.sh build <march>   -> emits /tmp/smix2-seqreg, /tmp/smix2-ilvreg
#   ./bench-kit.sh run             -> runs both binaries and prints deltas
set -e

MODE="${1:-}"
if [ "$MODE" = "build" ]; then
    MARCH="${2:-native}"
elif [ "$MODE" = "run" ]; then
    MARCH=""
else
    echo "usage: bench-kit.sh build <march> | bench-kit.sh run" >&2
    exit 1
fi

SRCDIR="$(cd "$(dirname "$0")" && pwd)"
CC="${CC:-clang}"

COMMON="-O3 -march=${MARCH} -mtune=${MARCH} -mavx2 -mfma -mbmi2 -mlzcnt -mpopcnt -mprfchw -msha \
-funroll-loops -fno-math-errno -ffast-math -fno-strict-aliasing -fno-omit-frame-pointer \
-fno-exceptions -fno-rtti -fno-plt -fno-semantic-interposition -fno-stack-protector \
-fdata-sections -ffunction-sections -DENABLE_PREFETCH=1 -DNDEBUG \
-DCIVIC_YESPOWER_SMIX2_BENCH -DCIVIC_YESPOWER_4WAY \
-include algo/civiclight/yespower/yespower.h \
-I. -Ialgo/civiclight/yespower \
tests/civiclight-smix2-bench.c algo/civiclight/yespower/yespower-opt.c \
algo/civiclight/yespower/yespower_sha256.c algo/civiclight/yespower/yespower-platform.c"

build_one () {
    OUT="$1"; shift
    echo "== building ${OUT} (march=${MARCH}$*) =="
    if ! $CC $COMMON "$@" -o "$OUT" >"${OUT}-build.log" 2>&1; then
        cat "${OUT}-build.log" >&2
        exit 1
    fi
    grep -v "Note:" "${OUT}-build.log" || true
}

case "$MODE" in
  build)
    build_one /tmp/smix2-seqreg
    build_one /tmp/smix2-ilvreg -DCIVIC_PWX_ILV_REG
    ls -la /tmp/smix2-seqreg /tmp/smix2-ilvreg
    ;;
  run)
    [ -x /tmp/smix2-seqreg ] || { echo "missing /tmp/smix2-seqreg; run bench-kit.sh build <march> first" >&2; exit 1; }
    [ -x /tmp/smix2-ilvreg ] || { echo "missing /tmp/smix2-ilvreg; run bench-kit.sh build <march> first" >&2; exit 1; }
    ROUNDS="${ROUNDS:-3}"
    for i in $(seq 1 "$ROUNDS"); do
        /tmp/smix2-seqreg > "/tmp/seqreg-$i.out"
        /tmp/smix2-ilvreg > "/tmp/ilvreg-$i.out"
    done
    echo "== medians over $ROUNDS rounds (ns/hash, 2-way) =="
    for bin in seqreg ilvreg; do
        for row in "random+save" "pipelined" "reg-state"; do
            med=$(grep -hF "$row" /tmp/$bin-*.out | awk '{print $7}' | sort -n | awk '{a[NR]=$1} END {if (NR%2) print a[(NR+1)/2]; else print (a[NR/2]+a[NR/2+1])/2}')
            printf "  %-14s %-12s %s\n" "$bin" "$row:" "$med"
        done
        echo
    done
    ;;
  *)
    echo "usage: bench-kit.sh build <march> | bench-kit.sh run" >&2
    exit 1;;
esac
