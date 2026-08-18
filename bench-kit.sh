#!/bin/bash
# bench-kit.sh - portable A/B bench for the CivicLight pwx kernel.
# Builds packed vs unpacked smix2 micro-benches from the same source and
# runs them back-to-back.  Use on a quiet box (bare-metal Linux preferred).
#
# Usage:  ./bench-kit.sh [SOJ_MARCH]     (default: native)
# If a compiler is missing on the target, pre-build locally and push:
#   ./bench-kit.sh build znver5      -> emits /tmp/smix2-packed, /tmp/smix2-unpacked
#   ./bench-kit.sh run               -> runs the two binaries and prints deltas
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

case "$MODE" in
  build)
    echo "== building packed smix2 bench (-DCIVIC_PWX_PACKED, march=${MARCH}) =="
    if ! $CC $COMMON -DCIVIC_PWX_PACKED -o /tmp/smix2-packed >/tmp/smix2-packed-build.log 2>&1; then
      cat /tmp/smix2-packed-build.log >&2
      exit 1
    fi
    grep -v "Note:" /tmp/smix2-packed-build.log || true
    echo "== building unpacked smix2 bench (default, no flag) =="
    if ! $CC $COMMON -o /tmp/smix2-unpacked >/tmp/smix2-unpacked-build.log 2>&1; then
      cat /tmp/smix2-unpacked-build.log >&2
      exit 1
    fi
    grep -v "Note:" /tmp/smix2-unpacked-build.log || true
    ls -la /tmp/smix2-packed /tmp/smix2-unpacked
    ;;
  run)
    [ -x /tmp/smix2-packed ] || { echo "missing /tmp/smix2-packed; run bench-kit.sh build <march> first" >&2; exit 1; }
    [ -x /tmp/smix2-unpacked ] || { echo "missing /tmp/smix2-unpacked; run bench-kit.sh build <march> first" >&2; exit 1; }
    /tmp/smix2-packed > /tmp/packed.out
    /tmp/smix2-unpacked > /tmp/unpacked.out
    echo "================ PACKED ================"
    sed -n '2,8p' /tmp/packed.out
    echo
    echo "================ UNPACKED ================"
    sed -n '2,8p' /tmp/unpacked.out
    echo
    echo "== per-mode delta (ns/hash 2-way; negative = unpacked faster) =="
    awk 'FNR==NR { if (FNR>2 && $1!="mode") p[$1]=$7; next }
         FNR>2 && $1!="mode" { u[$1]=$7 }
         END { for (m in p) if (u[m]!="")
                 printf "  %-16s packed=%10.1f unpacked=%10.1f  %+6.2f%%\n", m, p[m], u[m], (u[m]/p[m]-1)*100 }' \
         /tmp/packed.out /tmp/unpacked.out | sort
    ;;
  *)
    echo "usage: bench-kit.sh build <march> | bench-kit.sh run" >&2; exit 1;;
esac
