#!/bin/sh
set -e

# With no explicit target, build the two supported comparison binaries. Keep
# SOJ_MARCH=znverN available for a single-target build through the same script.
if [ -z "${SOJ_MARCH:-}" ] && [ "${SOJ_BUILD_ALL:-0}" != "1" ]; then
    echo "Building both Zen 2 and Zen 4 targets..."
    SOJ_BUILD_ALL=1 SOJ_MARCH=znver2 "$0" "$@"
    SOJ_BUILD_ALL=1 SOJ_MARCH=znver4 "$0" "$@"
    exit 0
fi

# --------- SANITY: REMOVE BOM IF PRESENT ---------
sed -i '1s/^\xEF\xBB\xBF//' "$0" 2>/dev/null || true

# --------- BUILD NUMBER TRACKING ---------
if [ ! -f .build_number ]; then
    echo 0 > .build_number
fi
BUILD_NUMBER=$(cat .build_number)
BUILD_NUMBER=$((BUILD_NUMBER + 1))
echo $BUILD_NUMBER > .build_number

# --------- BUILD VERSION INFO ---------
if GIT_HASH=$(git rev-parse --short --verify HEAD 2>/dev/null); then
    :
else
    GIT_HASH="unknown"
fi
if GIT_BRANCH=$(git symbolic-ref --short -q HEAD 2>/dev/null); then
    :
else
    GIT_BRANCH="unknown"
fi
GIT_TAG=$(git describe --tags --exact-match 2>/dev/null || echo "")
BUILD_DATE=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
BUILD_DATE_SHORT=$(date -u +"%m%d")
BUILD_TYPE="civiclight-soj-clang-fast"

if [ -n "$GIT_TAG" ]; then
    BUILD_VERSION="${GIT_TAG}.${GIT_BRANCH}.${GIT_HASH}.b${BUILD_NUMBER}.clangfast"
else
    BUILD_VERSION="v1.0.${BUILD_DATE_SHORT}.${GIT_BRANCH}.b${BUILD_NUMBER}.clangfast"
fi

echo "Building (Clang FAST) #$BUILD_NUMBER version: ${BUILD_VERSION} (${GIT_HASH})"
echo "Branch: ${GIT_BRANCH}"
echo "Date:   ${BUILD_DATE}"

# --------- CLEAN AUTOCONF / MAKE STATE ---------
rm -f Makefile */Makefile
rm -f config.cache config.status config.log soj-config.h
rm -rf autom4te.cache
rm -f version.h

# --------- GENERATE version.h ---------
sed \
    -e "s/@BUILD_VERSION@/${BUILD_VERSION}/g" \
    -e "s/@BUILD_GIT_HASH@/${GIT_HASH}/g" \
    -e "s/@BUILD_GIT_BRANCH@/${GIT_BRANCH}/g" \
    -e "s/@BUILD_DATE@/${BUILD_DATE}/g" \
    -e "s/@BUILD_TYPE@/${BUILD_TYPE}/g" \
    version.h.in > version.h

# --------- COMPILER SELECTION (CLANG) ---------
export CC=clang
export CXX=clang++

# Optional A/B knobs. Examples:
#   CLANG_INLINE_THRESHOLD=600 ./build-clang-fast.sh
#   CLANG_UNROLL_THRESHOLD=400 ./build-clang-fast.sh
INLINE_FLAGS=""
if [ -n "${CLANG_INLINE_THRESHOLD:-}" ]; then
    INLINE_FLAGS="-mllvm -inline-threshold=${CLANG_INLINE_THRESHOLD} -Qunused-arguments"
fi
if [ -n "${CLANG_UNROLL_THRESHOLD:-}" ]; then
    INLINE_FLAGS="${INLINE_FLAGS} -mllvm -unroll-threshold=${CLANG_UNROLL_THRESHOLD}"
fi
if [ -n "${SOJ_EXTRA_CFLAGS:-}" ]; then
    INLINE_FLAGS="${INLINE_FLAGS} ${SOJ_EXTRA_CFLAGS}"
fi

# Frame pointer: kept for perf/gprof workflows by default; omit to free RBP.
#   SOJ_OMIT_FP=1 ./build-clang-fast.sh
FP_FLAG="-fno-omit-frame-pointer"
if [ "${SOJ_OMIT_FP:-0}" = "1" ]; then
    FP_FLAG="-fomit-frame-pointer"
fi

# Function/loop alignment (bytes). 32 keeps hot loops off decode boundaries.
#   SOJ_ALIGN=32 ./build-clang-fast.sh
ALIGN_FLAGS=""
case "${SOJ_ALIGN:-}" in
    16|32|64) ALIGN_FLAGS="-falign-functions=${SOJ_ALIGN} -falign-loops=${SOJ_ALIGN}";;
esac

# ThinLTO: cross-TU inlining (sha256 helpers into the algo layer, etc.).
#   SOJ_LTO=1 ./build-clang-fast.sh
LTO_FLAGS=""
if [ "${SOJ_LTO:-0}" = "1" ]; then
    LTO_FLAGS="-flto=thin"
fi

# Non-PIE: direct addressing for globals instead of GOT indirection.
#   SOJ_NOPIE=1 ./build-clang-fast.sh
NOPIE_CFLAGS=""
NOPIE_LDFLAGS=""
if [ "${SOJ_NOPIE:-0}" = "1" ]; then
    NOPIE_CFLAGS="-fno-pie"
    NOPIE_LDFLAGS="-no-pie"
fi

# PGO: two-stage build; stage 1 instruments, a short offline --benchmark run
# trains the profile, stage 2 optimizes with it. Requires llvm-profdata.
#   SOJ_PGO=1 ./build-clang-fast.sh        (optional: SOJ_PGO_THREADS=4)
PGO_TRAIN_THREADS="${SOJ_PGO_THREADS:-4}"
export SOJ_MARCH SOJ_MTUNE CLANG_INLINE_THRESHOLD CLANG_UNROLL_THRESHOLD SOJ_EXTRA_CFLAGS \
       SOJ_OMIT_FP SOJ_ALIGN SOJ_LTO SOJ_NOPIE SOJ_PGO SOJ_PGO_THREADS
PGO_PASS="${SOJ_PGO_PASS:-}"

PROFDATA_BIN=""
find_profdata() {
    if command -v llvm-profdata >/dev/null 2>&1; then
        command -v llvm-profdata
    elif command -v "llvm-profdata-${CLANG_MAJOR:-20}" >/dev/null 2>&1; then
        command -v "llvm-profdata-${CLANG_MAJOR:-20}"
    elif ls /usr/lib/llvm-*/bin/llvm-profdata >/dev/null 2>&1; then
        ls /usr/lib/llvm-*/bin/llvm-profdata | sort -V | tail -1
    else
        echo ""
    fi
}
if [ "${SOJ_PGO:-0}" = "1" ]; then
    PROFDATA_BIN=$(find_profdata)
    if [ -z "$PROFDATA_BIN" ]; then
        echo "SOJ_PGO=1 but llvm-profdata not found; aborting." >&2
        exit 1
    fi
    export PROFDATA_BIN PGO_TRAIN_THREADS
fi

# --------- CPU TARGET ---------
# Default invocation builds Zen 2 and Zen 4. Override for one target, e.g.
#   SOJ_MARCH=znver2 ./build-clang-fast.sh     # EPYC Rome / Zen 2
#   SOJ_MARCH=znver4 ./build-clang-fast.sh     # Ryzen 7950X3D / Zen 4
#   SOJ_MARCH=native  ./build-clang-fast.sh    # whatever box you're on
# The march is baked into the output name (soj-civiclight-${SOJ_MARCH}) so
# binaries for different CPUs can coexist in one checkout.
SOJ_MARCH="${SOJ_MARCH:-znver5}"
SOJ_MTUNE="${SOJ_MTUNE:-${SOJ_MARCH}}"

# --------- CLANG FLAGS (AGGRESSIVE BUT REASONABLE) ---------
BASE_CFLAGS="-O3 -g -march=${SOJ_MARCH} -mtune=${SOJ_MTUNE} \
-mavx2 -mfma -mbmi2 -mlzcnt -mpopcnt -mprfchw -msha \
-funroll-loops -fno-math-errno -ffast-math \
-fno-strict-aliasing \
${FP_FLAG} \
-fvisibility=hidden \
-fno-exceptions -fno-rtti \
-fno-plt -fno-semantic-interposition \
-fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables \
-fdata-sections -ffunction-sections \
-DENABLE_PREFETCH=1 \
-DENABLE_JOB_RETENTION=1 -DNDEBUG -pipe"

PGO_CFLAGS=""
if [ "${SOJ_PGO:-0}" = "1" ]; then
    case "$PGO_PASS" in
        train) PGO_CFLAGS="-fprofile-instr-generate";;
        use)   PGO_CFLAGS="-fprofile-instr-use=/tmp/soj-pgo.profdata -Wno-profile-instr-unprofiled";;
    esac
fi

export CFLAGS="${BASE_CFLAGS} ${ALIGN_FLAGS} ${LTO_FLAGS} ${NOPIE_CFLAGS} ${PGO_CFLAGS} ${INLINE_FLAGS}"

export CXXFLAGS="$CFLAGS"

# Link-time stripping of unused sections
export LDFLAGS="-fuse-ld=lld -Wl,--as-needed -Wl,--hash-style=gnu -Wl,--gc-sections -Wl,-O2 ${LTO_FLAGS} ${NOPIE_LDFLAGS}"

do_build() {
    # --------- RUN AUTOGEN + CONFIGURE ---------
    echo "Running autogen and configure (logging to build.log)..."
    ./autogen.sh > build.log 2>&1
    ./configure --with-curl >> build.log 2>&1

    # --------- BUILD ---------
    echo "Compiling... #$BUILD_NUMBER"
    make clean >> build.log 2>&1
    make -s -j$(nproc)
}

# --------- PGO ORCHESTRATOR (two recursive invocations) ---------
if [ "${SOJ_PGO:-0}" = "1" ] && [ -z "$PGO_PASS" ]; then
    echo "PGO pass 1/2: instrumented build + training benchmark..."
    SOJ_PGO_PASS=train "$0" "$@" || { echo "PGO training pass failed." >&2; exit 1; }
    if [ ! -f /tmp/soj-pgo.profdata ]; then
        echo "PGO training failed (no /tmp/soj-pgo.profdata); aborting." >&2
        exit 1
    fi
    echo "PGO pass 2/2: optimized rebuild with profile..."
    SOJ_PGO_PASS=use "$0" "$@"
    exit $?
fi

do_build

# --------- PGO SCOPE LIMITER ---------
# SOJ_PGO_SKIP_TUS: space-separated substrings of object names rebuilt
# WITHOUT the profile.  clang-20 instr-PGO miscompiles at least the curl /
# stratum paths (mangled pointers -> SIGSEGV under real mining), so default
# scope keeps the profile on the compute TUs only.
if [ "${SOJ_PGO:-0}" = "1" ] && [ "$PGO_PASS" = "use" ]; then
    SKIP_TUS="${SOJ_PGO_SKIP_TUS:-}"
    # Allow-list wins when set: every soj-*.o NOT matching is rebuilt plain.
    KEEP_TUS="${SOJ_PGO_KEEP_TUS:-civiclight yespower sph_sha2 sha1-hash sha256-hash sha256d md_helper simd-constants}"
    SKIP_OBJS=""
    for o in $(find . -name 'soj-*.o' -not -path './autom4te.cache/*'); do
        [ -e "$o" ] || continue
        b=$(basename "$o" .o)
        b=${b#soj-}
        keep=""
        for k in $KEEP_TUS; do
            case "$b" in
                *$k*) keep=1; break;;
            esac
        done
        if [ -z "$keep" ]; then
            if [ -n "$SKIP_TUS" ]; then
                for t in $SKIP_TUS; do
                    if [ "$b" = "$t" ]; then SKIP_OBJS="$SKIP_OBJS $o"; break; fi
                done
            else
                SKIP_OBJS="$SKIP_OBJS $o"
            fi
        fi
    done
    if [ -n "$SKIP_OBJS" ]; then
        echo "PGO scope: rebuilding without profile:$SKIP_OBJS"
        rm -f $SKIP_OBJS
        make CFLAGS="${BASE_CFLAGS} ${ALIGN_FLAGS} ${NOPIE_CFLAGS} ${INLINE_FLAGS}" -s >/dev/null
    fi
fi

# --------- PGO TRAINING RUN (train pass only; never published) ---------
if [ "$PGO_PASS" = "train" ]; then
    rm -f /tmp/soj-pgo-*.profraw /tmp/soj-pgo.profdata
    echo "PGO: training run (--benchmark, ${PGO_TRAIN_THREADS} threads, offline)..."
    LLVM_PROFILE_FILE=/tmp/soj-pgo-%p.profraw timeout 180 ./soj --benchmark 8 -t "$PGO_TRAIN_THREADS" > /dev/null 2>&1 || true
    ls /tmp/soj-pgo-*.profraw >/dev/null 2>&1 || { echo "No .profraw produced." >&2; exit 1; }
    "$PROFDATA_BIN" merge -output=/tmp/soj-pgo.profdata /tmp/soj-pgo-*.profraw
    echo "PGO profile written to /tmp/soj-pgo.profdata."
    exit 0
fi

# Consensus guard: compare the stitched miner against the CivicNet Core
# post-fork v2 hash vector before publishing a runnable binary.
./test-civiclight.sh

# Keep soj for compatibility while also emitting the focused project name.
BUILD_TS=$(date +"%Y%m%d-%H%M%S")
cp -f soj "soj-${BUILD_NUMBER}-${BUILD_TS}" 2>/dev/null || true
cp -f soj soj-civiclight
cp -f soj "soj-civiclight-${SOJ_MARCH}"
chmod +x soj soj-civiclight "soj-civiclight-${SOJ_MARCH}" "soj-${BUILD_NUMBER}-${BUILD_TS}" 2>/dev/null || true

# --------- KEEP ONLY LAST 5 BUILDS ---------
# List builds, sort them, and remove all but the newest 5 (handles transition to timestamped names)
ls soj-[0-9]* 2>/dev/null | grep -E '^soj-[0-9]+(-[0-9]{8}-[0-9]{6})?$' | sort -V | head -n -5 | xargs -r rm -f

# --------- CLEAN PREPROCESSED DUMPS ---------
rm -f preprocessed.c

echo ""
echo "Clang FAST CivicLight build #$BUILD_NUMBER complete: soj and soj-civiclight (backup: soj-${BUILD_NUMBER}-${BUILD_TS})"
echo "   Target: ${SOJ_MARCH} -> soj-civiclight-${SOJ_MARCH}"
echo "   Version: ${BUILD_VERSION}"
echo "   Commit:  ${GIT_HASH}"
echo "   Built:   ${BUILD_DATE}"
