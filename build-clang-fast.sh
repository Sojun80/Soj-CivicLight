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

# Optional A/B knob. Example:
#   CLANG_INLINE_THRESHOLD=600 ./build-clang-fast.sh
INLINE_FLAGS=""
if [ -n "${CLANG_INLINE_THRESHOLD:-}" ]; then
    INLINE_FLAGS="-mllvm -inline-threshold=${CLANG_INLINE_THRESHOLD} -Qunused-arguments"
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
export CFLAGS="-O3 -g -march=${SOJ_MARCH} -mtune=${SOJ_MTUNE} \
-mavx2 -mfma -mbmi2 -mlzcnt -mpopcnt -mprfchw -msha \
-funroll-loops -fno-math-errno -ffast-math \
-fno-strict-aliasing \
-fno-omit-frame-pointer \
-fno-exceptions -fno-rtti \
-fno-plt -fno-semantic-interposition \
-fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables \
-fdata-sections -ffunction-sections \
-DENABLE_PREFETCH=1 \
-DENABLE_JOB_RETENTION=1 -DNDEBUG -pipe \
${INLINE_FLAGS}"

export CXXFLAGS="$CFLAGS"

# Link-time stripping of unused sections
export LDFLAGS="-fuse-ld=lld -Wl,--as-needed -Wl,--hash-style=gnu -Wl,--gc-sections"


# --------- RUN AUTOGEN + CONFIGURE ---------
echo "Running autogen and configure (logging to build.log)..."
./autogen.sh > build.log 2>&1
./configure --with-curl >> build.log 2>&1

# --------- BUILD ---------
echo "Compiling... #$BUILD_NUMBER"
make clean >> build.log 2>&1
make -s -j$(nproc)

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
